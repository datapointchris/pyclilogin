"""A usable access token, refreshed at most once at a time per machine.

## Two processes refreshing at once cost an interactive login

A provider following RFC 9700 rotates the refresh token on every use, and
§ 4.14.2 then requires it to revoke the whole grant when a consumed one is
presented again, because it cannot tell an attacker from a racing client. So
two processes refreshing from the same stored token cost an interactive login
rather than a retry:

    process A ─┐                     A wins: RT1 -> RT2, saved
    process B ─┼── all hold RT1 ───► B, C: replay RT1
    process C ─┘                            │
                                    the provider revokes the grant
                                            │
                                    RT2 is dead too -> log in again

`TokenSource.token` holds an exclusive `flock` for the refresh and re-reads the
store once it has the lock. A process that waited then uses the winner's token
instead of replaying its own. The threading lock covers threads in one process;
the file lock covers processes.

## The lock degrades rather than blocks

No state directory, an unwritable one, or a holder still busy after
`LOCK_WAIT_SECONDS` gives an unlocked refresh. That risks the revoked grant
above, which costs one login. Blocking on a wedged peer would instead hang every
command until the peer exits.

## The provider is asked only when a refresh is due

goclilogin reads the discovery document when a token source is built. Here it
is read inside the refresh, so a command holding a live token makes no call to
the identity provider at all.

## A service client stores nothing

`ServiceTokenSource` is goclilogin's `ClientCredentialsTokenSource`. The grant
issues no refresh token, so there is nothing to store and no rotation for
processes to race on. Its token lives in this process and a new one is
requested once it lapses. The secret is an argument, and nothing here reads it
from the environment.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import fcntl
import json
import os
import subprocess
import threading
import time
from pathlib import Path

from .errors import LoginError
from .errors import NotLoggedIn
from .errors import ServiceRefused
from .errors import StoreFailed
from .errors import TokenCommandFailed
from .errors import TokenRefused
from .provider import Token

LOCK_WAIT_SECONDS = 10.0
LOCK_POLL_SECONDS = 0.02

# The most of a failed token command's stderr its error carries.
MAX_COMMAND_STDERR = 2000


@contextlib.contextmanager
def refresh_lock(state_dir, client_id, wait=LOCK_WAIT_SECONDS):
    """Yield True holding the machine-wide refresh lock for `client_id`, or False without it.

    The lock lives on an open descriptor, so the kernel drops it when the process
    dies and a crash never leaves a lock file blocking the next run.
    """
    if not state_dir:
        yield False
        return
    try:
        Path(state_dir).mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = os.open(Path(state_dir) / f'{client_id}.refresh.lock', os.O_RDWR | os.O_CREAT, 0o600)
    except OSError:
        yield False
        return
    try:
        deadline = time.monotonic() + wait
        held = False
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                held = True
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    break
                time.sleep(LOCK_POLL_SECONDS)
        yield held
    finally:
        os.close(descriptor)


class TokenSource:
    """Hands out a live access token, refreshing and persisting it when it lapses."""

    def __init__(self, provider, store, client_id, state_dir):
        self.provider = provider
        self.store = store
        self.client_id = client_id
        self.state_dir = state_dir
        self.mutex = threading.Lock()
        self.current, _ = store.load(client_id)

    def token(self):
        with self.mutex:
            if self.current.valid():
                return self.current
            with refresh_lock(self.state_dir, self.client_id):
                # Whoever held the lock may have refreshed while this process
                # waited. Their token is then the live one, and refreshing again
                # would present the refresh token their rotation consumed.
                with contextlib.suppress(NotLoggedIn):
                    self.current, _ = self.store.load(self.client_id)
                if self.current.valid():
                    return self.current
                refreshed = self.provider.refresh(self.current)
                self.current = refreshed
                try:
                    self.store.save(self.client_id, refreshed)
                except LoginError as error:
                    # The provider has consumed the stored refresh token. Carrying on
                    # would leave the next process to replay it and lose the grant.
                    raise StoreFailed(f'the token refreshed but could not be stored: {error}') from error
                return refreshed


class ServiceTokenSource:
    """Hands out a service client's access token, requesting a new one when it lapses.

    `repair` is what a refusal tells the operator to check: where the client id
    and the secret came from.
    """

    def __init__(self, provider, secret, repair=''):
        self.provider = provider
        self.secret = secret
        self.repair = repair
        self.mutex = threading.Lock()
        self.current = Token('')

    def token(self):
        with self.mutex:
            if not self.current.valid():
                try:
                    self.current = self.provider.client_credentials(self.secret)
                except TokenRefused as error:
                    refused = f'the identity provider refused service client {self.provider.client_id}: {error.error}'
                    detail = f' ({error.description})' if error.description else ''
                    raise ServiceRefused(f'{refused}{detail}. {self.repair}'.rstrip()) from error
            return self.current


class CommandTokenSource:
    """Hands out the token the config file's token_command prints, running it again once that lapses.

    The command prints an RFC 6749 § 5.1 token response: `access_token`, and
    optionally `token_type` and `expires_in`, counted from when it started.
    """

    def __init__(self, argv, path):
        self.argv = tuple(argv)
        self.path = path
        self.mutex = threading.Lock()
        self.current = Token('')

    def token(self):
        with self.mutex:
            if not self.current.valid():
                self.current = self.run()
            return self.current

    def run(self):
        started = dt.datetime.now(dt.UTC)
        try:
            done = subprocess.run(self.argv, capture_output=True, text=True, check=False)
        except OSError as error:
            raise self.failed(str(error), '') from error
        if done.returncode != 0:
            raise self.failed(f'it exited {done.returncode}', done.stderr)
        try:
            answer = json.loads(done.stdout)
        except json.JSONDecodeError as error:
            raise self.failed(f'its output is not a token response: {error}', done.stderr) from error
        if not isinstance(answer, dict) or not answer.get('access_token'):
            raise self.failed('it printed no access_token', done.stderr)
        if answer.get('token_type', 'Bearer').lower() != 'bearer':
            raise self.failed(f'it printed a {answer["token_type"]} token, and only a bearer token is sent', done.stderr)
        expires_in = answer.get('expires_in')
        expiry = started + dt.timedelta(seconds=expires_in) if isinstance(expires_in, int) and expires_in > 0 else None
        return Token(answer['access_token'], expiry=expiry)

    def failed(self, reason, stderr):
        stderr = stderr.strip()[:MAX_COMMAND_STDERR]
        said = f': {stderr}' if stderr else ''
        return TokenCommandFailed(f'token_command in {self.path} ({" ".join(self.argv)}) handed no token: {reason}{said}')
