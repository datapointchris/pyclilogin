"""Where the token is kept: the OS keychain, or a mode-600 file where there is none.

A keyring that fails has two causes, and they need opposite answers.

- **No keyring at all.** A Linux host with no Secret Service fails before any
  request is made. The token goes to `token.json` in the state directory, and
  `save` returns `FILE` so the command says so at the moment it happens.
- **A keyring that refuses.** A macOS login keychain locked to an SSH session is
  present and will not answer. Writing plaintext there would outlive the lock,
  because `load` prefers the keyring only while it holds something. So `save`
  refuses with the fix instead.

Only macOS can tell the two apart, because every Mac has a login keychain. A
Secret Service error says nothing about whether the bus exists, so it stays
unattributed and keeps the fallback.

## How a locked keychain is recognized

The `keyring` library reaches the keychain through the Security framework. A
session that cannot show the unlock dialog gets OSStatus -25308,
`errSecInteractionNotAllowed`. The library maps no exception to that status, so
it raises its generic error with the status as `args[0]`, wrapped in a
`KeyringError`. `diagnose` walks the chain for that number. No message text is
parsed, so nothing about it can drift with a wording change.
"""

from __future__ import annotations

import enum
import json
import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import keyring
import keyring.errors

from .errors import KeyringRefused
from .errors import NotLoggedIn
from .errors import StoreFailed
from .provider import Token

TOKEN_FILE = 'token.json'
ERR_SEC_INTERACTION_NOT_ALLOWED = -25308


class Backend(enum.StrEnum):
    KEYRING = 'OS keyring'
    FILE = 'file'


class Cause(enum.Enum):
    UNATTRIBUTED = 'unattributed'
    LOCKED = 'locked'
    REFUSED = 'refused'

    @property
    def keyring_present(self):
        return self in (Cause.LOCKED, Cause.REFUSED)


@dataclass(frozen=True)
class Diagnosis:
    cause: Cause
    reason: str


class KeyringBackend(Protocol):
    """The three calls the `keyring` module exposes, spelled as it spells them."""

    def set_password(self, service_name: str, username: str, password: str) -> None: ...
    def get_password(self, service_name: str, username: str) -> str | None: ...
    def delete_password(self, service_name: str, username: str) -> None: ...


def error_chain(error):
    """The error and every error it was raised from."""
    seen = set()
    while error is not None and id(error) not in seen:
        seen.add(id(error))
        yield error
        error = error.__cause__ or error.__context__


def diagnose(platform, error):
    """Attribute a keyring failure before blaming either cause.

    `platform` is a parameter rather than a read of `sys.platform`, so the macOS
    branch runs in a test on any host.
    """
    if platform == 'darwin':
        if any(cause.args and cause.args[0] == ERR_SEC_INTERACTION_NOT_ALLOWED for cause in error_chain(error)):
            return Diagnosis(
                Cause.LOCKED,
                'the login keychain is locked and this session cannot prompt to unlock it'
                ' — run `security unlock-keychain` in this session first'
                ' (an SSH session is the usual way to land here: it does not inherit the console session'
                "'s keychain access)",
            )
        return Diagnosis(Cause.REFUSED, f'the login keychain refused: {error}')
    return Diagnosis(Cause.UNATTRIBUTED, f'the OS keyring is unavailable ({error})')


class FileStore:
    """Tokens in a mode-600 JSON file, keyed by client id like the keyring."""

    def __init__(self, state_dir):
        # No state directory is no private place for a secret, so the store
        # refuses rather than dropping a token somewhere world-readable.
        self.path = Path(state_dir) / TOKEN_FILE if state_dir else None

    def get(self, client_id):
        if self.path is None:
            return None
        stored = load(self.path).get(client_id)
        return Token.from_json(stored) if stored else None

    def set(self, client_id, token):
        if self.path is None:
            raise StoreFailed('there is no state directory to store a token in; set XDG_STATE_HOME')
        tokens = load(self.path)
        tokens[client_id] = token.to_json()
        write(self.path, tokens)

    def delete(self, client_id):
        """True when a token was removed."""
        if self.path is None:
            return False
        tokens = load(self.path)
        if client_id not in tokens:
            return False
        del tokens[client_id]
        write(self.path, tokens)
        return True


def load(path):
    try:
        text = path.read_text()
    except FileNotFoundError:
        return {}
    except OSError as error:
        raise StoreFailed(f'cannot read {path}: {error}') from error
    try:
        return json.loads(text)
    except json.JSONDecodeError as error:
        # Read as empty, a corrupt file reports "not logged in" for a token
        # sitting right there, and the next login overwrites it.
        raise StoreFailed(f'{path} is not readable as JSON: {error}') from error


def write(path, tokens):
    """Replace the file atomically, created 0600 and set 0600 again explicitly.

    The chmod is the line keeping the token from being world-readable, so it is
    stated rather than left as a property of `mkstemp`.
    """
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, staging = tempfile.mkstemp(dir=path.parent, prefix='.token-', suffix='.json')
    try:
        with os.fdopen(descriptor, 'w') as handle:
            json.dump(tokens, handle, indent=2)
        os.chmod(staging, 0o600)
        os.replace(staging, path)
    finally:
        if os.path.exists(staging):
            os.unlink(staging)


class TokenStore:
    """The keyring under one service name, with the file as its fallback.

    `login_command` is what a not-logged-in refusal tells the user to run.
    """

    def __init__(self, service, state_dir, backend: KeyringBackend = keyring, platform=sys.platform, login_command=''):
        self.service = service
        self.backend = backend
        self.file = FileStore(state_dir)
        self.platform = platform
        self.login_command = login_command

    @property
    def file_path(self):
        return self.file.path

    def save(self, client_id, token):
        """Store the token and return which backend took it."""
        try:
            self.backend.set_password(self.service, client_id, json.dumps(token.to_json()))
            return Backend.KEYRING
        except keyring.errors.KeyringError as error:
            diagnosis = diagnose(self.platform, error)
        if diagnosis.cause.keyring_present:
            raise KeyringRefused(diagnosis.reason)
        try:
            self.file.set(client_id, token)
        except StoreFailed as error:
            raise StoreFailed(f'{diagnosis.reason}, and the fallback file failed: {error}') from error
        return Backend.FILE

    def load(self, client_id):
        """The stored token and its backend, or `NotLoggedIn`.

        The keyring wins whenever it holds something, so a host that gains a
        Secret Service later moves onto it with no re-login.
        """
        keyring_error = None
        try:
            raw = self.backend.get_password(self.service, client_id)
        except keyring.errors.KeyringError as error:
            raw, keyring_error = None, error
        if raw:
            return Token.from_json(json.loads(raw)), Backend.KEYRING
        stored = self.file.get(client_id)
        if stored is not None:
            return stored, Backend.FILE
        reason = diagnose(self.platform, keyring_error).reason if keyring_error is not None else ''
        raise NotLoggedIn(client_id, reason, self.login_command)

    def delete(self, client_id):
        """Forget the token in both stores, so a file token cannot outlive the logout.

        This machine forgets the grant. The provider is not asked to revoke it.
        """
        try:
            self.backend.delete_password(self.service, client_id)
            from_keyring = True
        except keyring.errors.KeyringError:
            from_keyring = False
        from_file = self.file.delete(client_id)
        if not (from_keyring or from_file):
            raise NotLoggedIn(client_id, login_command=self.login_command)
