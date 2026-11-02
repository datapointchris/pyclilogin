"""The refresh is serialized across processes, so the grant survives a stampede, and a service stores nothing.

A port of goclilogin's pair. Eight processes start holding the same expired token
and ask for a usable one at once. The provider rotates the refresh token on every
use and revokes the whole grant when a consumed one is replayed, as RFC 9700
§ 4.14.2 requires. Its state is a file under its own lock, so the eight
processes see one server.
"""

from __future__ import annotations

import datetime as dt
import fcntl
import json
import multiprocessing
import time
from pathlib import Path

import pytest
from conftest import NoKeyring

from pyclilogin import ServiceRefused
from pyclilogin import ServiceTokenSource
from pyclilogin import Token
from pyclilogin import TokenRefused
from pyclilogin import TokenSource
from pyclilogin import TokenStore
from pyclilogin import session

PROCESSES = 8
CLIENT = 'acme-cli-test'
EXPIRED = dt.datetime(2020, 1, 1, tzinfo=dt.UTC)


class RotatingProvider:
    """A provider whose grant lives in a file, so every process refreshes against one."""

    def __init__(self, state):
        self.state = Path(state)

    def refresh(self, token):
        # Widens the window between reading the stored token and presenting it,
        # which is where the race lives.
        time.sleep(0.05)
        with open(self.state, 'r+') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            grant = json.load(handle)
            if grant['revoked'] or token.refresh_token != grant['current']:
                grant['revoked'] = True
                handle.seek(0)
                handle.truncate()
                json.dump(grant, handle)
                raise TokenRefused('invalid_grant', 'refresh token replayed; grant revoked')
            grant['rotations'] += 1
            grant['current'] = f'rt-{grant["rotations"]}'
            handle.seek(0)
            handle.truncate()
            json.dump(grant, handle)
        return Token(f'at-{grant["rotations"]}', grant['current'], expiry=dt.datetime.now(dt.UTC) + dt.timedelta(hours=1))


def file_store(state_dir):
    return TokenStore('acme-cli', state_dir, backend=NoKeyring(), platform='linux')


def one_process(state_dir, provider_state, barrier, outcomes):
    source = TokenSource(RotatingProvider(provider_state), file_store(state_dir), CLIENT, state_dir)
    barrier.wait()
    try:
        source.token()
        outcomes.put('ok')
    except TokenRefused:
        outcomes.put('refused')


def test_with_the_lock_one_process_refreshes_and_the_rest_use_its_token(tmp_path):
    state_dir = tmp_path / 'state'
    file_store(state_dir).save(CLIENT, Token('at-0', 'rt-0', expiry=EXPIRED))
    provider_state = tmp_path / 'grant.json'
    provider_state.write_text(json.dumps({'current': 'rt-0', 'rotations': 0, 'revoked': False}))

    context = multiprocessing.get_context('fork')
    barrier = context.Barrier(PROCESSES)
    outcomes = context.Queue()
    workers = [context.Process(target=one_process, args=(state_dir, provider_state, barrier, outcomes)) for _ in range(PROCESSES)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=30)
    results = [outcomes.get(timeout=5) for _ in workers]

    assert results == ['ok'] * PROCESSES
    assert json.loads(provider_state.read_text()) == {'current': 'rt-1', 'rotations': 1, 'revoked': False}


def test_a_live_token_asks_the_provider_nothing(tmp_path):
    class Untouchable:
        def refresh(self, token):
            raise AssertionError('a live token must not be refreshed')

    store = file_store(tmp_path)
    store.save(CLIENT, Token('at', 'rt', expiry=dt.datetime.now(dt.UTC) + dt.timedelta(hours=1)))
    assert TokenSource(Untouchable(), store, CLIENT, tmp_path).token().access_token == 'at'


def test_the_lock_degrades_to_unlocked_when_the_holder_is_wedged(tmp_path):
    with session.refresh_lock(tmp_path, CLIENT) as first:
        assert first
        with session.refresh_lock(tmp_path, CLIENT, wait=0.1) as second:
            assert not second


class ScriptedProvider:
    client_id = 'acme-svc-scheduler'

    def __init__(self, *answers):
        self.answers = list(answers)
        self.asked = 0

    def client_credentials(self, secret):
        self.asked += 1
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer


def lasting(seconds):
    return Token(f'at-{seconds}', expiry=dt.datetime.now(dt.UTC) + dt.timedelta(seconds=seconds))


class TestTheServiceTokenSource:
    def test_a_live_token_is_reused_and_a_lapsed_one_replaced(self):
        provider = ScriptedProvider(lasting(5), lasting(300))
        source = ServiceTokenSource(provider, 's3cret')
        assert source.token().access_token == 'at-5'
        assert source.token().access_token == 'at-300'
        assert source.token().access_token == 'at-300'
        assert provider.asked == 2

    def test_a_refusal_names_the_client_and_the_repair_and_never_suggests_a_login(self, product):
        source = ServiceTokenSource(ScriptedProvider(TokenRefused('invalid_client', 'bad secret')), 'wrong', product.service_repair())
        with pytest.raises(ServiceRefused) as refused:
            source.token()
        assert 'acme-svc-scheduler' in str(refused.value)
        assert product.client_secret_variable in str(refused.value)
        assert 'login' not in str(refused.value)
