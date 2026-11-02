"""Where a token goes: the keyring, the file where there is none, and a refusal where one refuses."""

from __future__ import annotations

import datetime as dt
import stat

import keyring.errors
import pytest
from conftest import LockedKeychain
from conftest import NoKeyring

from pyclilogin import Backend
from pyclilogin import KeyringRefused
from pyclilogin import NotLoggedIn
from pyclilogin import StoreFailed
from pyclilogin import Token
from pyclilogin import TokenStore
from pyclilogin.store import Cause
from pyclilogin.store import diagnose
from pyclilogin.testing import MemoryKeyring

CLIENT = 'acme-cli-test'
TOKEN = Token('at', 'rt', 'Bearer', dt.datetime(2026, 10, 7, 12, tzinfo=dt.UTC))


def store_with(backend, tmp_path, platform='linux'):
    return TokenStore('acme-cli', tmp_path / 'state', backend=backend, platform=platform, login_command='acme auth login')


class TestAHostWithAKeyring:
    def test_the_token_goes_to_the_keyring(self, tmp_path):
        store = store_with(MemoryKeyring(), tmp_path)
        assert store.save(CLIENT, TOKEN) == Backend.KEYRING
        assert store.load(CLIENT) == (TOKEN, Backend.KEYRING)
        assert not store.file_path.exists()


class TestAHostWithNoKeyring:
    def test_the_token_falls_back_to_a_file_readable_by_this_user_alone_and_says_so(self, tmp_path):
        store = store_with(NoKeyring(), tmp_path)
        assert store.save(CLIENT, TOKEN) == Backend.FILE
        assert store.load(CLIENT) == (TOKEN, Backend.FILE)
        assert stat.S_IMODE(store.file_path.stat().st_mode) == 0o600
        assert store.file_path.parent.stat().st_mode & 0o777 == 0o700

    def test_a_host_that_gains_a_keyring_moves_onto_it(self, tmp_path):
        store_with(NoKeyring(), tmp_path).save(CLIENT, Token('old'))
        store = store_with(MemoryKeyring(), tmp_path)
        store.save(CLIENT, TOKEN)
        assert store.load(CLIENT) == (TOKEN, Backend.KEYRING)

    def test_a_corrupt_file_is_an_error_not_a_logout(self, tmp_path):
        store = store_with(NoKeyring(), tmp_path)
        store.save(CLIENT, TOKEN)
        store.file_path.write_text('{')
        with pytest.raises(StoreFailed, match='not readable as JSON'):
            store.load(CLIENT)


class TestALockedMacKeychain:
    def test_it_is_attributed_by_its_status_and_not_its_wording(self):
        try:
            LockedKeychain().set_password('s', 'u', 'p')
        except keyring.errors.KeyringError as error:
            assert diagnose('darwin', error).cause is Cause.LOCKED
            assert diagnose('linux', error).cause is Cause.UNATTRIBUTED

    def test_save_refuses_rather_than_writing_plaintext(self, tmp_path):
        """A file token would outlive the lock, and `load` would keep preferring it."""
        store = store_with(LockedKeychain(), tmp_path, platform='darwin')
        with pytest.raises(KeyringRefused, match='security unlock-keychain'):
            store.save(CLIENT, TOKEN)
        assert not store.file_path.exists()

    def test_load_says_the_keychain_is_locked_rather_than_logged_out(self, tmp_path):
        store = store_with(LockedKeychain(), tmp_path, platform='darwin')
        with pytest.raises(NotLoggedIn) as refused:
            store.load(CLIENT)
        assert 'locked' in refused.value.keyring_reason


class TestLogout:
    def test_it_clears_both_stores(self, tmp_path):
        """A file token from before the keyring would otherwise outlive the logout."""
        store_with(NoKeyring(), tmp_path).save(CLIENT, Token('from-file'))
        store = store_with(MemoryKeyring(), tmp_path)
        store.save(CLIENT, TOKEN)
        store.delete(CLIENT)
        with pytest.raises(NotLoggedIn, match='Run `acme auth login`'):
            store.load(CLIENT)

    def test_nothing_stored_anywhere_is_not_logged_in(self, tmp_path):
        with pytest.raises(NotLoggedIn):
            store_with(MemoryKeyring(), tmp_path).delete(CLIENT)
