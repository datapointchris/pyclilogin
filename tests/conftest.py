"""Every test runs on a machine with no config file, no service secret and no keyring of its own.

The config file, the state directory and the secret are ambient. A test run on a
desk would otherwise read a real config while the same test in CI reads
nothing, and the one that passes on both asserted neither. The secret is
exported before it is cleared, so the clearing has something to remove on a
machine that never leaked it.

The keychain is shared machine state, so every test's `Product` keeps its
tokens in a `MemoryKeyring`.
"""

from __future__ import annotations

import dataclasses as dc
from types import SimpleNamespace

import httpx2
import keyring.errors
import pytest

from pyclilogin import Product
from pyclilogin.testing import MemoryKeyring

XDG_BASES = ('XDG_CONFIG_HOME', 'XDG_STATE_HOME')
ACME = Product(name='acme', keyring_service='acme-cli', product_keys=frozenset())


@pytest.fixture(autouse=True)
def unconfigured_machine(monkeypatch, tmp_path):
    monkeypatch.setenv(ACME.client_secret_variable, 'seeded-so-the-clearing-has-something-to-remove')
    monkeypatch.delenv(ACME.client_secret_variable)
    for name in XDG_BASES:
        monkeypatch.setenv(name, str(tmp_path / name.lower()))
    monkeypatch.setenv('HOME', str(tmp_path / 'home'))
    return tmp_path


@pytest.fixture
def product():
    return dc.replace(ACME, keyring_backend=MemoryKeyring())


@pytest.fixture
def write_config():
    """Write acme's config file, returning its path."""

    def write(body):
        path = ACME.config_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
        return path

    return write


@pytest.fixture
def metadata(monkeypatch):
    """Every API answering its RFC 9728 metadata from `documents`, keyed by the URL asked; anything else is 404."""
    documents = {}
    asked = []

    def answer(request):
        asked.append(str(request.url))
        document = documents.get(str(request.url))
        return httpx2.Response(200, json=document) if document is not None else httpx2.Response(404)

    transport = httpx2.MockTransport(answer)
    real = httpx2.Client
    monkeypatch.setattr(httpx2, 'Client', lambda **kwargs: real(**{**kwargs, 'transport': transport}))
    return SimpleNamespace(documents=documents, asked=asked)


class NoKeyring:
    """A Linux host with no Secret Service: every call fails before reaching anything."""

    def set_password(self, service, username, password):
        raise keyring.errors.NoKeyringError('No recommended backend was available')

    def get_password(self, service, username):
        raise keyring.errors.NoKeyringError('No recommended backend was available')

    def delete_password(self, service, username):
        raise keyring.errors.NoKeyringError('No recommended backend was available')


class MacKeychainError(Exception):
    """What keyring's macOS api raises: the OSStatus as the first argument."""


class LockedKeychain:
    """macOS over SSH: errSecInteractionNotAllowed, wrapped the way keyring wraps it."""

    def _locked(self, wrapper, verb):
        try:
            raise MacKeychainError(-25308, 'Unknown Error')
        except MacKeychainError as error:
            raise wrapper(f"Can't {verb} keychain: {error}") from error

    def set_password(self, service, username, password):
        self._locked(keyring.errors.PasswordSetError, 'store password on')

    def get_password(self, service, username):
        self._locked(keyring.errors.KeyringError, 'get password from')

    def delete_password(self, service, username):
        self._locked(keyring.errors.PasswordDeleteError, 'delete password in')
