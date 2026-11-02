"""An in-memory keyring, so a consumer's tests never touch the machine's real keychain.

goclilogin's `NewTestTokenStore`. The keychain is shared machine state: a test
that logs in through the OS keyring writes a token every later run on that
machine reads.

    import dataclasses
    from pyclilogin.testing import MemoryKeyring

    product = dataclasses.replace(PRODUCT, keyring_backend=MemoryKeyring())
"""

from __future__ import annotations

import keyring.errors


class MemoryKeyring:
    """A working keyring: the `keyring` module's three calls over a dict."""

    def __init__(self):
        self.entries = {}

    def set_password(self, service, username, password):
        self.entries[(service, username)] = password

    def get_password(self, service, username):
        return self.entries.get((service, username))

    def delete_password(self, service, username):
        if (service, username) not in self.entries:
            raise keyring.errors.PasswordDeleteError('not found')
        del self.entries[(service, username)]
