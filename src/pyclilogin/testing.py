"""An in-memory keyring, so a consumer's tests never touch the machine's real keychain.

goclilogin's `NewTestTokenStore`. The keychain is shared machine state: a test
that logs in through the OS keyring writes a token every later run on that
machine reads.

Hand it to one `Product`:

    import dataclasses
    from pyclilogin.testing import MemoryKeyring

    product = dataclasses.replace(PRODUCT, keyring_backend=MemoryKeyring())

Or make it the process's keyring, which reaches a `Product` captured before the
test ran, such as the one `add_auth_commands` closes over:

    import keyring

    keyring.set_keyring(MemoryKeyring())
"""

from __future__ import annotations

import keyring.backend
import keyring.errors


class MemoryKeyring(keyring.backend.KeyringBackend):
    """A working keyring: the three keyring calls over a dict.

    Its priority is below the `fail` backend's, so `keyring`'s own discovery
    never picks it on a host where only that would answer.
    """

    priority = -1

    def __init__(self):
        super().__init__()
        self.entries = {}

    def set_password(self, service, username, password):
        self.entries[(service, username)] = password

    def get_password(self, service, username):
        return self.entries.get((service, username))

    def delete_password(self, service, username):
        if (service, username) not in self.entries:
            raise keyring.errors.PasswordDeleteError('not found')
        del self.entries[(service, username)]
