"""Exceptions raised by pyclilogin.

Every failure mode has its own class, so a caller matches on a type rather than
on message text. Each is one level under `LoginError`, which is what a CLI's
entry point catches to print the message as one sentence. Every message names
what fixes it.
"""

from __future__ import annotations


class LoginError(Exception):
    """Base class for every error this package raises."""


class NotConfigured(LoginError):
    """The config file lacks a value every command needs.

    `deployment` carries the path and whatever the file did set, so a status
    command can show what is missing.
    """

    def __init__(self, message, deployment):
        self.deployment = deployment
        super().__init__(message)


class ConfigRefused(LoginError):
    """A config file, a value given in its place, or a combination of credentials that cannot be honored."""


class MetadataRefused(LoginError):
    """An API's RFC 9728 metadata could not be read, or does not name the login server it needs to."""


class ProviderUnreachable(LoginError):
    """The identity provider could not be asked, which proves nothing about the grant."""


class TokenRefused(LoginError):
    """The identity provider refused the exchange. Only an interactive login fixes it."""

    def __init__(self, error, description=''):
        self.error = error
        self.description = description
        super().__init__(f'the identity provider refused: {error}{f" ({description})" if description else ""}')


class LoginAbandoned(LoginError):
    """The device code expired or was denied before anything approved it."""


class NotLoggedIn(LoginError):
    """Neither store holds a token for this client. A state, not a fault.

    `keyring_reason` is set when the keyring failed rather than came back empty.
    "Not logged in" and "your keychain is locked" need different fixes.
    """

    def __init__(self, client_id, keyring_reason='', login_command=''):
        self.client_id = client_id
        self.keyring_reason = keyring_reason
        detail = f' ({keyring_reason})' if keyring_reason else ''
        fix = f' Run `{login_command}`.' if login_command else ''
        super().__init__(f'not logged in as {client_id}{detail}.{fix}')


class KeyringRefused(LoginError):
    """A keyring this host demonstrably has would not take the token."""


class StoreFailed(LoginError):
    """The token file could not be read or written, or a refreshed token could not be kept."""


class ServiceRefused(LoginError):
    """The provider refused a service client. Its secret or its registration fixes it, never a login."""


class ServiceUnscoped(LoginError):
    """A service client running a command that names no scope for it to request."""


class TokenCommandFailed(LoginError):
    """The config file's token_command printed no token. Whatever it talks to fixes it, never a login."""
