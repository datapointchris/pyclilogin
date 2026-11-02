"""Log a Python command-line tool into an OIDC provider, and keep it logged in across every run on the machine.

The Python sibling of goclilogin, held to its contract point for point:

- one config file, `$XDG_CONFIG_HOME/<product>/config.toml`, holding `api`,
  `issuer` and `client_id`, read by every command and filled in by
  `<product> auth login <url>`
- the device authorization grant, so approval works from any browser on any
  device, over SSH too
- a token store in the OS keychain that falls back to a mode-600 file only where
  there may be no keyring, says when it did, and refuses where a keyring
  demonstrably exists
- a refresh serialized across processes with `flock`, re-reading the store once
  the lock is held, so a provider rotating refresh tokens never revokes the grant
- a client-credentials source for a service, which keeps its token in memory and
  stores nothing
- a token command, for a workload whose broker hands it short-lived tokens

    from pyclilogin import Product

    product = Product(name='acme', keyring_service='acme-cli')
    resolved = product.load()
    token = product.token_source(resolved).token().access_token

The layers: `deployment` reads and writes the config file, `provider` speaks
OAuth to the identity provider, `store` keeps the token, `session` hands out a
usable one, and `product` builds all of them for one CLI. The typer commands
live in `pyclilogin.typercmd`, installed with the `typer` extra.
"""

from pyclilogin.deployment import Deployment
from pyclilogin.deployment import Setting
from pyclilogin.deployment import Source
from pyclilogin.deployment import config_path
from pyclilogin.deployment import deployment_for_login
from pyclilogin.deployment import load_deployment
from pyclilogin.deployment import write_deployment
from pyclilogin.errors import ConfigRefused
from pyclilogin.errors import KeyringRefused
from pyclilogin.errors import LoginAbandoned
from pyclilogin.errors import LoginError
from pyclilogin.errors import MetadataRefused
from pyclilogin.errors import NotConfigured
from pyclilogin.errors import NotLoggedIn
from pyclilogin.errors import ProviderUnreachable
from pyclilogin.errors import ServiceRefused
from pyclilogin.errors import ServiceUnscoped
from pyclilogin.errors import StoreFailed
from pyclilogin.errors import TokenCommandFailed
from pyclilogin.errors import TokenRefused
from pyclilogin.product import Product
from pyclilogin.provider import DEFAULT_SCOPES
from pyclilogin.provider import DevicePrompt
from pyclilogin.provider import Provider
from pyclilogin.provider import Token
from pyclilogin.session import CommandTokenSource
from pyclilogin.session import ServiceTokenSource
from pyclilogin.session import TokenSource
from pyclilogin.store import Backend
from pyclilogin.store import TokenStore

__all__ = [
    'DEFAULT_SCOPES',
    'Backend',
    'CommandTokenSource',
    'ConfigRefused',
    'Deployment',
    'DevicePrompt',
    'KeyringRefused',
    'LoginAbandoned',
    'LoginError',
    'MetadataRefused',
    'NotConfigured',
    'NotLoggedIn',
    'Product',
    'Provider',
    'ProviderUnreachable',
    'ServiceRefused',
    'ServiceTokenSource',
    'ServiceUnscoped',
    'Setting',
    'Source',
    'StoreFailed',
    'Token',
    'TokenCommandFailed',
    'TokenRefused',
    'TokenSource',
    'TokenStore',
    'config_path',
    'deployment_for_login',
    'load_deployment',
    'write_deployment',
]
