"""One product CLI's login, as its config file names it.

Every command a CLI runs builds its provider, store and token source from one
`Product` and one `Deployment`. So the login, the logout, the status and every
API request cannot disagree about which client or which keychain entry they
mean.

The CLI supplies its name, its keyring service, and anything it changes from
the defaults. Each Go product CLI writes this half for itself beside
goclilogin's core. In Python it is the same in every CLI, so it ships here.

## Three ways a machine gets its token

    the config file's token_command set ──→ CommandTokenSource
    $<NAME>_CLIENT_SECRET set ────────────→ ServiceTokenSource
    neither ──────────────────────────────→ TokenSource over the keychain

- **A person** logs in once with the device grant, and every command refreshes
  the stored token.
- **A service** holds a confidential client's secret in the environment, and
  authenticates as the file's `client_id` with the client-credentials grant. Its
  token carries only the scopes its command asks for, so a command a service
  runs names its scope through `token_source(deployment, service_scopes)`.
- **A workload whose broker hands it tokens** names the broker's command as the
  file's `token_command`. Every request carries what it prints, and the CLI
  never logs in.

The secret stays in the environment rather than the file, because a status
command prints the file and a file holds a credential at whatever mode it has.
"""

from __future__ import annotations

import os
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import keyring

from . import deployment
from .errors import ConfigRefused
from .errors import NotConfigured
from .errors import ServiceUnscoped
from .provider import DEFAULT_SCOPES
from .provider import USER_AGENT
from .provider import Provider
from .session import CommandTokenSource
from .session import ServiceTokenSource
from .session import TokenSource
from .store import TokenStore


@dataclass(frozen=True)
class Product:
    """One CLI: what names its config file, its keychain entries, its state and its service secret.

    `name` names the config directory, the state directory and the client id
    login derives. `keyring_service` namespaces the CLI's keychain entries. It
    is a deployed identifier: it keeps its spelling whatever the package or the
    command is renamed to, or every machine's stored token is orphaned.

    `product_keys` is None where the CLI reads keys of its own from the config
    file and checks them itself, or the CLI's own keys, so any key outside them
    and the login's is refused. `config_example_command` is a command printing
    an annotated config file. A service client cannot log in to fill the file,
    so its refusal names that command where one is set.
    """

    name: str
    keyring_service: str
    state_dir: Path | None = None
    scopes: tuple[str, ...] = DEFAULT_SCOPES
    secret_variable: str = ''
    user_agent: str = USER_AGENT
    product_keys: frozenset[str] | None = None
    config_example_command: str = ''
    keyring_backend: Any = keyring
    platform: str = sys.platform

    @property
    def client_secret_variable(self):
        """`secret_variable`, or `<NAME>_CLIENT_SECRET` where none is set."""
        return self.secret_variable or f'{self.name.upper().replace("-", "_")}_CLIENT_SECRET'

    def config_path(self):
        return deployment.config_path(self.name)

    def resolved_state_dir(self):
        """Where the refresh lock and the fallback token file live, resolved at call time.

        The XDG variables are part of a run's environment, so a value frozen at
        import would read one directory while a later command reports another.
        """
        if self.state_dir is not None:
            return Path(self.state_dir)
        declared = os.environ.get('XDG_STATE_HOME')
        base = Path(declared).expanduser() if declared else Path.home() / '.local' / 'state'
        return base / self.name

    def login_command(self):
        return f'{self.name} auth login'

    def client_secret(self):
        """A service client's secret, from the environment alone, or '' where none is set."""
        return os.environ.get(self.client_secret_variable, '')

    def is_service(self):
        return bool(self.client_secret())

    def default_client_id(self):
        """`<name>-cli-<short hostname>`, the client login derives when nothing names one."""
        return deployment.client_id_for(self.name)

    def load(self, api=''):
        """Where every command is pointed, or `NotConfigured` naming what fills it in.

        A person fills the file with `<name> auth login <url>`. A service client
        cannot log in, so its refusal names the keys to write instead, with
        `client_id` as the client its secret belongs to.
        """
        try:
            return deployment.load_deployment(self.name, api, user_agent=self.user_agent, product_keys=self.product_keys)
        except NotConfigured as unconfigured:
            if not self.is_service():
                raise
            resolved = unconfigured.deployment
            example = f' `{self.config_example_command}` prints the file.' if self.config_example_command else ''
            raise NotConfigured(
                f'not configured: {resolved.path} sets no {" or ".join(resolved.missing())}. '
                f'${self.client_secret_variable} is set, so {self.name} authenticates as a service client, which cannot log in '
                'to fill the file. Write api, issuer and client_id there, with client_id the service client the secret '
                f'belongs to, such as {self.name}-svc-<machine>.{example}',
                resolved,
            ) from unconfigured

    def for_login(self, api='', client_id=''):
        """What `<name> auth login` logs in to: the file's values, with what it lacks filled in."""
        return deployment.deployment_for_login(self.name, api, client_id, user_agent=self.user_agent, product_keys=self.product_keys)

    def store(self):
        return TokenStore(
            self.keyring_service,
            self.resolved_state_dir(),
            backend=self.keyring_backend,
            platform=self.platform,
            login_command=self.login_command(),
        )

    def provider(self, resolved, scopes=None):
        """The identity provider the deployment names, asked as its client for `scopes`, or the product's."""
        return Provider(
            issuer=resolved.issuer.value,
            client_id=resolved.client_id.value,
            scopes=tuple(self.scopes if scopes is None else scopes),
            user_agent=self.user_agent,
        )

    def service_repair(self):
        """What fixes a refused service client: the file's client id, or the secret."""
        return f'Check client_id in {self.config_path()} and ${self.client_secret_variable}.'

    def repair(self, resolved):
        """What fixes a token the API refused, for whichever of the three sources sent it.

        A handed token's remedy is whatever handed it, so it names the command. A
        login offered there is refused, because the file's token_command rules one out.
        """
        if resolved.hands_tokens():
            return f'Check what token_command in {resolved.path} hands out: `{shlex.join(resolved.token_command)}`.'
        if self.is_service():
            return self.service_repair()
        return f'Run `{self.login_command()}`.'

    def refuse_two_credentials(self, resolved):
        """Stop a file naming a token_command where the secret also makes this machine a service client."""
        if resolved.hands_tokens() and self.is_service():
            raise ConfigRefused(
                f'{resolved.path} sets token_command and ${self.client_secret_variable} is set, '
                f'so {self.name} has two credentials; keep one'
            )

    def token_source(self, resolved, service_scopes=()):
        """A source for this machine's token, or `NotLoggedIn` when it holds none.

        `service_scopes` is what a service client requests. A person's login
        carries the scopes it was granted at login, so it ignores them.
        """
        client_id = resolved.client_id.value
        if resolved.hands_tokens():
            self.refuse_two_credentials(resolved)
            return CommandTokenSource(resolved.token_command, resolved.path)
        if not self.is_service():
            return TokenSource(self.provider(resolved), self.store(), client_id, self.resolved_state_dir())
        if not service_scopes:
            raise ServiceUnscoped(
                f'${self.client_secret_variable} is set, so {self.name} authenticates as service client {client_id}. '
                'A service client asks for the scope its command names, and this command names none. '
                f"Run it with a person's `{self.login_command()}`, with ${self.client_secret_variable} unset."
            )
        return ServiceTokenSource(self.provider(resolved, service_scopes), self.client_secret(), self.service_repair())
