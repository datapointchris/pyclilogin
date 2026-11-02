"""Where a product CLI is pointed: its API, the login server, and the client this machine logs in as.

A port of goclilogin's `deployment.go`, held to its contract:

- **One file.** `$XDG_CONFIG_HOME/<product>/config.toml` holds `api`, `issuer`
  and `client_id`.
- **Every command reads it through `load_deployment`.** An explicit `--api`
  outranks the file. A value the file lacks is a refusal naming
  `<product> auth login <url>`. No environment variable is read and no address
  is compiled in.
- **`deployment_for_login` fills in only what the file lacks.** `api` comes from
  the URL given to login, `issuer` from the API's RFC 9728 metadata, and
  `client_id` from `--client-id` or the short hostname.
- **`Deployment.save` writes only those filled-in values**, and never through a
  symlink. Login refuses a linked file before the device grant starts.

## A key outside the login's belongs to the product

goclilogin leaves any other key in the file to its product, and so does this
module by default. A product whose file holds nothing else passes
`product_keys=()`, and a key outside the login's and the product's is then
refused rather than ignored. That catches a renamed key: `api_base`, filed under
an old spelling, would otherwise read as a file setting no `api`.

## An `--api` the file does not name is checked before it gets a token

Every request carries a token the file's issuer signed. So an `--api` differing
from the file's must name that issuer in its own metadata, or the command is
refused before anything is sent.
"""

from __future__ import annotations

import contextlib
import dataclasses as dc
import enum
import json
import os
import socket
import tempfile
import tomllib
from dataclasses import dataclass
from dataclasses import field
from pathlib import Path
from urllib.parse import urlsplit
from urllib.parse import urlunsplit

import httpx2

from .errors import ConfigRefused
from .errors import MetadataRefused
from .errors import NotConfigured
from .provider import TIMEOUT_SECONDS
from .provider import USER_AGENT

KEYS = ('api', 'issuer', 'client_id')

# The argv a broker's token command runs, set only in the file. A CLI whose file
# names one is handed its tokens and never logs in, so it needs only `api`.
TOKEN_COMMAND = 'token_command'

# RFC 9728 § 3.1 inserts this between the resource's host and its path.
METADATA_PATH = '/.well-known/oauth-protected-resource'

# The first column of every row `write_deployment` prints, and of any row a
# status command adds beneath them.
LABEL_WIDTH = max(len(key) for key in (*KEYS, TOKEN_COMMAND)) + 2


class Source(enum.StrEnum):
    """The layer that set a value."""

    COMMAND_LINE = 'command-line'
    FILE = 'file'
    DISCOVERED = 'discovered'
    HOSTNAME = 'hostname'


@dataclass(frozen=True)
class Setting:
    """One resolved value and the layer that set it. An empty value means nothing set it.

    `origin` is goclilogin's `From`: the file's path, the metadata URL a value
    was discovered at, or the hostname a client id was derived from.
    """

    value: str = ''
    source: Source | None = None
    origin: str = ''

    def describe_source(self):
        match self.source:
            case Source.COMMAND_LINE:
                return '(command line)'
            case Source.FILE:
                return '(config file)'
            case Source.DISCOVERED:
                return f'(discovered at {self.origin})'
            case Source.HOSTNAME:
                return f'(from hostname {self.origin})' if self.origin else '(no hostname)'
        return '(not set)'

    def to_json(self):
        return {'value': self.value, 'source': str(self.source or ''), 'from': self.origin}


@dataclass(frozen=True)
class Deployment:
    """Where the CLI is pointed, and the config file that says so."""

    path: Path
    api: Setting = field(default_factory=Setting)
    issuer: Setting = field(default_factory=Setting)
    client_id: Setting = field(default_factory=Setting)
    token_command: tuple[str, ...] = ()

    def settings(self):
        return (('api', self.api), ('issuer', self.issuer), ('client_id', self.client_id))

    def hands_tokens(self):
        """Whether the file's token_command hands this CLI its tokens, so it has no login of its own."""
        return bool(self.token_command)

    def missing(self):
        if self.hands_tokens():
            return [] if self.api.value else ['api']
        return [key for key, setting in self.settings() if not setting.value]

    def to_json(self):
        settings = {key: setting.to_json() for key, setting in self.settings()}
        return {'config_file': str(self.path), **settings, TOKEN_COMMAND: list(self.token_command)}

    def unwritten(self):
        """The keys `save` would write: every value that did not come from the file."""
        return [key for key, setting in self.settings() if setting.value and setting.source != Source.FILE]

    def save(self):
        """Write every value that did not come from the config file into it.

        Nothing already in the file is rewritten, and a file lacking nothing is
        not touched. The file is read again first, so a key written while the
        login waited for approval is kept rather than duplicated. The missing
        keys are written above the lines already there. A file reached through
        a symlink is refused, as `refuse_link` says.
        """
        current = read_config_file(self.path)
        missing = {key: getattr(self, key).value for key in self.unwritten() if key not in current}
        if not missing:
            return
        refuse_link(self.path, missing)
        lines = ''.join(f'{key} = {toml_string(value)}\n' for key, value in missing.items())
        try:
            existing = self.path.read_text()
        except FileNotFoundError:
            existing = ''
        except OSError as error:
            raise ConfigRefused(f'cannot read {self.path}: {error}') from error
        try:
            write_atomically(self.path, lines + ('\n' + existing if existing else ''))
        except OSError as error:
            raise ConfigRefused(f'cannot write {self.path}: {error}') from error


def config_path(product):
    """`$XDG_CONFIG_HOME/<product>/config.toml`, falling back to `~/.config`."""
    base = os.environ.get('XDG_CONFIG_HOME')
    root = Path(base).expanduser() if base else Path.home() / '.config'
    return root / product / 'config.toml'


def short_hostname():
    """The hostname's first label, lowercased, or '' where the OS reports none."""
    return socket.gethostname().split('.')[0].lower()


def client_id_for(product):
    """The conventional per-machine client: `acme` on `Laptop.example.lan` is `acme-cli-laptop`."""
    host = short_hostname()
    return f'{product}-cli-{host}' if host else f'{product}-cli'


def load_deployment(product, api='', *, user_agent=USER_AGENT, product_keys=None):
    """The deployment every command talks to. `api` is the `--api` flag's value, and outranks the file's.

    `product_keys` is None to leave every key outside the login's to the
    product, or the product's own keys, to refuse any other.
    """
    path = config_path(product)
    file = read_config_file(path, product_keys)
    deployment = Deployment(
        path=path,
        api=Setting(api, Source.COMMAND_LINE) if api else from_file(file, 'api', path),
        issuer=from_file(file, 'issuer', path),
        client_id=from_file(file, 'client_id', path),
        token_command=tuple(file.get(TOKEN_COMMAND, ())),
    )
    missing = deployment.missing()
    if missing:
        raise NotConfigured(f'not configured: {path} sets no {" or ".join(missing)}; run `{product} auth login <url>`', deployment)

    from_command_line = deployment.api.source == Source.COMMAND_LINE
    resource = normalize_api(deployment.api.value, None if from_command_line else path)
    deployment = dc.replace(deployment, api=dc.replace(deployment.api, value=resource))
    if from_command_line and resource != normalized_or_empty(file.get('api', '')):
        if not deployment.issuer.value:
            raise ConfigRefused(f'{path} sets no issuer, so --api {resource} cannot be checked before a token is sent to it')
        require_trusted_issuer(resource, deployment.issuer.value, path, user_agent)
    return deployment


def deployment_for_login(product, api='', client_id='', *, user_agent=USER_AGENT, product_keys=None):
    """The deployment a login authenticates against, filling in only what the file lacks.

    A value typed on the command line that differs from the file's is refused,
    naming the file to edit, because login never rewrites what the file says.
    A file login would write that is reached through a symlink is refused here,
    so the refusal arrives before a device grant the user would approve for
    nothing.
    Print the result before the device grant starts, so the login server is on
    screen before anything is sent to it, and `save` it once the grant succeeds.
    """
    path = config_path(product)
    file = read_config_file(path, product_keys)
    if file.get(TOKEN_COMMAND):
        raise ConfigRefused(f'{path} sets token_command, so {product} is handed its tokens by that command and never logs in')

    if file.get('api'):
        resource = normalize_api(file['api'], path)
        if api and normalize_api(api) != resource:
            raise ConfigRefused(f'{path} already sets api = "{resource}"; edit it there to log in to {normalize_api(api)}')
        api_setting = Setting(resource, Source.FILE, str(path))
    elif api:
        api_setting = Setting(normalize_api(api), Source.COMMAND_LINE)
    else:
        raise NotConfigured(f'not configured: {path} sets no api; run `{product} auth login <url>`', Deployment(path))

    if file.get('issuer'):
        issuer = from_file(file, 'issuer', path)
    else:
        server, metadata_url = discover_authorization_server(api_setting.value, path, user_agent)
        issuer = Setting(server, Source.DISCOVERED, metadata_url)

    if file.get('client_id'):
        if client_id and client_id != file['client_id']:
            raise ConfigRefused(f'{path} already sets client_id = "{file["client_id"]}"; edit it there to log in as {client_id}')
        client = from_file(file, 'client_id', path)
    elif client_id:
        client = Setting(client_id, Source.COMMAND_LINE)
    else:
        client = Setting(client_id_for(product), Source.HOSTNAME, short_hostname())

    resolved = Deployment(path=path, api=api_setting, issuer=issuer, client_id=client)
    if resolved.unwritten():
        refuse_link(path, resolved.unwritten())
    return resolved


def write_deployment(out, deployment):
    """Each value, the layer that set it, and the config file's path, one row each."""
    rows = [(key, setting.value or '-', setting.describe_source()) for key, setting in deployment.settings()]
    if deployment.hands_tokens():
        rows.append((TOKEN_COMMAND, ' '.join(deployment.token_command), '(config file)'))
    rows.append(('config', str(deployment.path), ''))
    width = max(len(value) for _, value, _ in rows) + 2
    for key, value, source in rows:
        print(f'{label(key)}{value:<{width}}{source}'.rstrip(), file=out)


def label(name):
    """A row's indented first column, the width `write_deployment` aligns its values to."""
    return f'  {name:<{LABEL_WIDTH}}'


def from_file(file, key, path):
    value = file.get(key, '')
    return Setting(value, Source.FILE, str(path)) if value else Setting()


def read_config_file(path, product_keys=None):
    """The keys this module owns, or {} where the file does not exist.

    A key set to "" is refused rather than read as absent. TOML counts it as
    defined, so a login filling it in would write a second definition, and no
    TOML reader accepts a file holding two.
    """
    try:
        with open(path, 'rb') as handle:
            parsed = tomllib.load(handle)
    except FileNotFoundError:
        return {}
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ConfigRefused(f'cannot read {path}: {error}') from error
    owned = (*KEYS, TOKEN_COMMAND)
    if product_keys is not None:
        known = {*owned, *product_keys}
        unknown = sorted(set(parsed) - known)
        if unknown:
            raise ConfigRefused(f'{path}: unknown key(s) {", ".join(unknown)}; known: {", ".join(sorted(known))}')
    login = {key: value for key, value in parsed.items() if key in owned}
    for key, value in login.items():
        if key == TOKEN_COMMAND:
            if (
                not isinstance(value, list)
                or not value
                or not all(isinstance(arg, str) and '\0' not in arg for arg in value)
                or not value[0]
            ):
                raise ConfigRefused(
                    f'{path} sets token_command to something other than an argv; write it as token_command = ["program", "arg"]'
                )
            continue
        if not isinstance(value, str):
            raise ConfigRefused(f'{path} sets {key} to a {type(value).__name__}; write it as {key} = "..."')
        if not value:
            raise ConfigRefused(f'{path} sets {key} to an empty value; give it one, or delete the line for login to fill in')
    return login


def normalize_api(raw, path=None):
    """`raw` without a trailing slash, once it is an absolute http or https URL.

    That is the resource identifier RFC 9728 inserts its well-known suffix into
    and compares the document's `resource` against. `path` names the file a
    malformed value came from.
    """
    try:
        parts = urlsplit(raw)
    except ValueError:
        parts = None
    if parts is None or parts.scheme not in ('http', 'https') or not parts.netloc:
        where = f'{path}: ' if path else ''
        raise ConfigRefused(f'{where}api {raw!r} is not an http or https URL, such as https://api.example.com')
    return raw.rstrip('/')


def normalized_or_empty(raw):
    try:
        return normalize_api(raw) if raw else ''
    except ConfigRefused:
        return ''


def toml_string(value):
    """`value` as a TOML basic string. JSON's escapes are a subset of TOML's."""
    return json.dumps(value)


def protected_resource_metadata_url(resource):
    """Where RFC 9728 § 3.1 puts a resource's metadata: the suffix between its host and its path."""
    parts = urlsplit(resource)
    return urlunsplit((parts.scheme, parts.netloc, METADATA_PATH + parts.path.rstrip('/'), parts.query, ''))


def read_protected_resource_metadata(resource, user_agent=USER_AGENT):
    """The authorization servers an API names, and the URL they were read from.

    A document describing another resource is refused, as RFC 9728 § 3.3 requires.
    """
    url = protected_resource_metadata_url(resource)
    try:
        with httpx2.Client(timeout=TIMEOUT_SECONDS, headers={'User-Agent': user_agent}, follow_redirects=False) as client:
            response = client.get(url)
    except httpx2.HTTPError as error:
        raise MetadataRefused(f'cannot reach the API at {url}: {error}') from error
    if response.status_code != 200:
        raise MetadataRefused(f'{url} answered HTTP {response.status_code}, so the API names no login server')
    try:
        document = response.json()
    except ValueError as error:
        raise MetadataRefused(f'cannot read {url}: {error}') from error
    if not isinstance(document, dict):
        raise MetadataRefused(f'{url} is not a JSON object')
    if document.get('resource') != resource:
        raise MetadataRefused(f'{url} describes {document.get("resource")!r} rather than {resource!r}, so it is refused (RFC 9728 § 3.3)')
    servers = document.get('authorization_servers') or []
    if not isinstance(servers, list) or not all(isinstance(server, str) for server in servers):
        raise MetadataRefused(f'{url} carries authorization_servers that are not a list of URLs')
    return servers, url


def discover_authorization_server(resource, path, user_agent=USER_AGENT):
    """The one issuer an API names, and the URL it was read from. `path` is the file to set it in instead."""
    try:
        servers, url = read_protected_resource_metadata(resource, user_agent)
    except MetadataRefused as error:
        raise MetadataRefused(f'{error}; setting issuer in {path} skips this lookup') from error
    if not servers:
        raise MetadataRefused(f'{url} names no authorization server; set issuer in {path}')
    if len(servers) > 1:
        raise MetadataRefused(
            f'{url} names {len(servers)} authorization servers ({", ".join(servers)}); set issuer in {path} to choose one'
        )
    return servers[0], url


def require_trusted_issuer(resource, issuer, path, user_agent=USER_AGENT):
    """Refuse an API whose metadata does not name `issuer`, before any token is sent to it."""
    try:
        servers, url = read_protected_resource_metadata(resource, user_agent)
    except MetadataRefused as error:
        raise MetadataRefused(f'check --api {resource} before sending it a token: {error}') from error
    if issuer in servers:
        return
    named = f'{", ".join(servers)} as its login server' if servers else 'no login server'
    raise MetadataRefused(f'{url} names {named}, not {issuer} from {path}; no token is sent to it')


def refuse_link(path, keys):
    """Refuse to write `keys` into a config file reached through a symlink.

    A link means a config manager owns the file, and its source may be every
    machine's. A client id written there would become every machine's client
    id, so the refusal names the keys and never suggests adding them to the
    source.
    """
    link = symlink_on_path(path)
    if link:
        raise ConfigRefused(
            f'{link} is a symlink, so whatever manages it owns {path}, and login does not write through it. '
            f"The file sets no {' or '.join(keys)}. Replace the link with a file of this machine's own, "
            'or have its manager write one per machine.'
        )


def symlink_on_path(path):
    """The config file or the product directory holding it, whichever is a symlink, or None."""
    for candidate in (path, path.parent):
        if candidate.is_symlink():
            return candidate
    return None


def write_atomically(path, content):
    """Replace `path` through a rename, so a reader never sees half a file.

    An existing file keeps its mode. A new one is 0644, because the file holds
    addresses and a client name but never a secret.
    """
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    try:
        mode = path.stat().st_mode & 0o777
    except FileNotFoundError:
        mode = 0o644
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix='.config.toml.')
    try:
        with os.fdopen(descriptor, 'w') as handle:
            handle.write(content)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)
        raise
