# pyclilogin

OIDC device-grant login for Python command-line tools. Tokens live in the OS
keychain, and the refresh is serialized across every process on the machine.
The same tool run by a service, with no person to approve a login, uses the
client-credentials grant instead.

It is the Python sibling of
[goclilogin](https://github.com/datapointchris/goclilogin), and keeps its
contract point for point: the same config file, the same keychain fallback, the
same refresh lock. A Go CLI and a Python CLI built on the two log in, store and
refresh the same way. Its server-side counterpart is
[pyapiauth](https://github.com/datapointchris/pyapiauth), which verifies the
tokens this package obtains.

## Install

```bash
uv add pyclilogin            # the core
uv add "pyclilogin[typer]"   # plus the ready-made `auth` commands
```

## Starting from scratch

A CLI called `acme` describes itself once, as a `Product`, and mounts the
`auth` commands on its typer app:

```python
from contextvars import ContextVar

import typer
from pyclilogin import Product
from pyclilogin.typercmd import add_auth_commands

PRODUCT = Product(name='acme', keyring_service='acme-cli')
API_FLAG: ContextVar[str] = ContextVar('api_flag', default='')

app = typer.Typer()


@app.callback()
def root(api: str = typer.Option('', '--api')):
    API_FLAG.set(api)


add_auth_commands(app, PRODUCT, api_flag=API_FLAG.get)
```

That gives `acme auth login [URL]`, `acme auth logout`, `acme auth token` and
`acme auth status`. Every other command gets its token the same way:

```python
import httpx2

resolved = PRODUCT.load(API_FLAG.get())            # the config file, with --api outranking it
source = PRODUCT.token_source(resolved)            # NotLoggedIn where nothing is stored
response = httpx2.get(
    f'{resolved.api.value}/items',
    headers={'Authorization': f'Bearer {source.token().access_token}'},  # refreshed first if it lapsed
)
```

The first run needs three things from outside the CLI:

- The provider advertises a `device_authorization_endpoint` in its OIDC
  discovery document.
- The client id is registered at the provider as a public client with no
  secret.
- The API serves RFC 9728 protected-resource metadata naming its login server.
  A `config.toml` that already sets `issuer` skips this.

Every error is a `LoginError` whose message names its fix, so a CLI's entry
point catches that one class and prints the message.

## Which call answers which question

| Ask | Call | Reads |
| --- | --- | --- |
| Where is this CLI pointed | `Product.load`, `write_deployment` | the config file, and an `--api`'s RFC 9728 metadata where it differs from the file's |
| What does a first login fill in | `Product.for_login` | the config file, then the API's RFC 9728 metadata for a missing `issuer` |
| How does a person log in | `Provider.login` | the issuer's discovery document, then the device grant |
| Where did the token go | `TokenStore.save`, `TokenStore.load` | the OS keychain, then the mode-600 file in the state directory |
| How do requests get a token | `Product.token_source` | the store, then on a refresh the refresh lock and the discovery document |
| How does a service with no person authenticate | `ServiceTokenSource` | the token endpoint, with the client's secret |
| How does a CLI use tokens a broker hands it | `CommandTokenSource` | the stdout of `token_command` from the config file |
| How do my tests avoid the real keychain | `pyclilogin.testing.MemoryKeyring` | a dict |

## One config file says where the CLI is pointed, and only login writes it

`$XDG_CONFIG_HOME/<name>/config.toml` holds three keys:

```toml
api = "https://acme.example.com"
issuer = "https://auth.example.com"
client_id = "acme-cli-laptop"
```

Every command reads it through `Product.load`. An explicit `--api` outranks the
file's. Nothing else is read: no environment variable, and no address compiled
into the package, because each value names one installation.

`acme auth login https://acme.example.com` fills in only what the file lacks.
`api` comes from the URL, `issuer` from the API's
`/.well-known/oauth-protected-resource`, and `client_id` from `--client-id` or
`acme-cli-<short hostname>`. Each is printed with where it came from before the
grant starts, and written once the grant succeeds. A value the file already
holds is never rewritten, and a typed value differing from it is refused.

An `--api` differing from the file's must name the file's issuer in its own
metadata. Otherwise the command is refused before any request carries a token.

Login never writes through a symlink. A link means a config manager owns the
file, and its source may be every machine's. A client id written there would
become every machine's.

A key outside these three belongs to the product, as in goclilogin. A product
whose file holds nothing else passes `product_keys=frozenset()`, and a renamed
key such as `api_base` is then refused rather than read as a file with no
`api`.

## The refresh is serialized across every process on the machine

A provider following RFC 9700 rotates the refresh token on every use, and
revokes the whole grant when a consumed one is presented again. Two processes
refreshing from the same stored token therefore cost an interactive login.
One rotates, and the other replays the token that rotation consumed.

`TokenSource.token` holds an exclusive `flock` in the state directory for the
refresh, and reads the store again once it has the lock. A process that waited
uses the winner's token instead of replaying its own. A lock that cannot be
taken within ten seconds gives an unlocked refresh. That risks one login, where
blocking on a wedged holder would hang every command.

A command holding a live token makes no call to the provider at all.

## The token goes to the keychain, and the downgrade is visible

`TokenStore.save` returns the backend that took the token. On a Linux host with
no Secret Service, that is a mode-600 `token.json` in the state directory, and
`auth login` says so. A macOS keychain locked to an SSH session is refused
instead, with `security unlock-keychain` as the fix. A plaintext copy written
there would outlive the lock. `TokenStore.delete` clears both stores, so a file
token written before a host had a keyring cannot outlive the logout.

## A service authenticates as itself, never as a person

With `ACME_CLIENT_SECRET` set, `Product.token_source` authenticates as the
config file's `client_id` with the client-credentials grant. The variable is
`<NAME>_CLIENT_SECRET` unless `Product.secret_variable` names another. The
secret stays in the environment, because `auth status` prints the file.

```python
source = PRODUCT.token_source(resolved, service_scopes=('acme.items.read',))
```

A service's token carries only the scopes its command names, so a command
naming none is refused before any request. Nothing is stored and no lock is
taken: the grant issues no refresh token. Name the service's client so the API
can tell it from a person's, such as `acme-svc-scheduler`.

## A broker's token command replaces the login

A workload whose broker hands it short-lived tokens names the broker's command
in the file:

```toml
api = "https://acme.example.com"
token_command = ["broker", "token", "--audience", "acme"]
```

The command prints an RFC 6749 § 5.1 token response. Every request carries its
`access_token`, and the command runs again once `expires_in` lapses.

## Linux and macOS

The refresh lock is `fcntl.flock`, so the package runs on Linux and macOS.
Releases are cut only from a commit whose suite passes on both, on Python 3.11
and 3.13.

## What it deliberately does not do

It is not a general OIDC client. It has no ID token verification, no
back-channel logout, no DPoP and no mTLS-bound tokens. An API that verifies
tokens against the provider's JWKS, as pyapiauth does, needs none of them.
