# pyclilogin — Claude Code instructions

A public Python library, not a CLI. There is no entry point; it ships to PyPI
and is imported by Python product CLIs, each the command-line client of one web
API.

Its users are strangers, who know it only through what it ships. Treat the
public API, the README and the docstrings as the product. A change that suits
one known consumer is not right for that reason alone.

It is the Python sibling of goclilogin, and keeps its contract: the config
file's three keys, the keychain fallback and its refusal, the serialized
refresh, the client-credentials source and the token command. A Go CLI and a
Python CLI pointed at one API must log in, store and refresh the same way. A
behavior changed here is checked against goclilogin first.

## Layout

| Path | Holds |
| --- | --- |
| `errors.py` | `LoginError` and every typed failure under it |
| `deployment.py` | The config file: `load_deployment`, `deployment_for_login` with RFC 9728 discovery, `Deployment.save`, `write_deployment` |
| `provider.py` | Discovery, the device grant, refresh and client credentials over `httpx2`, and `Token` |
| `store.py` | `TokenStore` over the keyring and the mode-600 file, and the keyring diagnosis |
| `session.py` | The refresh lock, `TokenSource`, `ServiceTokenSource`, `CommandTokenSource` |
| `product.py` | `Product`: one CLI's name, keyring service and secret variable, building the rest |
| `typercmd.py` | The typer `auth` commands. The only module importing typer |
| `testing.py` | `MemoryKeyring`, for a consumer's tests |

## Constraints that must not regress

- **The refresh holds a machine-wide lock and re-reads the store after taking
  it.** Both halves are load-bearing. The lock alone still lets a waiter replay
  its own stale token once it gets in, and the re-read alone races.
  `test_with_the_lock_one_process_refreshes_and_the_rest_use_its_token` runs
  eight processes against a provider that revokes on replay.
- **Every lock failure degrades to an unlocked refresh, never to an error.** The
  race costs one login. Blocking on a wedged holder costs the CLI.
- **The keyring downgrade stays visible, and a keyring that refuses is not one
  that is absent.** `save` returns the backend it used, and refuses where
  `diagnose` attributes the failure to a keyring that exists. A plaintext copy
  written beside a locked keychain outlives the lock. `delete` clears both
  stores.
- **A refusal is not an outage.** `TokenRefused` is a 400 or 401 with an OAuth
  error, and only a login fixes it. Every other failure is
  `ProviderUnreachable`, so a 502 from a proxy never sends anyone to log in.
- **The config file is the one source for `api`, `issuer` and `client_id`.**
  Nothing reads an environment variable for them and nothing is compiled in.
  Login fills only what the file lacks, never rewrites a value, and never writes
  through a symlink.
- **A token goes only to an API naming the file's issuer.** An `--api`
  differing from the file's is checked against its RFC 9728 metadata first.
- **The core reads one environment variable, the service secret, and only in
  `product.py`.** `ServiceTokenSource` takes the secret as an argument.
- **typer stays confined to `typercmd.py`,** installed through the `typer`
  extra, so a CLI on argparse or click never installs it. CI imports every
  other module with no extras installed.
- **The floor is Python 3.11**, which `tomllib` and `enum.StrEnum` need. CI
  tests it.
- **Errors are typed.** A new failure gets a class in `errors.py` under
  `LoginError`, and its message names what fixes it.

## Why the command layer ships here when goclilogin's does not

goclilogin ships no command layer, because its Go consumers' `auth` commands had
already diverged before the core was extracted. The Python commands had one
copy when this package was cut, so shipping them keeps a second CLI from
starting a divergent copy. `add_auth_commands` takes what differs between CLIs
as arguments: the `Product`, the root `--api` reader, the group's name and its
help panel.
