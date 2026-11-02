"""A ready-made `auth` command group for CLIs built with typer: login, logout, token and status.

A separate module, installed with the `typer` extra, so importing pyclilogin
imposes no CLI framework on a project using argparse, click or anything else:

    uv add "pyclilogin[typer]"

    from pyclilogin import Product
    from pyclilogin.typercmd import add_auth_commands

    product = Product(name='acme', keyring_service='acme-cli')
    add_auth_commands(app, product, api_flag=lambda: API_FLAG.get())

`api_flag` reads the CLI's root `--api` option for the command running now,
where the CLI has one. It outranks the config file's `api`.

## What each verb answers

- **`auth login [URL]`** fills in whatever the config file lacks, prints each
  value with where it came from before the device grant starts, and writes them
  once the grant succeeds. It opens a desktop browser where the session has one.
- **`auth logout`** forgets this machine's token in the keychain and the file.
- **`auth token`** prints an access token for calling the API directly.
- **`auth status`** answers from the config file and the stored token alone,
  with no network call, and exits 1 when the file lacks a value or no token is
  stored. Its first line is the verdict, so a script reads that line alone. A
  service client stores no token, so its status asks the provider for one
  naming no scope, which proves the secret and grants nothing.

Every failure prints `<name>: <sentence>` on stderr and exits 1.

Annotations here are evaluated when each command is defined, never deferred.
The help text names the CLI, and typer resolves a deferred annotation in this
module's globals, where the CLI's name is not.
"""

import contextlib
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from typing import Annotated

import typer

from . import deployment
from .errors import LoginError
from .errors import NotConfigured
from .errors import NotLoggedIn
from .errors import ProviderUnreachable
from .errors import TokenRefused
from .product import Product
from .provider import DevicePrompt
from .store import Backend

EXIT_FAILED = 1

JsonFlag = Annotated[bool, typer.Option('--json', help='Output as JSON to stdout.')]


def note(message):
    """Everything that is not data goes to stderr, so a piped token or `--json` stays parseable."""
    print(message, file=sys.stderr)


def emit(document):
    json.dump(document, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write('\n')


@contextlib.contextmanager
def reported(product):
    """Turn a `LoginError` into one sentence on stderr and exit 1."""
    try:
        yield
    except LoginError as error:
        note(f'{product.name}: {error}')
        raise typer.Exit(EXIT_FAILED) from error


def write_instructions(client_id, prompt: DevicePrompt):
    """goclilogin's `WriteInstructions`, on stderr."""
    note(f'\nSigning in as {client_id}\n')
    note(f'  Code:  {prompt.user_code}')
    note(f'  Open:  {prompt.browser_url()}\n')
    if prompt.verification_uri_complete:
        note('Open that URL in any browser, on any device, and check it shows the code.')
    else:
        note('Open that URL in any browser, on any device, and enter the code.')
    note('Waiting for approval...')


def open_browser(url, environ=None, platform=sys.platform):
    """Open `url` in a desktop browser where this session has one, and say nothing.

    Not `webbrowser`. With no display it falls back to a console browser, which
    takes over the terminal the code is printed in. Its launcher also inherits
    this process's streams, so whatever the browser logs on startup lands between
    the code and the URL being read off the screen.

    Over SSH there is no desktop here, and the printed URL is the route.
    """
    environ = os.environ if environ is None else environ
    if platform == 'darwin':
        command = None if environ.get('SSH_CONNECTION') else 'open'
    else:
        command = 'xdg-open' if (environ.get('DISPLAY') or environ.get('WAYLAND_DISPLAY')) else None
    if command is None or shutil.which(command) is None:
        return False
    subprocess.Popen(
        [command, url],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    return True


def show_prompt_for(client_id):
    def show(prompt):
        write_instructions(client_id, prompt)
        open_browser(prompt.browser_url())

    return show


def add_auth_commands(
    app: typer.Typer,
    product: Product,
    *,
    api_flag: Callable[[], str] = lambda: '',
    name: str = 'auth',
    rich_help_panel: str | None = None,
) -> typer.Typer:
    """Register `<name> auth login|logout|token|status` on an existing typer app, and return the group."""
    cli = product.name
    auth = typer.Typer(
        name=name,
        no_args_is_help=True,
        help=(
            f'Log this machine in to the {cli} API. Approve the code in a browser on any device, so it works over SSH too.\n\n'
            f'Where the CLI is pointed comes from one config file. `{cli} {name} status` prints its path and its api, '
            f'issuer and client_id, and `{cli} {name} login <url>` fills in whatever it lacks.'
        ),
        context_settings={'help_option_names': ['-h', '--help']},
    )

    def refuse_as_service(verb):
        """Stop a login or a logout where the secret makes this machine a service client, which stores no token."""
        if product.is_service():
            raise LoginError(
                f'${product.client_secret_variable} is set, so {cli} authenticates as a service client and '
                f'has no login to {verb}; unset it to {verb} as a person'
            )

    @auth.command('login', rich_help_panel='Changing')
    def login(
        url: Annotated[
            str,
            typer.Argument(help=f"The {cli} API to log in to. Omit it to log in to the config file's api.", show_default=False),
        ] = '',
        client_id: Annotated[
            str,
            typer.Option(
                '--client-id', help=f'Log in as this client when the config file names none. Default: {cli}-cli-<short hostname>.'
            ),
        ] = '',
    ):
        """Log in by approving a code in a browser, filling in whatever the config file lacks.

        api comes from URL, the issuer from the API's RFC 9728 metadata, and the
        client id from --client-id or this machine's short hostname. Each is printed
        with where it came from before the login starts, and written to the file
        once it succeeds. A value already in the file is never rewritten.
        """
        flag = api_flag()
        if url and flag and url != flag:
            raise typer.BadParameter(f'--api {flag} and the url {url} name different APIs; give one', param_hint="'URL' and '--api'")
        with reported(product):
            refuse_as_service('log in')
            resolved = product.for_login(url or flag, client_id)
            note('Logging in to:')
            deployment.write_deployment(sys.stderr, resolved)

            client = resolved.client_id.value
            store = product.store()
            token = product.provider(resolved).login(show_prompt_for(client))
            backend = store.save(client, token)
            if backend == Backend.FILE:
                note(f'\nThis host has no OS keyring, so the token is in {store.file_path}, readable by this user alone.')
            try:
                resolved.save()
            except LoginError as error:
                raise LoginError(f'logged in as {client}, but the config file was not written: {error}') from error
            note(f'\nLogged in as {client}')

    @auth.command('logout', rich_help_panel='Changing')
    def logout():
        """Log out, forgetting this machine's token."""
        with reported(product):
            refuse_as_service('log out')
            # Only the client id finds the token, so a file lacking the other two keys
            # still logs out. A file naming no client falls back to the hostname's, the
            # client login derives, so its token cannot outlive the logout.
            try:
                loaded = product.load(api_flag())
            except NotConfigured as unconfigured:
                loaded = unconfigured.deployment
            if loaded.hands_tokens():
                raise LoginError(f'{loaded.path} sets token_command, so {cli} is handed its tokens and stores none to remove')
            client = loaded.client_id.value or product.default_client_id()
            try:
                product.store().delete(client)
            except NotLoggedIn:
                note('Not logged in — there is nothing to remove.')
                return
            note(f'Logged out ({client}).')

    @auth.command('token', rich_help_panel='Reading')
    def token():
        """Print an access token for calling the API directly. Exits 1 when logged out."""
        with reported(product):
            print(product.token_source(product.load(api_flag())).token().access_token)

    @auth.command('status', rich_help_panel='Reading')
    def status(as_json: JsonFlag = False):
        """Show where the CLI is pointed and whether it is logged in.

        Prints the api, issuer and client_id, where each came from, and the config
        file's path. Exits 1 when the file lacks a value or no token is stored.
        """
        with reported(product):
            if product.is_service():
                service_status(product, as_json, product.load(api_flag()))
                return
            try:
                resolved, unconfigured = product.load(api_flag()), None
            except NotConfigured as error:
                resolved, unconfigured = error.deployment, error
            if unconfigured is None and resolved.hands_tokens():
                handed_status(product, as_json, resolved)
                return
            person_status(product, as_json, resolved, unconfigured)

    app.add_typer(auth, name=name, rich_help_panel=rich_help_panel)
    return auth


def person_status(product, as_json, resolved, unconfigured):
    """A person's login, from the config file and the store alone. Exits 1 when either lacks something."""
    report = {
        'logged_in': False,
        'configured': unconfigured is None,
        'config_file': str(resolved.path),
        'api': resolved.api.value,
        'client_id': resolved.client_id.value,
        'issuer': resolved.issuer.value,
        'expires_at': None,
        'expired': False,
        'backend': None,
    }
    if report['client_id']:
        try:
            stored, backend = product.store().load(report['client_id'])
        except NotLoggedIn as error:
            if error.keyring_reason:
                note(f'The OS keyring could not be read: {error.keyring_reason}')
        else:
            report['logged_in'] = True
            report['backend'] = str(backend)
            if stored.expiry is not None:
                report['expires_at'] = stored.expiry.isoformat()
                report['expired'] = stored.expiry <= dt.datetime.now(dt.UTC)

    if as_json:
        emit(report)
    else:
        print_status(product, report, resolved, unconfigured)
    if not (report['configured'] and report['logged_in']):
        raise typer.Exit(EXIT_FAILED)


def print_status(product, report, resolved, unconfigured):
    """The verdict on a line of its own, then where the CLI is pointed and what the token is."""
    out = sys.stdout
    if unconfigured is not None:
        print(unconfigured, file=out)
    elif not report['logged_in']:
        print(f'Not logged in as {report["client_id"]}. Run `{product.login_command()}` to authenticate.', file=out)
    else:
        print('Logged in', file=out)
    deployment.write_deployment(out, resolved)
    if report['expires_at'] and report['expired']:
        print(f'{deployment.label("token")}expired at {report["expires_at"]}, and is refreshed on the next command', file=out)
    elif report['expires_at']:
        print(f'{deployment.label("token")}valid until {report["expires_at"]}', file=out)
    if report['backend'] == Backend.FILE:
        print(f'{deployment.label("stored")}in a file, since this host has no OS keyring', file=out)


def service_status(product, as_json, resolved):
    """Whether the provider accepts the service client's secret. Exits 1 when it does not."""
    provider = product.provider(resolved, scopes=())
    report = {
        'service': True,
        'config_file': str(resolved.path),
        'api': resolved.api.value,
        'client_id': provider.client_id,
        'issuer': provider.issuer,
        'secret_from': f'${product.client_secret_variable}',
        'accepted': False,
        'answer': '',
    }
    try:
        provider.client_credentials(product.client_secret())
    except TokenRefused as error:
        detail = f' ({error.description})' if error.description else ''
        report['answer'] = f'Service client refused by {provider.issuer}: {error.error}{detail}. {product.service_repair()}'
    except ProviderUnreachable as error:
        report['answer'] = f'Service client configured, but {provider.issuer} could not be reached: {error}'
    else:
        report['accepted'] = True

    if as_json:
        emit(report)
    else:
        print('Service client (client credentials)' if report['accepted'] else report['answer'])
        deployment.write_deployment(sys.stdout, resolved)
        if report['accepted']:
            print(f'{deployment.label("secret")}{report["secret_from"]}, which the provider accepts')
    if not report['accepted']:
        raise typer.Exit(EXIT_FAILED)


def handed_status(product, as_json, resolved):
    """Whether the file's token_command hands a token now. Exits 1 when it does not."""
    report = {
        'type': 'external_account',
        'config_file': str(resolved.path),
        'api': resolved.api.value,
        'client_id': resolved.client_id.value,
        'token_command': list(resolved.token_command),
        'handed': False,
        'expires_at': None,
        'answer': '',
    }
    try:
        handed = product.token_source(resolved).token()
    except LoginError as error:
        report['answer'] = str(error)
    else:
        report['handed'] = True
        report['expires_at'] = handed.expiry.isoformat() if handed.expiry else None

    if as_json:
        emit(report)
    else:
        print('Handed a token by token_command' if report['handed'] else report['answer'])
        deployment.write_deployment(sys.stdout, resolved)
        if report['expires_at']:
            print(f'{deployment.label("token")}valid until {report["expires_at"]}')
    if not report['handed']:
        raise typer.Exit(EXIT_FAILED)
