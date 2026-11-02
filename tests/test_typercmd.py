"""`acme auth`: what each verb prints, how it exits, what login writes, and when it opens a browser.

A config manager can probe a CLI with `auth status` and read only the exit code,
so logged out has to exit 1 and logged in 0, with no network call either way.
"""

from __future__ import annotations

import datetime as dt
import json
from contextvars import ContextVar
from types import SimpleNamespace
from urllib.parse import parse_qs

import httpx2
import pytest
import typer
from typer.testing import CliRunner

from pyclilogin import Token
from pyclilogin import deployment
from pyclilogin import typercmd
from pyclilogin.typercmd import add_auth_commands

runner = CliRunner()

API = 'https://acme.example.test'
ISSUER = 'https://auth.example.test'
TOKEN_URL = f'{ISSUER}/api/oidc/token'
SERVICE = 'acme-svc-scheduler'
CONFIGURED = f'api = "{API}"\nissuer = "{ISSUER}"\nclient_id = "acme-cli-test"\n'


@pytest.fixture
def app(product):
    api_flag: ContextVar[str] = ContextVar('api_flag', default='')
    app = typer.Typer()

    @app.callback()
    def root(api: str = typer.Option('', '--api')):
        api_flag.set(api)

    add_auth_commands(app, product, api_flag=api_flag.get)
    return app


@pytest.fixture
def configured(write_config):
    return write_config(CONFIGURED)


def logged_in(product, expiry, client_id='acme-cli-test'):
    product.store().save(client_id, Token('at', 'rt', expiry=expiry))


@pytest.fixture
def approving(monkeypatch, product):
    """A provider that approves the device grant at once, recording which issuer and client it was built for."""
    built = []

    class Approving:
        def __init__(self, resolved):
            built.append((resolved.issuer.value, resolved.client_id.value))

        def login(self, show):
            print('GRANT STARTS', file=typercmd.sys.stderr)
            return Token('at-new', 'rt-new', expiry=dt.datetime(2099, 1, 1, tzinfo=dt.UTC))

    monkeypatch.setattr(type(product), 'provider', lambda self, resolved, scopes=None: Approving(resolved))
    return built


class TestStatus:
    def test_logged_out_leads_with_the_verdict_then_where_it_is_pointed(self, app, configured):
        result = runner.invoke(app, ['auth', 'status'])
        assert result.exit_code == 1
        first, *rows = result.stdout.splitlines()
        assert first == 'Not logged in as acme-cli-test. Run `acme auth login` to authenticate.'
        assert [row.split()[:2] for row in rows] == [
            ['api', API],
            ['issuer', ISSUER],
            ['client_id', 'acme-cli-test'],
            ['config', str(configured)],
        ]

    def test_logged_in_exits_zero_and_says_until_when(self, app, product, configured):
        logged_in(product, dt.datetime(2099, 1, 1, tzinfo=dt.UTC))
        result = runner.invoke(app, ['auth', 'status'])
        assert result.exit_code == 0
        assert result.stdout.splitlines()[0] == 'Logged in'
        assert 'valid until 2099-01-01' in result.stdout

    def test_an_expired_token_is_still_logged_in(self, app, product, configured):
        """The refresh token outlives the access token, and the next command refreshes."""
        logged_in(product, dt.datetime(2020, 1, 1, tzinfo=dt.UTC))
        result = runner.invoke(app, ['auth', 'status', '--json'])
        report = json.loads(result.stdout)
        assert result.exit_code == 0
        assert report['logged_in'] and report['expired'] and report['configured']
        assert report['backend'] == 'OS keyring'
        assert (report['api'], report['config_file']) == (API, str(configured))

    def test_a_machine_with_no_file_names_the_login_and_exits_one(self, app):
        result = runner.invoke(app, ['auth', 'status', '--json'])
        report = json.loads(result.stdout)
        assert result.exit_code == 1
        assert not report['configured'] and not report['logged_in']
        assert runner.invoke(app, ['auth', 'status']).stdout.startswith('not configured: ')


class TestLogin:
    def test_a_fresh_machine_fills_all_three_keys_and_says_where_each_came_from(self, app, product, approving, metadata, monkeypatch):
        monkeypatch.setattr(deployment.socket, 'gethostname', lambda: 'Test.example.lan')
        metadata.documents[f'{API}/.well-known/oauth-protected-resource'] = {'resource': API, 'authorization_servers': [ISSUER]}
        result = runner.invoke(app, ['auth', 'login', API])
        assert result.exit_code == 0, result.output
        assert approving == [(ISSUER, 'acme-cli-test')]
        assert '(command line)' in result.stderr
        assert '(discovered at ' in result.stderr
        assert '(from hostname test)' in result.stderr
        assert result.stderr.index(ISSUER) < result.stderr.index('GRANT STARTS')
        assert product.config_path().read_text() == CONFIGURED
        stored, _ = product.store().load('acme-cli-test')
        assert stored.access_token == 'at-new'

    def test_a_url_and_an_api_flag_naming_different_apis_is_a_usage_error(self, app, approving):
        result = runner.invoke(app, ['--api', 'https://one.test', 'auth', 'login', 'https://two.test'])
        assert result.exit_code == 2
        assert approving == []

    def test_a_linked_file_it_would_write_is_refused_before_the_grant_starts(self, app, product, approving, metadata, tmp_path):
        """A grant approved for a file login cannot write is a login the user did for nothing."""
        metadata.documents[f'{API}/.well-known/oauth-protected-resource'] = {'resource': API, 'authorization_servers': [ISSUER]}
        managed = tmp_path / 'managed.toml'
        managed.write_text('')
        path = product.config_path()
        path.parent.mkdir(parents=True)
        path.symlink_to(managed)
        result = runner.invoke(app, ['auth', 'login', API, '--client-id', 'acme-cli-test'])
        assert result.exit_code == 1
        assert result.stderr.startswith('acme: ')
        assert 'is a symlink' in result.stderr
        assert approving == []
        assert product.keyring_backend.get_password('acme-cli', 'acme-cli-test') is None


class TestLogout:
    def test_it_forgets_the_token(self, app, product, configured):
        logged_in(product, dt.datetime(2099, 1, 1, tzinfo=dt.UTC))
        assert runner.invoke(app, ['auth', 'logout']).exit_code == 0
        assert runner.invoke(app, ['auth', 'status']).exit_code == 1

    def test_with_no_file_it_forgets_the_hostnames_client(self, app, product, monkeypatch):
        """The client login derives, so a token stored before the file existed cannot outlive the logout."""
        monkeypatch.setattr(deployment.socket, 'gethostname', lambda: 'Test')
        logged_in(product, dt.datetime(2099, 1, 1, tzinfo=dt.UTC))
        assert runner.invoke(app, ['auth', 'logout']).exit_code == 0
        assert product.keyring_backend.get_password('acme-cli', 'acme-cli-test') is None

    def test_logged_out_already_is_not_a_failure(self, app, configured):
        assert runner.invoke(app, ['auth', 'logout']).exit_code == 0


@pytest.fixture
def service(monkeypatch, product, write_config):
    """A scheduler holding the service secret, with a file naming its service client."""
    monkeypatch.setenv(product.client_secret_variable, 's3cret')
    write_config(f'api = "{API}"\nissuer = "{ISSUER}"\nclient_id = "{SERVICE}"\n')


@pytest.fixture
def wire(monkeypatch):
    """One transport answering as the identity provider, for every client the CLI builds."""
    seen = []
    answers = {'token': (200, {'access_token': 'svc-token', 'token_type': 'Bearer', 'expires_in': 300})}
    discovery = {'issuer': ISSUER, 'token_endpoint': TOKEN_URL, 'device_authorization_endpoint': f'{ISSUER}/api/oidc/device'}

    def answer(request):
        seen.append(request)
        if str(request.url) == f'{ISSUER}/.well-known/openid-configuration':
            return httpx2.Response(200, json=discovery)
        if str(request.url) == TOKEN_URL:
            status, body = answers['token']
            return httpx2.Response(status, json=body)
        return httpx2.Response(404)

    transport = httpx2.MockTransport(answer)
    real = httpx2.Client
    monkeypatch.setattr(httpx2, 'Client', lambda **kwargs: real(**{**kwargs, 'transport': transport}))
    return SimpleNamespace(answers=answers, granted=lambda: [r for r in seen if str(r.url) == TOKEN_URL])


class TestAServiceClient:
    def test_status_asks_the_provider_for_no_scope_and_reports_the_client(self, app, service, wire):
        result = runner.invoke(app, ['auth', 'status'])
        assert result.exit_code == 0
        (grant,) = wire.granted()
        assert parse_qs(grant.content.decode()) == {'grant_type': ['client_credentials']}
        assert result.stdout.startswith('Service client')
        assert SERVICE in result.stdout

    def test_status_with_a_refused_secret_says_so_and_never_suggests_a_login(self, app, service, wire):
        wire.answers['token'] = (401, {'error': 'invalid_client', 'error_description': 'bad secret'})
        result = runner.invoke(app, ['auth', 'status'])
        assert result.exit_code == 1
        assert 'refused' in result.stdout
        assert 'auth login' not in result.stdout

    def test_status_with_no_client_named_never_reports_the_persons_login(self, app, product, monkeypatch, write_config):
        monkeypatch.setenv(product.client_secret_variable, 's3cret')
        write_config(f'api = "{API}"\nissuer = "{ISSUER}"\n')
        logged_in(product, dt.datetime(2099, 1, 1, tzinfo=dt.UTC), client_id=product.default_client_id())
        result = runner.invoke(app, ['auth', 'status'])
        assert result.exit_code == 1
        assert 'Logged in' not in result.stdout
        assert 'sets no client_id' in result.stderr
        assert 'acme-svc-<machine>' in result.stderr

    def test_a_login_is_refused_since_a_service_stores_no_token(self, app, service):
        result = runner.invoke(app, ['auth', 'login'])
        assert result.exit_code == 1
        assert 'unset it to log in as a person' in result.stderr


class TestTheBrowser:
    @pytest.mark.parametrize(
        'platform,environ',
        [
            ('linux', {}),
            ('darwin', {'SSH_CONNECTION': '10.0.0.1 1 10.0.0.2 22'}),
        ],
    )
    def test_no_desktop_means_no_browser(self, platform, environ, monkeypatch):
        """With no display, `webbrowser` would hand the terminal to a console browser."""
        launched = []
        monkeypatch.setattr(typercmd.subprocess, 'Popen', lambda *args, **kwargs: launched.append(args))
        assert not typercmd.open_browser('https://auth.example.test/device', environ=environ, platform=platform)
        assert launched == []

    def test_a_desktop_launches_detached_and_silenced(self, monkeypatch):
        launched = []
        monkeypatch.setattr(typercmd.shutil, 'which', lambda name: f'/usr/bin/{name}')
        monkeypatch.setattr(typercmd.subprocess, 'Popen', lambda args, **kwargs: launched.append((args, kwargs)))
        assert typercmd.open_browser('https://auth.example.test/device', environ={'WAYLAND_DISPLAY': 'wayland-1'}, platform='linux')
        args, kwargs = launched[0]
        assert args == ['xdg-open', 'https://auth.example.test/device']
        assert kwargs['stdout'] is typercmd.subprocess.DEVNULL
        assert kwargs['stderr'] is typercmd.subprocess.DEVNULL
        assert kwargs['start_new_session']
