"""The config-file contract ported from goclilogin: what every command reads, what login fills in, and what it writes.

`conftest.py` leaves every test on a machine with no config file, and the
`metadata` fixture is the only API any of them reaches.
"""

from __future__ import annotations

import io
import os

import pytest

from pyclilogin import ConfigRefused
from pyclilogin import Deployment
from pyclilogin import MetadataRefused
from pyclilogin import NotConfigured
from pyclilogin import Setting
from pyclilogin import Source
from pyclilogin import config_path
from pyclilogin import deployment
from pyclilogin import deployment_for_login
from pyclilogin import load_deployment
from pyclilogin import write_deployment

API = 'https://acme.example.test'
ISSUER = 'https://auth.example.test'
METADATA = f'{API}/.well-known/oauth-protected-resource'
CONFIGURED = f'api = "{API}"\nissuer = "{ISSUER}"\nclient_id = "acme-cli-desk"\n'


def load(api='', product_keys=()):
    return load_deployment('acme', api, product_keys=product_keys)


def for_login(api='', client_id=''):
    return deployment_for_login('acme', api, client_id)


class TestEveryCommandReadsTheFile:
    def test_each_value_comes_from_the_file(self, write_config):
        path = write_config(CONFIGURED)
        resolved = load()
        assert resolved.api == Setting(API, Source.FILE, str(path))
        assert resolved.issuer.value == ISSUER
        assert resolved.client_id.value == 'acme-cli-desk'

    def test_a_missing_value_names_the_login_that_fills_it_and_keeps_what_was_set(self, write_config):
        path = write_config(f'api = "{API}"\n')
        with pytest.raises(NotConfigured) as refused:
            load()
        assert str(refused.value) == f'not configured: {path} sets no issuer or client_id; run `acme auth login <url>`'
        assert refused.value.deployment.api.value == API

    def test_an_api_flag_naming_the_files_issuer_outranks_the_file(self, write_config, metadata):
        write_config(CONFIGURED)
        metadata.documents['https://other.example.test/.well-known/oauth-protected-resource'] = {
            'resource': 'https://other.example.test',
            'authorization_servers': [ISSUER],
        }
        resolved = load('https://other.example.test/')
        assert resolved.api == Setting('https://other.example.test', Source.COMMAND_LINE)

    def test_an_api_flag_trusting_another_issuer_is_refused_before_any_token_is_sent(self, write_config, metadata):
        write_config(CONFIGURED)
        metadata.documents['https://other.example.test/.well-known/oauth-protected-resource'] = {
            'resource': 'https://other.example.test',
            'authorization_servers': ['https://auth.elsewhere.test'],
        }
        with pytest.raises(MetadataRefused, match='no token is sent to it'):
            load('https://other.example.test')

    def test_an_api_flag_equal_to_the_files_asks_nothing(self, write_config, metadata):
        write_config(CONFIGURED)
        assert load(f'{API}/').api.source == Source.COMMAND_LINE
        assert metadata.asked == []


class TestAFileThatCannotBeHonored:
    def test_a_product_naming_its_keys_refuses_a_renamed_one_naming_both_spellings(self, write_config):
        write_config(f'api_base = "{API}"\n')
        with pytest.raises(ConfigRefused) as refused:
            load()
        assert 'api_base' in str(refused.value)
        assert 'known: api, client_id, issuer, token_command' in str(refused.value)

    def test_a_product_naming_no_keys_owns_every_other_key(self, write_config):
        """goclilogin's default: a key outside the login's is the product's to read and check."""
        write_config(CONFIGURED + 'theme = 3\n')
        assert load(product_keys=None).client_id.value == 'acme-cli-desk'

    def test_an_empty_value_is_refused_rather_than_read_as_absent(self, write_config):
        """Login filling it in would write a second definition, which no TOML reader accepts."""
        write_config('issuer = ""\n')
        with pytest.raises(ConfigRefused, match='empty value'):
            load()

    def test_an_api_that_is_not_a_url_names_the_file(self, write_config):
        path = write_config(CONFIGURED.replace(API, 'acme.example.test'))
        with pytest.raises(ConfigRefused, match=str(path)):
            load()


class TestLoginFillsInWhatTheFileLacks:
    def test_a_fresh_machine_takes_the_api_given_the_issuer_it_names_and_the_hostnames_client(self, metadata, monkeypatch):
        monkeypatch.setattr(deployment.socket, 'gethostname', lambda: 'Desk.example.lan')
        metadata.documents[METADATA] = {'resource': API, 'authorization_servers': [ISSUER]}
        resolved = for_login(f'{API}/')
        assert resolved.api == Setting(API, Source.COMMAND_LINE)
        assert resolved.issuer == Setting(ISSUER, Source.DISCOVERED, METADATA)
        assert resolved.client_id == Setting('acme-cli-desk', Source.HOSTNAME, 'desk')

    def test_a_document_describing_another_resource_is_refused(self, metadata):
        """RFC 9728 § 3.3: otherwise a document copied from another API picks the login server."""
        metadata.documents[METADATA] = {'resource': 'https://elsewhere.test', 'authorization_servers': [ISSUER]}
        with pytest.raises(MetadataRefused, match='3.3'):
            for_login(API)

    def test_an_api_naming_several_servers_asks_for_the_issuer_in_the_file(self, metadata):
        metadata.documents[METADATA] = {'resource': API, 'authorization_servers': [ISSUER, 'https://auth2.test']}
        with pytest.raises(MetadataRefused, match='set issuer in'):
            for_login(API)

    def test_the_files_values_are_kept_and_nothing_is_discovered(self, write_config, metadata):
        write_config(CONFIGURED)
        resolved = for_login()
        assert {setting.source for _, setting in resolved.settings()} == {Source.FILE}
        assert metadata.asked == []

    @pytest.mark.parametrize(
        'api,client_id,named',
        [('https://other.test', '', 'api'), ('', 'acme-cli-other', 'client_id')],
    )
    def test_a_typed_value_differing_from_the_files_is_refused(self, write_config, api, client_id, named):
        """Login never rewrites what the file says."""
        write_config(CONFIGURED)
        with pytest.raises(ConfigRefused, match=f'already sets {named}'):
            for_login(api, client_id)

    def test_with_no_file_and_no_url_it_names_the_login(self):
        with pytest.raises(NotConfigured, match='auth login <url>'):
            for_login()


class TestSave:
    def resolved(self, metadata):
        metadata.documents[METADATA] = {'resource': API, 'authorization_servers': [ISSUER]}
        return for_login(API, 'acme-cli-desk')

    def test_a_fresh_file_holds_the_three_lines_login_writes_in_order(self, metadata):
        """A config manager can render the same three lines, so a file written here reads as its rendering."""
        resolved = self.resolved(metadata)
        resolved.save()
        assert resolved.path.read_text() == CONFIGURED
        assert resolved.path.stat().st_mode & 0o777 == 0o644
        assert load() == Deployment(
            resolved.path,
            *(Setting(value, Source.FILE, str(resolved.path)) for value in (API, ISSUER, 'acme-cli-desk')),
        )

    def test_only_what_the_file_lacked_is_written_and_the_rest_is_kept(self, write_config, metadata):
        path = write_config(f'# mine\nissuer = "{ISSUER}"\n')
        os.chmod(path, 0o600)
        for_login(API, 'acme-cli-desk').save()
        assert path.read_text() == f'api = "{API}"\nclient_id = "acme-cli-desk"\n\n# mine\nissuer = "{ISSUER}"\n'
        assert path.stat().st_mode & 0o777 == 0o600
        assert metadata.asked == []

    def test_a_file_lacking_nothing_is_not_touched(self, write_config):
        path = write_config(CONFIGURED)
        before = path.stat().st_mtime_ns
        for_login().save()
        assert path.stat().st_mtime_ns == before

    @pytest.mark.parametrize('when', ['at login', 'at save'])
    def test_a_linked_file_is_refused_and_its_shared_source_is_never_offered_a_client_id(self, metadata, tmp_path, when):
        """A link's source may be every machine's, so a client id written there would become every machine's."""
        resolved = self.resolved(metadata)
        source = tmp_path / 'managed.toml'
        source.write_text('')
        resolved.path.parent.mkdir(parents=True)
        resolved.path.symlink_to(source)
        with pytest.raises(ConfigRefused) as refused:
            resolved.save() if when == 'at save' else for_login(API, 'acme-cli-desk')
        assert 'is a symlink' in str(refused.value)
        assert 'client_id' in str(refused.value)
        assert 'acme-cli-desk' not in str(refused.value)
        assert source.read_text() == ''

    def test_a_linked_file_lacking_nothing_is_read_and_never_written(self, tmp_path):
        source = tmp_path / 'managed.toml'
        source.write_text(CONFIGURED)
        path = config_path('acme')
        path.parent.mkdir(parents=True)
        path.symlink_to(source)
        for_login().save()
        assert source.read_text() == CONFIGURED


def test_write_deployment_aligns_each_value_and_says_where_it_came_from(metadata):
    metadata.documents[METADATA] = {'resource': API, 'authorization_servers': [ISSUER]}
    out = io.StringIO()
    write_deployment(out, for_login(API, 'acme-cli-desk'))
    lines = out.getvalue().splitlines()
    assert [line.split()[0] for line in lines] == ['api', 'issuer', 'client_id', 'config']
    assert lines[1].split(maxsplit=2)[1:] == [ISSUER, f'(discovered at {METADATA})']
    assert len({line.index(value) for line, value in zip(lines, (API, ISSUER, 'acme-cli-desk'), strict=False)}) == 1
