"""The OAuth exchanges, against a provider played by a mock transport.

The poll's sleep and clock are injected, so the device grant runs its whole
pending → slow_down → approved sequence without waiting out an interval.
"""

from __future__ import annotations

import base64
import datetime as dt
import urllib.parse

import httpx2
import pytest

from pyclilogin import LoginAbandoned
from pyclilogin import Provider
from pyclilogin import ProviderUnreachable
from pyclilogin import Token
from pyclilogin import TokenRefused
from pyclilogin.provider import DEVICE_CODE_GRANT

ISSUER = 'https://auth.example.test'
CLIENT = 'acme-cli-test'
DISCOVERY = {
    'issuer': ISSUER,
    'token_endpoint': f'{ISSUER}/api/oidc/token',
    'device_authorization_endpoint': f'{ISSUER}/api/oidc/device-authorization',
}
ISSUED = {'access_token': 'at-1', 'refresh_token': 'rt-1', 'token_type': 'Bearer', 'expires_in': 3600}


def form(request):
    return dict(urllib.parse.parse_qsl(request.content.decode()))


class PlayedProvider:
    """Answers discovery, then each token request from a script of responses."""

    def __init__(self, token_answers, discovery=DISCOVERY):
        self.token_answers = list(token_answers)
        self.discovery = discovery
        self.token_requests = []
        self.token_authorizations = []
        self.device_requests = []

    def __call__(self, request):
        if request.url.path.endswith('/.well-known/openid-configuration'):
            return httpx2.Response(200, json=self.discovery)
        if request.url.path.endswith('/device-authorization'):
            self.device_requests.append(form(request))
            return httpx2.Response(
                200,
                json={
                    'device_code': 'the-device-code',
                    'user_code': 'ABCD-EFGH',
                    'verification_uri': f'{ISSUER}/consent/device',
                    'verification_uri_complete': f'{ISSUER}/consent/device?user_code=ABCD-EFGH',
                    'expires_in': 600,
                    'interval': 5,
                },
            )
        self.token_requests.append(form(request))
        self.token_authorizations.append(request.headers.get('Authorization'))
        status, body = self.token_answers.pop(0)
        return httpx2.Response(status, json=body)


class Clock:
    def __init__(self):
        self.now = 0.0
        self.slept = []

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds

    def __call__(self):
        return self.now


def provider_for(played, clock=None, **fields):
    clock = clock or Clock()
    return Provider(issuer=ISSUER, client_id=CLIENT, sleep=clock.sleep, clock=clock, **fields, client=transported(played))


def transported(played):
    return httpx2.Client(transport=httpx2.MockTransport(played))


class TestTheDeviceGrant:
    def test_it_polls_through_pending_and_slows_down_when_told(self):
        clock = Clock()
        played = PlayedProvider([(400, {'error': 'authorization_pending'}), (400, {'error': 'slow_down'}), (200, ISSUED)])
        token = provider_for(played, clock, scopes=('openid', 'acme.write')).login(lambda prompt: None)
        assert token.access_token == 'at-1'
        assert clock.slept == [5, 5, 10]
        assert played.device_requests == [{'scope': 'openid acme.write', 'client_id': CLIENT}]
        assert played.token_requests[0] == {'grant_type': DEVICE_CODE_GRANT, 'device_code': 'the-device-code', 'client_id': CLIENT}

    def test_the_prompt_carries_the_url_with_the_code_in_it(self):
        prompts = []
        provider_for(PlayedProvider([(200, ISSUED)])).login(prompts.append)
        assert prompts[0].browser_url().endswith('user_code=ABCD-EFGH')
        assert prompts[0].user_code == 'ABCD-EFGH'

    @pytest.mark.parametrize('error', ['access_denied', 'expired_token'])
    def test_a_denied_or_expired_code_ends_the_login(self, error):
        with pytest.raises(LoginAbandoned):
            provider_for(PlayedProvider([(400, {'error': error})])).login(lambda prompt: None)

    def test_a_code_nobody_approves_ends_at_its_expiry(self):
        played = PlayedProvider([(400, {'error': 'authorization_pending'})] * 200)
        with pytest.raises(LoginAbandoned):
            provider_for(played).login(lambda prompt: None)

    def test_a_discovery_document_for_another_issuer_is_refused(self):
        played = PlayedProvider([], discovery={**DISCOVERY, 'issuer': 'https://elsewhere.test'})
        with pytest.raises(ProviderUnreachable):
            provider_for(played).login(lambda prompt: None)


class TestTheRefresh:
    def held(self, refresh_token='rt-1'):
        return Token(access_token='at-0', refresh_token=refresh_token, expiry=dt.datetime(2020, 1, 1, tzinfo=dt.UTC))

    def test_it_presents_the_held_refresh_token(self):
        played = PlayedProvider([(200, {**ISSUED, 'refresh_token': 'rt-2'})])
        refreshed = provider_for(played).refresh(self.held())
        assert played.token_requests[0] == {'grant_type': 'refresh_token', 'refresh_token': 'rt-1', 'client_id': CLIENT}
        assert refreshed.refresh_token == 'rt-2'

    def test_a_provider_sending_no_new_refresh_token_leaves_the_old_in_force(self):
        """RFC 6749 § 6: the old one stays valid, so dropping it would end the grant here."""
        answer = {key: value for key, value in ISSUED.items() if key != 'refresh_token'}
        refreshed = provider_for(PlayedProvider([(200, answer)])).refresh(self.held())
        assert refreshed.refresh_token == 'rt-1'

    def test_a_refused_refresh_is_a_refusal(self):
        played = PlayedProvider([(400, {'error': 'invalid_grant', 'error_description': 'revoked'})])
        with pytest.raises(TokenRefused) as refused:
            provider_for(played).refresh(self.held())
        assert refused.value.error == 'invalid_grant'

    def test_a_proxy_failure_is_an_outage_and_not_a_refusal(self):
        """A 502 from the proxy says nothing about the grant, so it must not send anyone to log in."""
        with pytest.raises(ProviderUnreachable):
            provider_for(PlayedProvider([(502, {})])).refresh(self.held())


class TestTheClientCredentialsGrant:
    SERVICE = 'acme-svc-scheduler'

    def service(self, played, scopes=('acme.read',)):
        return Provider(issuer=ISSUER, client_id=self.SERVICE, scopes=scopes, client=transported(played))

    def test_the_client_authenticates_with_basic_and_names_exactly_its_scopes(self):
        played = PlayedProvider([(200, {'access_token': 'at-svc', 'token_type': 'Bearer', 'expires_in': 300})])
        token = self.service(played).client_credentials('s3cret')
        assert token.access_token == 'at-svc'
        assert played.token_requests == [{'grant_type': 'client_credentials', 'scope': 'acme.read'}]
        assert played.token_authorizations == ['Basic ' + base64.b64encode(f'{self.SERVICE}:s3cret'.encode()).decode()]

    def test_a_wrong_secret_is_a_refusal(self):
        played = PlayedProvider([(401, {'error': 'invalid_client'})])
        with pytest.raises(TokenRefused, match='invalid_client'):
            self.service(played).client_credentials('wrong')


def test_a_token_this_close_to_expiry_is_already_spent():
    now = dt.datetime(2026, 10, 7, tzinfo=dt.UTC)
    assert not Token('at', expiry=now + dt.timedelta(seconds=5)).valid(now)
    assert Token('at', expiry=now + dt.timedelta(minutes=5)).valid(now)
    assert Token('at').valid(now)
