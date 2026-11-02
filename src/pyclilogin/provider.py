"""The OAuth exchanges with the identity provider: discovery, the device grant, refresh, client credentials.

goclilogin takes these from `golang.org/x/oauth2`. Each is one form POST and a
JSON answer, per RFC 8628 and RFC 6749, so they are written out here over
`httpx2` rather than pulling in an OAuth library for four requests.

## A refusal is not an outage

`TokenRefused` is the provider answering 400 or 401 with an OAuth error. Only an
interactive login fixes it. `ProviderUnreachable` is everything else: no route,
a timeout, a 5xx from the proxy in front. A 502 from a CDN therefore never tells
anyone to log in again.
"""

from __future__ import annotations

import dataclasses as dc
import datetime as dt
import time
from collections.abc import Callable
from dataclasses import dataclass
from dataclasses import field

import httpx2

from .errors import LoginAbandoned
from .errors import ProviderUnreachable
from .errors import TokenRefused

# What a CLI needs from a standard OIDC provider. offline_access yields the
# refresh token. A product's own authorization scope is added by the product.
DEFAULT_SCOPES = ('openid', 'profile', 'offline_access')
DISCOVERY_PATH = '/.well-known/openid-configuration'
DEVICE_CODE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code'
TIMEOUT_SECONDS = 15.0

# RFC 8628 § 3.5: the interval when the provider names none, and what a
# `slow_down` adds to it.
DEFAULT_POLL_SECONDS = 5
SLOW_DOWN_SECONDS = 5

# oauth2's expiryDelta. An access token this close to its expiry is treated as
# expired, so it is not sent only to lapse in transit.
EARLY_EXPIRY = dt.timedelta(seconds=10)

# A CDN in front of a provider can refuse a client that names none. A product
# names itself instead through `Product.user_agent`.
USER_AGENT = 'pyclilogin (+https://github.com/datapointchris/pyclilogin)'


@dataclass(frozen=True)
class Token:
    """One grant's tokens. `expiry` is None where the provider sent no `expires_in`."""

    access_token: str
    refresh_token: str = ''
    token_type: str = 'Bearer'
    expiry: dt.datetime | None = None
    id_token: str = ''

    def valid(self, now=None):
        """Usable as a bearer now: present, and not within `EARLY_EXPIRY` of lapsing."""
        if not self.access_token:
            return False
        if self.expiry is None:
            return True
        now = now or dt.datetime.now(dt.UTC)
        return self.expiry - EARLY_EXPIRY > now

    def to_json(self):
        return {
            'access_token': self.access_token,
            'refresh_token': self.refresh_token,
            'token_type': self.token_type,
            'expiry': self.expiry.isoformat() if self.expiry else None,
            'id_token': self.id_token,
        }

    @classmethod
    def from_json(cls, data):
        expiry = data.get('expiry')
        return cls(
            access_token=data.get('access_token', ''),
            refresh_token=data.get('refresh_token', ''),
            token_type=data.get('token_type', 'Bearer'),
            expiry=dt.datetime.fromisoformat(expiry) if expiry else None,
            id_token=data.get('id_token', ''),
        )


@dataclass(frozen=True)
class Endpoints:
    """The part of the discovery document a device-grant CLI needs."""

    issuer: str
    token: str
    device_authorization: str


@dataclass(frozen=True)
class DevicePrompt:
    """What the user acts on: a code, and a page to approve it on."""

    user_code: str
    verification_uri: str
    verification_uri_complete: str = ''

    def browser_url(self):
        """The complete URL where the provider sent one, the bare one otherwise.

        A provider can take a browser that is already signed in straight past
        the bare page, which then has nowhere to type the code.
        """
        return self.verification_uri_complete or self.verification_uri


@dataclass
class Provider:
    """One identity provider, asked through one client.

    `sleep` and `clock` are parameters so the device-grant poll can be driven
    from a test without waiting out its interval.
    """

    issuer: str
    client_id: str
    scopes: tuple[str, ...] = DEFAULT_SCOPES
    client: httpx2.Client | None = None
    user_agent: str = USER_AGENT
    sleep: Callable[[float], None] = time.sleep
    clock: Callable[[], float] = time.monotonic
    _endpoints: Endpoints | None = field(default=None, init=False, repr=False)

    def _http(self):
        if self.client is None:
            self.client = httpx2.Client(timeout=TIMEOUT_SECONDS, headers={'User-Agent': self.user_agent}, follow_redirects=False)
        return self.client

    def endpoints(self):
        """The discovery document's endpoints, fetched once per Provider."""
        if self._endpoints is not None:
            return self._endpoints
        url = self.issuer.rstrip('/') + DISCOVERY_PATH
        try:
            response = self._http().get(url)
        except httpx2.HTTPError as error:
            raise ProviderUnreachable(f'cannot reach the identity provider at {url}: {error}') from error
        if response.status_code != 200:
            raise ProviderUnreachable(f'identity provider discovery at {url} answered HTTP {response.status_code}')
        document = response.json()
        if document.get('issuer') != self.issuer.rstrip('/'):
            raise ProviderUnreachable(f'{url} describes {document.get("issuer")!r}, not {self.issuer!r}')
        device = document.get('device_authorization_endpoint')
        if not device:
            raise ProviderUnreachable(f'{self.issuer} advertises no device_authorization_endpoint')
        self._endpoints = Endpoints(issuer=document['issuer'], token=document['token_endpoint'], device_authorization=device)
        return self._endpoints

    def _post(self, url, form):
        try:
            return self._http().post(url, data={**form, 'client_id': self.client_id})
        except httpx2.HTTPError as error:
            raise ProviderUnreachable(f'cannot reach {url}: {error}') from error

    def login(self, show):
        """Run the device grant: ask for a code, hand it to `show`, poll until approved."""
        endpoints = self.endpoints()
        response = self._post(endpoints.device_authorization, {'scope': ' '.join(self.scopes)})
        if response.status_code != 200:
            raise refusal(response)
        grant = response.json()
        show(
            DevicePrompt(
                user_code=grant['user_code'],
                verification_uri=grant['verification_uri'],
                verification_uri_complete=grant.get('verification_uri_complete', ''),
            )
        )
        return self._poll(endpoints.token, grant)

    def _poll(self, token_url, grant):
        interval = int(grant.get('interval') or DEFAULT_POLL_SECONDS)
        deadline = self.clock() + int(grant['expires_in'])
        form = {'grant_type': DEVICE_CODE_GRANT, 'device_code': grant['device_code']}
        while self.clock() < deadline:
            self.sleep(interval)
            response = self._post(token_url, form)
            if response.status_code == 200:
                return token_from_response(response.json())
            error = error_code(response)
            if error == 'authorization_pending':
                continue
            if error == 'slow_down':
                interval += SLOW_DOWN_SECONDS
                continue
            if error in ('access_denied', 'expired_token'):
                raise LoginAbandoned(f'the login was not approved: {error}')
            raise refusal(response)
        raise LoginAbandoned('the code expired before anything approved it')

    def client_credentials(self, secret):
        """A service client's token, per RFC 6749 § 4.4, carrying exactly `scopes`.

        The client authenticates with HTTP Basic, which § 2.3.1 requires every
        provider to support. A provider that grants only the scopes a request
        names, as Authelia does, answers a request naming none with a token
        that proves the secret and grants nothing. A status command asks for
        exactly that.
        """
        url = self.endpoints().token
        form = {'grant_type': 'client_credentials'}
        if self.scopes:
            form['scope'] = ' '.join(self.scopes)
        try:
            response = self._http().post(url, data=form, auth=(self.client_id, secret))
        except httpx2.HTTPError as error:
            raise ProviderUnreachable(f'cannot reach {url}: {error}') from error
        if response.status_code != 200:
            raise refusal(response)
        return token_from_response(response.json())

    def refresh(self, token):
        """Exchange the refresh token for a new pair.

        A provider that sends no new refresh token leaves the old one in force,
        per RFC 6749 § 6, so it is carried over rather than dropped.
        """
        if not token.refresh_token:
            raise TokenRefused('no_refresh_token', 'the stored grant holds no refresh token')
        response = self._post(self.endpoints().token, {'grant_type': 'refresh_token', 'refresh_token': token.refresh_token})
        if response.status_code != 200:
            raise refusal(response)
        refreshed = token_from_response(response.json())
        if not refreshed.refresh_token:
            refreshed = dc.replace(refreshed, refresh_token=token.refresh_token)
        return refreshed


def token_from_response(body, now=None):
    now = now or dt.datetime.now(dt.UTC)
    expires_in = body.get('expires_in')
    return Token(
        access_token=body['access_token'],
        refresh_token=body.get('refresh_token', ''),
        token_type=body.get('token_type', 'Bearer'),
        expiry=now + dt.timedelta(seconds=int(expires_in)) if expires_in else None,
        id_token=body.get('id_token', ''),
    )


def error_code(response):
    try:
        return response.json().get('error', '')
    except ValueError:
        return ''


def refusal(response):
    """A non-200 from the provider, as the refusal or the outage it is."""
    if response.status_code in (400, 401):
        try:
            body = response.json()
        except ValueError:
            body = {}
        return TokenRefused(body.get('error') or f'HTTP {response.status_code}', body.get('error_description', ''))
    return ProviderUnreachable(f'the identity provider answered HTTP {response.status_code}')
