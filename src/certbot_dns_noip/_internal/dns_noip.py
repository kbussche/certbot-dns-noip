"""DNS Authenticator for No-IP."""
import logging
from typing import Any
from typing import Callable
from typing import List
from typing import Optional

import requests

from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins.dns_common import CredentialsConfiguration

logger = logging.getLogger(__name__)

NOIP_API_BASE = "https://api.noip.com/v1"

# Hard cap on every HTTP call so a hung or unresponsive API endpoint cannot
# stall certbot indefinitely (connect timeout, read timeout).
HTTP_TIMEOUT = (10, 30)


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for No-IP

    This Authenticator uses the No-IP API to fulfill a dns-01 challenge.
    """

    description = ('Obtain certificates using a DNS TXT record (if you are '
                   'using No-IP for DNS).')
    ttl = 30

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: Optional[CredentialsConfiguration] = None

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 30) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add('credentials', help='No-IP credentials INI file.')

    def more_info(self) -> str:
        return ('This plugin configures a DNS TXT record to respond to a dns-01 challenge using '
                'the No-IP API.')

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            'credentials',
            'No-IP credentials INI file',
            {
                'api_key': 'API key for No-IP account'
            }
        )

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_noip_client().add_txt_record(domain, validation_name, validation, self.ttl)

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_noip_client().del_txt_record(domain, validation_name, validation)

    def _get_noip_client(self) -> '_NoIPClient':
        if not self.credentials:  # pragma: no cover
            raise errors.Error("Plugin has not been prepared.")
        return _NoIPClient(self.credentials.conf('api_key'))


class _NoIPClient:
    """Encapsulates all communication with the No-IP API."""

    def __init__(self, api_key: str) -> None:
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
        })
        # TLS verification is on by default in requests; assert it explicitly so an
        # environment/config change can never silently disable it for API traffic that
        # carries the account API key.
        self.session.verify = True
        # Apply a default timeout to every request issued through this session so a
        # single unresponsive endpoint cannot hang the whole certificate run.
        _orig_request = self.session.request

        def _request_with_timeout(method: str, url: str, **kwargs: Any) -> requests.Response:
            kwargs.setdefault('timeout', HTTP_TIMEOUT)
            return _orig_request(method, url, **kwargs)

        self.session.request = _request_with_timeout  # type: ignore[method-assign]

    def add_txt_record(self, domain_name: str, record_name: str, record_content: str,
                       record_ttl: int) -> None:
        """
        Add a TXT record using the supplied information.

        If a TXT rrset already exists for the name (e.g., a wildcard + apex pair), the new value
        is merged into the existing rrset via the replace-rdata endpoint rather than creating a
        duplicate name.

        :param str domain_name: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (seconds).
        :raises certbot.errors.PluginError: if an error occurs communicating with the No-IP API.
        """
        zone_name = self._find_zone(domain_name)
        relative_name = self._compute_record_name(zone_name, record_name)
        existing = self._get_txt_rdata(zone_name, relative_name)

        if existing is None:
            try:
                # Step 1: create the DNS name entry
                self.session.post(
                    f'{NOIP_API_BASE}/dns/records/{zone_name}',
                    json={'name': relative_name},
                ).raise_for_status()
                # Step 2: set the TXT rdata on the new name
                self.session.put(
                    f'{NOIP_API_BASE}/dns/records/{zone_name}/{relative_name}/rrsets/TXT/rdata',
                    json=[{'value': record_content}],
                ).raise_for_status()
                logger.debug('Successfully added TXT record %s in zone %s',
                             relative_name, zone_name)
            except requests.RequestException as e:
                raise errors.PluginError(
                    f'Error adding TXT record using the No-IP API: {e}'
                )
        else:
            if record_content in existing:
                logger.debug('TXT record with this content already exists; skipping add.')
                return
            self._replace_txt_rdata(zone_name, relative_name, existing + [record_content])

    def del_txt_record(self, domain_name: str, record_name: str, record_content: str) -> None:
        """
        Delete a TXT record using the supplied information.

        Only the matching value is removed. If other TXT values exist alongside the one being
        removed, they are preserved via the replace-rdata endpoint.

        Failures are logged, but not raised.

        :param str domain_name: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        """
        try:
            zone_name = self._find_zone(domain_name)
        except errors.PluginError as e:
            logger.debug('Error finding zone using the No-IP API: %s', e)
            return

        relative_name = self._compute_record_name(zone_name, record_name)
        existing = self._get_txt_rdata(zone_name, relative_name)

        if existing is None:
            logger.debug('TXT record %s not found; nothing to delete.', relative_name)
            return

        if record_content not in existing:
            logger.debug('TXT record with content %r not found; nothing to delete.',
                         record_content)
            return

        remaining = [v for v in existing if v != record_content]

        if not remaining:
            try:
                logger.debug('Removing TXT name %s from zone %s', relative_name, zone_name)
                self.session.delete(
                    f'{NOIP_API_BASE}/dns/records/{zone_name}/{relative_name}'
                ).raise_for_status()
            except requests.RequestException as e:
                logger.warning('Error deleting TXT record %s using the No-IP API: %s',
                               relative_name, e)
        else:
            try:
                self._replace_txt_rdata(zone_name, relative_name, remaining)
            except errors.PluginError as e:
                logger.warning('Error updating TXT record %s using the No-IP API: %s',
                               relative_name, e)

    def _replace_txt_rdata(self, zone_name: str, relative_name: str, values: List[str]) -> None:
        """
        Replace the full TXT rdata set for a name.

        PUT /v1/dns/records/{zone_name}/{name}/rrsets/TXT/rdata

        :raises certbot.errors.PluginError: if the API request fails.
        """
        try:
            self.session.put(
                f'{NOIP_API_BASE}/dns/records/{zone_name}/{relative_name}/rrsets/TXT/rdata',
                json=[{'value': v} for v in values],
            ).raise_for_status()
            logger.debug('Successfully replaced TXT rdata for %s in zone %s',
                         relative_name, zone_name)
        except requests.RequestException as e:
            raise errors.PluginError(
                f'Error replacing TXT rdata using the No-IP API: {e}'
            )

    def _get_txt_rdata(self, zone_name: str, relative_name: str) -> Optional[List[str]]:
        """
        Return the current list of TXT rdata values for a name, or None if the name does not
        exist or has no TXT rrset.

        GET /v1/dns/records/{zone_name}/{name}/rrsets
        """
        try:
            response = self.session.get(
                f'{NOIP_API_BASE}/dns/records/{zone_name}/{relative_name}/rrsets'
            )
            if response.status_code == 404:
                return None
            response.raise_for_status()
        except requests.RequestException as e:
            logger.debug('Error fetching rrsets for %s: %s', relative_name, e)
            return None

        values: List[str] = [
            rd['value']
            for rrset in response.json().get('data', [])
            if rrset.get('dns_type') == 'TXT'
            for rd in rrset.get('rdata', [])
            if rd.get('value') is not None
        ]
        return values if values else None

    def _find_zone(self, domain_name: str) -> str:
        """
        Find the No-IP zone name for a given domain name.

        GET /v1/dns/zones

        :raises certbot.errors.PluginError: if no matching zone is found or auth fails.
        """
        domain_name_guesses = dns_common.base_domain_name_guesses(domain_name)

        try:
            response = self.session.get(f'{NOIP_API_BASE}/dns/zones')
            if response.status_code == 401:
                raise errors.PluginError(
                    'Error retrieving zones using the No-IP API: authentication failed. '
                    'Did you provide a valid API key?'
                )
            response.raise_for_status()
            zone_names = {z['name'] for z in response.json().get('data', [])}
        except errors.PluginError:
            raise
        except requests.RequestException as e:
            raise errors.PluginError(f'Error retrieving zones using the No-IP API: {e}')

        for guess in domain_name_guesses:
            if guess in zone_names:
                logger.debug('Found zone for %s using name %s', domain_name, guess)
                return guess

        raise errors.PluginError(
            f'Unable to determine zone for {domain_name} using names: {domain_name_guesses}.'
        )

    @staticmethod
    def _compute_record_name(zone_name: str, full_record_name: str) -> str:
        # No-IP expects the record name relative to the zone (no trailing zone suffix).
        return full_record_name.rpartition('.' + zone_name)[0]
