"""Tests for certbot_dns_noip._internal.dns_noip."""
import unittest
from unittest import mock

import requests
import requests_mock as requests_mock_lib

from certbot import errors
from certbot.plugins import dns_test_common
from certbot.tests import util as test_util

from certbot_dns_noip._internal import dns_noip

NOIP_API_BASE = dns_noip.NOIP_API_BASE

FAKE_API_KEY = "test_api_key_123"
FAKE_ZONE = "example.com"
FAKE_RECORD_NAME = "_acme-challenge"
FAKE_FULL_RECORD_NAME = f"{FAKE_RECORD_NAME}.{FAKE_ZONE}"
FAKE_VALIDATION = "some-validation-token"
FAKE_TTL = 30

ZONES_RESPONSE = {
    "data": [
        {"name": "example.com"},
        {"name": "other.com"},
    ]
}

RRSETS_RESPONSE_EMPTY = {"data": []}

RRSETS_RESPONSE_WITH_TXT = {
    "data": [
        {
            "dns_type": "TXT",
            "rdata": [
                {"value": "existing-value"},
            ],
        }
    ]
}


class AuthenticatorTest(dns_test_common.BaseAuthenticatorTest):
    """Tests for Authenticator."""

    DOMAIN = FAKE_ZONE
    DOMAIN_NOT_FOUND = "notmydomain.com"

    def setUp(self) -> None:
        from certbot_dns_noip._internal.dns_noip import Authenticator

        super().setUp()
        self.config = mock.MagicMock()
        self.auth = Authenticator(self.config, "dns-noip")
        self.mock_client = mock.MagicMock()
        self.auth._get_noip_client = mock.MagicMock(return_value=self.mock_client)

    def test_perform(self) -> None:
        self.auth._perform(FAKE_ZONE, FAKE_FULL_RECORD_NAME, FAKE_VALIDATION)
        self.mock_client.add_txt_record.assert_called_once_with(
            FAKE_ZONE, FAKE_FULL_RECORD_NAME, FAKE_VALIDATION, self.auth.ttl
        )

    def test_cleanup(self) -> None:
        self.auth._cleanup(FAKE_ZONE, FAKE_FULL_RECORD_NAME, FAKE_VALIDATION)
        self.mock_client.del_txt_record.assert_called_once_with(
            FAKE_ZONE, FAKE_FULL_RECORD_NAME, FAKE_VALIDATION
        )


class NoIPClientTest(unittest.TestCase):
    """Tests for _NoIPClient."""

    def setUp(self) -> None:
        self.client = dns_noip._NoIPClient(FAKE_API_KEY)

    # -------------------------------------------------------------------------
    # _find_zone
    # -------------------------------------------------------------------------

    def test_find_zone_success(self) -> None:
        with requests_mock_lib.Mocker() as m:
            m.get(f'{NOIP_API_BASE}/dns/zones', json=ZONES_RESPONSE)
            zone = self.client._find_zone(FAKE_ZONE)
        self.assertEqual(zone, FAKE_ZONE)

    def test_find_zone_subdomain(self) -> None:
        with requests_mock_lib.Mocker() as m:
            m.get(f'{NOIP_API_BASE}/dns/zones', json=ZONES_RESPONSE)
            zone = self.client._find_zone(f'sub.{FAKE_ZONE}')
        self.assertEqual(zone, FAKE_ZONE)

    def test_find_zone_not_found(self) -> None:
        with requests_mock_lib.Mocker() as m:
            m.get(f'{NOIP_API_BASE}/dns/zones', json=ZONES_RESPONSE)
            with self.assertRaises(errors.PluginError) as ctx:
                self.client._find_zone('notmydomain.com')
        self.assertIn('Unable to determine zone', str(ctx.exception))

    def test_find_zone_auth_failure(self) -> None:
        with requests_mock_lib.Mocker() as m:
            m.get(f'{NOIP_API_BASE}/dns/zones', status_code=401)
            with self.assertRaises(errors.PluginError) as ctx:
                self.client._find_zone(FAKE_ZONE)
        self.assertIn('authentication failed', str(ctx.exception))

    def test_find_zone_network_error(self) -> None:
        with requests_mock_lib.Mocker() as m:
            m.get(f'{NOIP_API_BASE}/dns/zones', exc=requests.ConnectionError)
            with self.assertRaises(errors.PluginError):
                self.client._find_zone(FAKE_ZONE)

    # -------------------------------------------------------------------------
    # _compute_record_name
    # -------------------------------------------------------------------------

    def test_compute_record_name(self) -> None:
        result = dns_noip._NoIPClient._compute_record_name(
            FAKE_ZONE, FAKE_FULL_RECORD_NAME
        )
        self.assertEqual(result, FAKE_RECORD_NAME)

    # -------------------------------------------------------------------------
    # _get_txt_rdata
    # -------------------------------------------------------------------------

    def test_get_txt_rdata_not_found(self) -> None:
        with requests_mock_lib.Mocker() as m:
            m.get(
                f'{NOIP_API_BASE}/dns/records/{FAKE_ZONE}/{FAKE_RECORD_NAME}/rrsets',
                status_code=404
            )
            result = self.client._get_txt_rdata(FAKE_ZONE, FAKE_RECORD_NAME)
        self.assertIsNone(result)

    def test_get_txt_rdata_empty(self) -> None:
        with requests_mock_lib.Mocker() as m:
            m.get(
                f'{NOIP_API_BASE}/dns/records/{FAKE_ZONE}/{FAKE_RECORD_NAME}/rrsets',
                json=RRSETS_RESPONSE_EMPTY
            )
            result = self.client._get_txt_rdata(FAKE_ZONE, FAKE_RECORD_NAME)
        self.assertIsNone(result)

    def test_get_txt_rdata_with_values(self) -> None:
        with requests_mock_lib.Mocker() as m:
            m.get(
                f'{NOIP_API_BASE}/dns/records/{FAKE_ZONE}/{FAKE_RECORD_NAME}/rrsets',
                json=RRSETS_RESPONSE_WITH_TXT
            )
            result = self.client._get_txt_rdata(FAKE_ZONE, FAKE_RECORD_NAME)
        self.assertEqual(result, ['existing-value'])

    # -------------------------------------------------------------------------
    # add_txt_record
    # -------------------------------------------------------------------------

    def test_add_txt_record_new_name(self) -> None:
        with requests_mock_lib.Mocker() as m:
            m.get(f'{NOIP_API_BASE}/dns/zones', json=ZONES_RESPONSE)
            m.get(
                f'{NOIP_API_BASE}/dns/records/{FAKE_ZONE}/{FAKE_RECORD_NAME}/rrsets',
                status_code=404
            )
            m.post(f'{NOIP_API_BASE}/dns/records/{FAKE_ZONE}', status_code=201)
            m.put(
                f'{NOIP_API_BASE}/dns/records/{FAKE_ZONE}/{FAKE_RECORD_NAME}/rrsets/TXT/rdata',
                status_code=202
            )

            self.client.add_txt_record(FAKE_ZONE, FAKE_FULL_RECORD_NAME, FAKE_VALIDATION,
                                       FAKE_TTL)

        post_req = next(r for r in m.request_history if r.method == 'POST')
        self.assertEqual(post_req.json(), {'name': FAKE_RECORD_NAME})

        put_req = next(r for r in m.request_history if r.method == 'PUT')
        self.assertEqual(put_req.json(), [{'value': FAKE_VALIDATION}])

    def test_add_txt_record_merge_existing(self) -> None:
        with requests_mock_lib.Mocker() as m:
            m.get(f'{NOIP_API_BASE}/dns/zones', json=ZONES_RESPONSE)
            m.get(
                f'{NOIP_API_BASE}/dns/records/{FAKE_ZONE}/{FAKE_RECORD_NAME}/rrsets',
                json=RRSETS_RESPONSE_WITH_TXT
            )
            m.put(
                f'{NOIP_API_BASE}/dns/records/{FAKE_ZONE}/{FAKE_RECORD_NAME}/rrsets/TXT/rdata',
                status_code=202
            )

            self.client.add_txt_record(FAKE_ZONE, FAKE_FULL_RECORD_NAME, FAKE_VALIDATION,
                                       FAKE_TTL)

        put_req = m.request_history[-1]
        self.assertEqual(put_req.method, 'PUT')
        values = [r['value'] for r in put_req.json()]
        self.assertIn('existing-value', values)
        self.assertIn(FAKE_VALIDATION, values)

    def test_add_txt_record_already_exists(self) -> None:
        existing_response = {
            "data": [{
                "dns_type": "TXT",
                "rdata": [{"value": FAKE_VALIDATION}],
            }]
        }
        with requests_mock_lib.Mocker() as m:
            m.get(f'{NOIP_API_BASE}/dns/zones', json=ZONES_RESPONSE)
            m.get(
                f'{NOIP_API_BASE}/dns/records/{FAKE_ZONE}/{FAKE_RECORD_NAME}/rrsets',
                json=existing_response
            )
            # No PUT or POST should be called
            self.client.add_txt_record(FAKE_ZONE, FAKE_FULL_RECORD_NAME, FAKE_VALIDATION,
                                       FAKE_TTL)

        methods = [r.method for r in m.request_history]
        self.assertNotIn('PUT', methods)
        self.assertNotIn('POST', methods)

    def test_add_txt_record_api_error(self) -> None:
        with requests_mock_lib.Mocker() as m:
            m.get(f'{NOIP_API_BASE}/dns/zones', json=ZONES_RESPONSE)
            m.get(
                f'{NOIP_API_BASE}/dns/records/{FAKE_ZONE}/{FAKE_RECORD_NAME}/rrsets',
                status_code=404
            )
            m.post(f'{NOIP_API_BASE}/dns/records/{FAKE_ZONE}', status_code=500)

            with self.assertRaises(errors.PluginError):
                self.client.add_txt_record(FAKE_ZONE, FAKE_FULL_RECORD_NAME, FAKE_VALIDATION,
                                           FAKE_TTL)

    # -------------------------------------------------------------------------
    # del_txt_record
    # -------------------------------------------------------------------------

    def test_del_txt_record_removes_name_when_only_value(self) -> None:
        existing_response = {
            "data": [{
                "dns_type": "TXT",
                "rdata": [{"value": FAKE_VALIDATION}],
            }]
        }
        with requests_mock_lib.Mocker() as m:
            m.get(f'{NOIP_API_BASE}/dns/zones', json=ZONES_RESPONSE)
            m.get(
                f'{NOIP_API_BASE}/dns/records/{FAKE_ZONE}/{FAKE_RECORD_NAME}/rrsets',
                json=existing_response
            )
            m.delete(
                f'{NOIP_API_BASE}/dns/records/{FAKE_ZONE}/{FAKE_RECORD_NAME}',
                status_code=200
            )
            self.client.del_txt_record(FAKE_ZONE, FAKE_FULL_RECORD_NAME, FAKE_VALIDATION)

        delete_req = m.request_history[-1]
        self.assertEqual(delete_req.method, 'DELETE')

    def test_del_txt_record_preserves_remaining_values(self) -> None:
        existing_response = {
            "data": [{
                "dns_type": "TXT",
                "rdata": [
                    {"value": "other-value"},
                    {"value": FAKE_VALIDATION},
                ],
            }]
        }
        with requests_mock_lib.Mocker() as m:
            m.get(f'{NOIP_API_BASE}/dns/zones', json=ZONES_RESPONSE)
            m.get(
                f'{NOIP_API_BASE}/dns/records/{FAKE_ZONE}/{FAKE_RECORD_NAME}/rrsets',
                json=existing_response
            )
            m.put(
                f'{NOIP_API_BASE}/dns/records/{FAKE_ZONE}/{FAKE_RECORD_NAME}/rrsets/TXT/rdata',
                status_code=202
            )
            self.client.del_txt_record(FAKE_ZONE, FAKE_FULL_RECORD_NAME, FAKE_VALIDATION)

        put_req = m.request_history[-1]
        self.assertEqual(put_req.method, 'PUT')
        values = [r['value'] for r in put_req.json()]
        self.assertIn('other-value', values)
        self.assertNotIn(FAKE_VALIDATION, values)

    def test_del_txt_record_not_found(self) -> None:
        with requests_mock_lib.Mocker() as m:
            m.get(f'{NOIP_API_BASE}/dns/zones', json=ZONES_RESPONSE)
            m.get(
                f'{NOIP_API_BASE}/dns/records/{FAKE_ZONE}/{FAKE_RECORD_NAME}/rrsets',
                status_code=404
            )
            # Should not raise
            self.client.del_txt_record(FAKE_ZONE, FAKE_FULL_RECORD_NAME, FAKE_VALIDATION)

    def test_del_txt_record_zone_not_found(self) -> None:
        with requests_mock_lib.Mocker() as m:
            m.get(f'{NOIP_API_BASE}/dns/zones', json={"data": []})
            # Should not raise
            self.client.del_txt_record(FAKE_ZONE, FAKE_FULL_RECORD_NAME, FAKE_VALIDATION)


if __name__ == '__main__':
    unittest.main()
