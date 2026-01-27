"""Tests for the SSL certificate supplement."""

import json
from unittest.mock import MagicMock, patch

from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, SSLCertInfo
from gdoc2netcfg.supplements.ssl_certs import (
    enrich_hosts_with_ssl_certs,
    load_ssl_cert_cache,
    save_ssl_cert_cache,
    scan_ssl_certs,
)


def _make_host(hostname="desktop", ip="10.1.10.100"):
    return Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=[
            NetworkInterface(
                name=None,
                mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                ipv4=IPv4Address(ip),
                ipv6_addresses=[],
                dhcp_name=hostname,
            ),
        ],
        default_ipv4=IPv4Address(ip),
    )


class TestSSLCertInfoModel:
    def test_ssl_cert_info_creation(self):
        info = SSLCertInfo(
            issuer="Let's Encrypt",
            self_signed=False,
            valid=True,
            expiry="2026-04-15",
            sans=("example.com", "www.example.com"),
        )
        assert info.issuer == "Let's Encrypt"
        assert info.self_signed is False
        assert info.valid is True
        assert info.expiry == "2026-04-15"
        assert len(info.sans) == 2

    def test_ssl_cert_info_frozen(self):
        info = SSLCertInfo(
            issuer="Test", self_signed=True, valid=False, expiry=""
        )
        try:
            info.issuer = "Modified"
            assert False, "Should have raised FrozenInstanceError"
        except AttributeError:
            pass

    def test_host_ssl_cert_info_default_none(self):
        host = _make_host()
        assert host.ssl_cert_info is None


class TestCacheIO:
    def test_load_missing_cache(self, tmp_path):
        data = load_ssl_cert_cache(tmp_path / "nonexistent.json")
        assert data == {}

    def test_save_and_load_roundtrip(self, tmp_path):
        cache_path = tmp_path / "ssl_certs.json"
        cert_data = {
            "desktop": {
                "issuer": "Let's Encrypt",
                "self_signed": False,
                "valid": True,
                "expiry": "2026-04-15",
                "sans": ["desktop.example.com"],
            }
        }
        save_ssl_cert_cache(cache_path, cert_data)
        loaded = load_ssl_cert_cache(cache_path)
        assert loaded == cert_data

    def test_save_creates_parent_dirs(self, tmp_path):
        cache_path = tmp_path / "sub" / "dir" / "ssl_certs.json"
        save_ssl_cert_cache(cache_path, {})
        assert cache_path.exists()


class TestEnrichHosts:
    def test_enrich_with_matching_cert(self):
        host = _make_host()
        cert_data = {
            "desktop": {
                "issuer": "Let's Encrypt",
                "self_signed": False,
                "valid": True,
                "expiry": "2026-04-15",
                "sans": ["desktop.example.com"],
            }
        }
        enrich_hosts_with_ssl_certs([host], cert_data)
        assert host.ssl_cert_info is not None
        assert host.ssl_cert_info.issuer == "Let's Encrypt"
        assert host.ssl_cert_info.valid is True
        assert host.ssl_cert_info.sans == ("desktop.example.com",)

    def test_enrich_with_no_matching_cert(self):
        host = _make_host()
        enrich_hosts_with_ssl_certs([host], {})
        assert host.ssl_cert_info is None

    def test_enrich_with_self_signed_cert(self):
        host = _make_host()
        cert_data = {
            "desktop": {
                "issuer": "desktop",
                "self_signed": True,
                "valid": False,
                "expiry": "2027-01-01",
                "sans": [],
            }
        }
        enrich_hosts_with_ssl_certs([host], cert_data)
        assert host.ssl_cert_info.self_signed is True
        assert host.ssl_cert_info.valid is False


class TestScanSSLCerts:
    @patch("gdoc2netcfg.supplements.ssl_certs.check_reachable")
    @patch("gdoc2netcfg.supplements.ssl_certs.check_port_open")
    @patch("gdoc2netcfg.supplements.ssl_certs._fetch_cert")
    def test_scan_finds_cert(self, mock_fetch, mock_port, mock_reach, tmp_path):
        mock_reach.return_value = True
        mock_port.return_value = True
        mock_fetch.return_value = {
            "issuer": "Let's Encrypt",
            "self_signed": False,
            "valid": True,
            "expiry": "2026-04-15",
            "sans": ["desktop.example.com"],
        }

        host = _make_host()
        cache_path = tmp_path / "ssl_certs.json"
        result = scan_ssl_certs([host], cache_path, force=True)

        assert "desktop" in result
        assert result["desktop"]["valid"] is True
        mock_fetch.assert_called_once_with("10.1.10.100")

    @patch("gdoc2netcfg.supplements.ssl_certs.check_reachable")
    def test_scan_skips_unreachable(self, mock_reach, tmp_path):
        mock_reach.return_value = False

        host = _make_host()
        cache_path = tmp_path / "ssl_certs.json"
        result = scan_ssl_certs([host], cache_path, force=True)

        assert result == {}

    @patch("gdoc2netcfg.supplements.ssl_certs.check_reachable")
    @patch("gdoc2netcfg.supplements.ssl_certs.check_port_open")
    def test_scan_skips_no_https(self, mock_port, mock_reach, tmp_path):
        mock_reach.return_value = True
        mock_port.return_value = False

        host = _make_host()
        cache_path = tmp_path / "ssl_certs.json"
        result = scan_ssl_certs([host], cache_path, force=True)

        assert result == {}

    @patch("gdoc2netcfg.supplements.ssl_certs.check_reachable")
    @patch("gdoc2netcfg.supplements.ssl_certs.check_port_open")
    @patch("gdoc2netcfg.supplements.ssl_certs._fetch_cert")
    def test_scan_uses_cache_when_fresh(self, mock_fetch, mock_port, mock_reach, tmp_path):
        cache_path = tmp_path / "ssl_certs.json"
        existing = {
            "desktop": {
                "issuer": "Cached",
                "self_signed": False,
                "valid": True,
                "expiry": "",
                "sans": [],
            }
        }
        save_ssl_cert_cache(cache_path, existing)

        host = _make_host()
        result = scan_ssl_certs([host], cache_path, force=False, max_age=9999)

        assert result == existing
        mock_reach.assert_not_called()
        mock_fetch.assert_not_called()

    @patch("gdoc2netcfg.supplements.ssl_certs.check_reachable")
    @patch("gdoc2netcfg.supplements.ssl_certs.check_port_open")
    @patch("gdoc2netcfg.supplements.ssl_certs._fetch_cert")
    def test_scan_saves_cache(self, mock_fetch, mock_port, mock_reach, tmp_path):
        mock_reach.return_value = True
        mock_port.return_value = True
        mock_fetch.return_value = {
            "issuer": "LE",
            "self_signed": False,
            "valid": True,
            "expiry": "2026-06-01",
            "sans": [],
        }

        host = _make_host()
        cache_path = tmp_path / "ssl_certs.json"
        scan_ssl_certs([host], cache_path, force=True)

        assert cache_path.exists()
        loaded = json.loads(cache_path.read_text())
        assert "desktop" in loaded


class TestFetchCert:
    @patch("gdoc2netcfg.supplements.ssl_certs.socket.create_connection")
    @patch("gdoc2netcfg.supplements.ssl_certs.ssl.create_default_context")
    def test_fetch_valid_cert(self, mock_ctx_factory, mock_conn):
        from gdoc2netcfg.supplements.ssl_certs import _fetch_cert

        # Set up mock SSL context
        mock_ctx = MagicMock()
        mock_ctx_factory.return_value = mock_ctx

        mock_sock = MagicMock()
        mock_conn.return_value.__enter__ = MagicMock(return_value=mock_sock)
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        mock_ssock = MagicMock()
        mock_ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=mock_ssock)
        mock_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)

        mock_ssock.getpeercert.return_value = {
            "issuer": ((("organizationName", "Let's Encrypt"),),),
            "subject": ((("commonName", "desktop.example.com"),),),
            "notAfter": "Apr 15 12:00:00 2026 GMT",
            "subjectAltName": (("DNS", "desktop.example.com"), ("DNS", "www.example.com")),
        }

        result = _fetch_cert("10.1.10.100")

        assert result is not None
        assert result["issuer"] == "Let's Encrypt"
        assert result["self_signed"] is False
        assert result["valid"] is True
        assert result["expiry"] == "2026-04-15"
        assert result["sans"] == ["desktop.example.com", "www.example.com"]

    @patch("gdoc2netcfg.supplements.ssl_certs.socket.create_connection")
    @patch("gdoc2netcfg.supplements.ssl_certs.ssl.create_default_context")
    def test_fetch_connection_refused(self, mock_ctx_factory, mock_conn):
        from gdoc2netcfg.supplements.ssl_certs import _fetch_cert

        mock_ctx_factory.return_value = MagicMock()
        mock_conn.side_effect = OSError("Connection refused")

        result = _fetch_cert("10.1.10.100")
        assert result is None
