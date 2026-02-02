"""Tests for shared SNMP infrastructure."""

from unittest.mock import patch

from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface
from gdoc2netcfg.supplements.snmp_common import (
    load_json_cache,
    save_json_cache,
    try_snmp_credentials,
)


def _make_host(hostname="switch", ip="10.1.10.1", extra=None):
    return Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=[
            NetworkInterface(
                name=None,
                mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                ipv4=IPv4Address(ip),
                dhcp_name=hostname,
            ),
        ],
        default_ipv4=IPv4Address(ip),
        extra=extra or {},
    )


class TestJSONCache:
    def test_load_missing_returns_empty(self, tmp_path):
        result = load_json_cache(tmp_path / "nonexistent.json")
        assert result == {}

    def test_save_and_load_roundtrip(self, tmp_path):
        cache_path = tmp_path / "cache.json"
        data = {"host1": {"key": "value"}}
        save_json_cache(cache_path, data)
        loaded = load_json_cache(cache_path)
        assert loaded == data

    def test_save_creates_parent_directory(self, tmp_path):
        cache_path = tmp_path / "subdir" / "cache.json"
        save_json_cache(cache_path, {"host": {"k": "v"}})
        assert cache_path.exists()


class TestTrySNMPCredentials:
    @patch("gdoc2netcfg.supplements.snmp_common.asyncio.run")
    def test_public_community_succeeds(self, mock_run):
        mock_run.return_value = {
            "snmp_version": "v2c",
            "system_info": {"sysName": "device"},
        }
        host = _make_host()
        result = try_snmp_credentials("10.1.10.1", host)
        assert result is not None
        assert result["system_info"]["sysName"] == "device"
        assert mock_run.call_count == 1

    @patch("gdoc2netcfg.supplements.snmp_common.asyncio.run")
    def test_fallback_to_custom_community(self, mock_run):
        mock_run.side_effect = [
            None,
            {"snmp_version": "v2c", "system_info": {"sysName": "device"}},
        ]
        host = _make_host(extra={"SNMP Community": "secret"})
        result = try_snmp_credentials("10.1.10.1", host)
        assert result is not None
        assert mock_run.call_count == 2

    @patch("gdoc2netcfg.supplements.snmp_common.asyncio.run")
    def test_all_credentials_fail(self, mock_run):
        mock_run.return_value = None
        host = _make_host()
        result = try_snmp_credentials("10.1.10.1", host)
        assert result is None

    @patch("gdoc2netcfg.supplements.snmp_common.asyncio.run")
    def test_skips_duplicate_community(self, mock_run):
        mock_run.return_value = None
        host = _make_host(extra={"SNMP Community": "public"})
        result = try_snmp_credentials("10.1.10.1", host)
        assert result is None
        assert mock_run.call_count == 1
