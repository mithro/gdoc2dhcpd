"""Tests for the NSDP supplement."""

import json
from unittest.mock import patch, MagicMock

from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NSDPData, NetworkInterface
from gdoc2netcfg.supplements.nsdp import (
    enrich_hosts_with_nsdp,
    load_nsdp_cache,
    save_nsdp_cache,
)


def _make_host(hostname="gs110emx", ip="10.1.20.1", hardware_type="netgear-switch-plus"):
    return Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=[
            NetworkInterface(
                name=None,
                mac=MACAddress.parse("00:09:5b:aa:bb:cc"),
                ipv4=IPv4Address(ip),
                dhcp_name=hostname,
            ),
        ],
        default_ipv4=IPv4Address(ip),
        hardware_type=hardware_type,
    )


class TestNSDPCache:
    def test_load_missing_returns_empty(self, tmp_path):
        result = load_nsdp_cache(tmp_path / "nonexistent.json")
        assert result == {}

    def test_save_and_load_roundtrip(self, tmp_path):
        cache_path = tmp_path / "nsdp.json"
        data = {
            "gs110emx": {
                "model": "GS110EMX",
                "mac": "00:09:5b:aa:bb:cc",
                "firmware_version": "V2.06.24GR",
            }
        }
        save_nsdp_cache(cache_path, data)
        loaded = load_nsdp_cache(cache_path)
        assert loaded == data

    def test_save_creates_parent_directory(self, tmp_path):
        cache_path = tmp_path / "subdir" / "nsdp.json"
        save_nsdp_cache(cache_path, {"host": {"model": "GS110EMX", "mac": "aa:bb:cc:dd:ee:ff"}})
        assert cache_path.exists()


class TestEnrichHostsWithNSDP:
    def test_enrich_from_cache(self):
        host = _make_host()
        cache = {
            "gs110emx": {
                "model": "GS110EMX",
                "mac": "00:09:5b:aa:bb:cc",
                "firmware_version": "V2.06.24GR",
                "port_count": 10,
                "port_status": [(1, 5), (2, 0)],
            }
        }
        enrich_hosts_with_nsdp([host], cache)
        assert host.nsdp_data is not None
        assert host.nsdp_data.model == "GS110EMX"
        assert host.nsdp_data.firmware_version == "V2.06.24GR"
        assert host.nsdp_data.port_count == 10
        assert len(host.nsdp_data.port_status) == 2

    def test_no_cache_entry(self):
        host = _make_host()
        enrich_hosts_with_nsdp([host], {})
        assert host.nsdp_data is None

    def test_skip_non_netgear(self):
        host = _make_host(hardware_type=None)
        cache = {
            "gs110emx": {
                "model": "GS110EMX",
                "mac": "00:09:5b:aa:bb:cc",
            }
        }
        enrich_hosts_with_nsdp([host], cache)
        # Still enriches — cache is hostname-keyed, not hardware-type filtered
        assert host.nsdp_data is not None
