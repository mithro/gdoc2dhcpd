"""Tests for the SSHFP supplement."""

import json
from pathlib import Path

from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface
from gdoc2netcfg.supplements.sshfp import (
    enrich_hosts_with_sshfp,
    load_sshfp_cache,
    save_sshfp_cache,
)


def _make_host(hostname, ip):
    return Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=[
            NetworkInterface(
                name=None,
                mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                ipv4=IPv4Address(ip),
            )
        ],
        default_ipv4=IPv4Address(ip),
    )


class TestSSHFPCache:
    def test_load_missing_returns_empty(self, tmp_path):
        result = load_sshfp_cache(tmp_path / "nonexistent.json")
        assert result == {}

    def test_save_and_load_roundtrip(self, tmp_path):
        cache_path = tmp_path / "sshfp.json"
        data = {
            "server": ["server IN SSHFP 1 2 abc123"],
            "desktop": ["desktop IN SSHFP 4 2 def456"],
        }
        save_sshfp_cache(cache_path, data)
        loaded = load_sshfp_cache(cache_path)
        assert loaded == data

    def test_save_creates_parent_directory(self, tmp_path):
        cache_path = tmp_path / "subdir" / "sshfp.json"
        save_sshfp_cache(cache_path, {"host": ["record"]})
        assert cache_path.exists()


class TestEnrichHostsWithSSHFP:
    def test_enriches_matching_hosts(self):
        hosts = [_make_host("server", "10.1.10.1"), _make_host("desktop", "10.1.10.2")]
        sshfp_data = {"server": ["server IN SSHFP 1 2 abc123"]}

        enrich_hosts_with_sshfp(hosts, sshfp_data)

        assert hosts[0].sshfp_records == ["server IN SSHFP 1 2 abc123"]
        assert hosts[1].sshfp_records == []

    def test_no_sshfp_data(self):
        hosts = [_make_host("server", "10.1.10.1")]
        enrich_hosts_with_sshfp(hosts, {})
        assert hosts[0].sshfp_records == []

    def test_multiple_records_per_host(self):
        hosts = [_make_host("server", "10.1.10.1")]
        sshfp_data = {
            "server": [
                "server IN SSHFP 1 2 abc123",
                "server IN SSHFP 4 2 def456",
            ]
        }

        enrich_hosts_with_sshfp(hosts, sshfp_data)

        assert len(hosts[0].sshfp_records) == 2
