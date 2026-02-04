"""Tests for the SSHFP supplement."""

from unittest.mock import patch

from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface
from gdoc2netcfg.supplements.reachability import HostReachability
from gdoc2netcfg.supplements.sshfp import (
    enrich_hosts_with_sshfp,
    load_sshfp_cache,
    save_sshfp_cache,
    scan_sshfp,
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


class TestScanSSHFP:
    @patch("gdoc2netcfg.supplements.sshfp.check_port_open")
    @patch("gdoc2netcfg.supplements.sshfp._keyscan")
    def test_scan_finds_sshfp(self, mock_keyscan, mock_port, tmp_path):
        mock_port.return_value = True
        mock_keyscan.return_value = ["server IN SSHFP 1 2 abc123"]
        reachability = {
            "server": HostReachability(
                hostname="server", active_ips=("10.1.10.1",),
            ),
        }
        host = _make_host("server", "10.1.10.1")
        cache_path = tmp_path / "sshfp.json"
        result = scan_sshfp(
            [host], cache_path, force=True, reachability=reachability,
        )

        assert "server" in result
        assert result["server"] == ["server IN SSHFP 1 2 abc123"]
        mock_keyscan.assert_called_once()

    @patch("gdoc2netcfg.supplements.sshfp._keyscan")
    def test_scan_skips_unreachable(self, mock_keyscan, tmp_path):
        reachability = {
            "server": HostReachability(hostname="server", active_ips=()),
        }
        host = _make_host("server", "10.1.10.1")
        cache_path = tmp_path / "sshfp.json"
        result = scan_sshfp(
            [host], cache_path, force=True, reachability=reachability,
        )

        assert result == {}
        mock_keyscan.assert_not_called()

    @patch("gdoc2netcfg.supplements.sshfp.check_port_open")
    @patch("gdoc2netcfg.supplements.sshfp._keyscan")
    def test_scan_skips_no_ssh(self, mock_keyscan, mock_port, tmp_path):
        mock_port.return_value = False
        reachability = {
            "server": HostReachability(
                hostname="server", active_ips=("10.1.10.1",),
            ),
        }
        host = _make_host("server", "10.1.10.1")
        cache_path = tmp_path / "sshfp.json"
        result = scan_sshfp(
            [host], cache_path, force=True, reachability=reachability,
        )

        assert result == {}
        mock_keyscan.assert_not_called()

    @patch("gdoc2netcfg.supplements.sshfp._keyscan")
    def test_scan_skips_without_reachability(self, mock_keyscan, tmp_path):
        """Without reachability data, hosts are skipped."""
        host = _make_host("server", "10.1.10.1")
        cache_path = tmp_path / "sshfp.json"
        result = scan_sshfp([host], cache_path, force=True, reachability=None)

        assert result == {}
        mock_keyscan.assert_not_called()

    @patch("gdoc2netcfg.supplements.sshfp._keyscan")
    def test_scan_uses_cache_when_fresh(self, mock_keyscan, tmp_path):
        cache_path = tmp_path / "sshfp.json"
        existing = {"server": ["server IN SSHFP 1 2 abc123"]}
        save_sshfp_cache(cache_path, existing)

        host = _make_host("server", "10.1.10.1")
        result = scan_sshfp([host], cache_path, force=False, max_age=9999)

        assert result == existing
        mock_keyscan.assert_not_called()

    @patch("gdoc2netcfg.supplements.sshfp.check_port_open")
    @patch("gdoc2netcfg.supplements.sshfp._keyscan")
    def test_scan_saves_cache(self, mock_keyscan, mock_port, tmp_path):
        mock_port.return_value = True
        mock_keyscan.return_value = ["server IN SSHFP 4 2 def456"]
        reachability = {
            "server": HostReachability(
                hostname="server", active_ips=("10.1.10.1",),
            ),
        }
        host = _make_host("server", "10.1.10.1")
        cache_path = tmp_path / "sshfp.json"
        scan_sshfp(
            [host], cache_path, force=True, reachability=reachability,
        )

        assert cache_path.exists()
        import json
        loaded = json.loads(cache_path.read_text())
        assert "server" in loaded
