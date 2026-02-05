"""Tests for the NSDP supplement."""

from gdoc2netcfg.cli.main import main
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface
from gdoc2netcfg.supplements.nsdp import (
    enrich_hosts_with_nsdp,
    load_nsdp_cache,
    save_nsdp_cache,
)


class TestNSDPCLIRegistration:
    """Test that the 'nsdp' CLI subcommand is registered."""

    def test_nsdp_subcommand_in_help(self, capsys):
        """The nsdp subcommand should be registered in argparse."""
        try:
            main(["nsdp", "--help"])
        except SystemExit as e:
            # Should exit 0 with help output, not exit 2 with error
            assert e.code == 0, f"Expected exit 0 for --help, got exit {e.code}"
        captured = capsys.readouterr()
        # The help output should describe what nsdp does
        assert "nsdp" in captured.out.lower() or "netgear" in captured.out.lower()


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

    def test_enrich_with_vlan_engine(self):
        """Test that vlan_engine is loaded from cache."""
        host = _make_host()
        cache = {
            "gs110emx": {
                "model": "GS110EMX",
                "mac": "00:09:5b:aa:bb:cc",
                "vlan_engine": 4,
            }
        }
        enrich_hosts_with_nsdp([host], cache)
        assert host.nsdp_data is not None
        assert host.nsdp_data.vlan_engine == 4

    def test_enrich_with_vlan_members(self):
        """Test that vlan_members is loaded from cache."""
        host = _make_host()
        cache = {
            "gs110emx": {
                "model": "GS110EMX",
                "mac": "00:09:5b:aa:bb:cc",
                "vlan_members": [
                    [1, [1, 2, 3], [3]],
                    [10, [1, 2], [1, 2]],
                ],
            }
        }
        enrich_hosts_with_nsdp([host], cache)
        assert host.nsdp_data is not None
        assert len(host.nsdp_data.vlan_members) == 2
        # Check first VLAN
        assert host.nsdp_data.vlan_members[0][0] == 1  # vlan_id
        assert host.nsdp_data.vlan_members[0][1] == frozenset({1, 2, 3})  # members
        assert host.nsdp_data.vlan_members[0][2] == frozenset({3})  # tagged
        # Check second VLAN
        assert host.nsdp_data.vlan_members[1][0] == 10  # vlan_id
        assert host.nsdp_data.vlan_members[1][1] == frozenset({1, 2})  # members
        assert host.nsdp_data.vlan_members[1][2] == frozenset({1, 2})  # tagged

    def test_enrich_with_port_statistics(self):
        """Test that port_statistics is loaded from cache."""
        host = _make_host()
        cache = {
            "gs110emx": {
                "model": "GS110EMX",
                "mac": "00:09:5b:aa:bb:cc",
                "port_statistics": [
                    [1, 1000, 500, 0],
                    [2, 2000, 1000, 5],
                ],
            }
        }
        enrich_hosts_with_nsdp([host], cache)
        assert host.nsdp_data is not None
        assert len(host.nsdp_data.port_statistics) == 2
        assert host.nsdp_data.port_statistics[0] == (1, 1000, 500, 0)
        assert host.nsdp_data.port_statistics[1] == (2, 2000, 1000, 5)

    def test_enrich_with_all_new_fields(self):
        """Test enrichment with all new VLAN/stats fields together."""
        host = _make_host()
        cache = {
            "gs110emx": {
                "model": "GS110EMX",
                "mac": "00:09:5b:aa:bb:cc",
                "vlan_engine": 4,
                "vlan_members": [[1, [1, 2], [2]]],
                "port_statistics": [[1, 100, 50, 0]],
            }
        }
        enrich_hosts_with_nsdp([host], cache)
        assert host.nsdp_data is not None
        assert host.nsdp_data.vlan_engine == 4
        assert len(host.nsdp_data.vlan_members) == 1
        assert len(host.nsdp_data.port_statistics) == 1
