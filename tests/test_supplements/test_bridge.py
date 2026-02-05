"""Tests for the bridge SNMP supplement."""

import json
from unittest.mock import patch

from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface
from gdoc2netcfg.supplements.bridge import (
    BRIDGE_CAPABLE_HARDWARE,
    _format_hex_mac,
    enrich_hosts_with_bridge_data,
    parse_bridge_port_map,
    parse_if_names,
    parse_lldp_neighbors,
    parse_mac_table,
    parse_poe_status,
    parse_port_pvids,
    parse_port_status,
    parse_vlan_egress_ports,
    parse_vlan_names,
    parse_vlan_untagged_ports,
    scan_bridge,
)
from gdoc2netcfg.supplements.reachability import HostReachability
from gdoc2netcfg.supplements.snmp_common import save_json_cache


def _make_switch(hostname="sw-test", ip="10.1.5.10"):
    return Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=[
            NetworkInterface(
                name="manage",
                mac=MACAddress.parse("08:bd:43:6b:b8:d8"),
                ipv4=IPv4Address(ip),
                dhcp_name=hostname,
            ),
        ],
        default_ipv4=IPv4Address(ip),
        hardware_type="netgear-switch",
        extra={},
    )


class TestParseMacTable:
    """Parse dot1qTpFdbTable walk results into (mac, vlan, port, name) tuples."""

    def test_parses_mac_vlan_port(self):
        # OID: .1.3.6.1.2.1.17.7.1.2.2.1.2.<VLAN>.<M1>.<M2>.<M3>.<M4>.<M5>.<M6>
        walk = [
            ("1.3.6.1.2.1.17.7.1.2.2.1.2.5.8.189.67.107.184.216", "313"),
            ("1.3.6.1.2.1.17.7.1.2.2.1.2.31.228.95.1.141.247.23", "3"),
        ]
        bridge_to_if = {313: 313, 3: 3}
        if_names = {313: "CPU Interface:  0/5/1", 3: "1/g3"}
        result = parse_mac_table(walk, bridge_to_if, if_names)
        assert len(result) == 2
        assert result[0] == ("08:BD:43:6B:B8:D8", 5, 313, "CPU Interface:  0/5/1")
        assert result[1] == ("E4:5F:01:8D:F7:17", 31, 3, "1/g3")

    def test_empty_walk(self):
        assert parse_mac_table([], {}, {}) == []

    def test_unknown_bridge_port(self):
        walk = [
            ("1.3.6.1.2.1.17.7.1.2.2.1.2.5.170.187.204.221.238.255", "99"),
        ]
        result = parse_mac_table(walk, {}, {})
        assert len(result) == 1
        assert result[0] == ("AA:BB:CC:DD:EE:FF", 5, 99, "port99")

    def test_skips_malformed_oid(self):
        """OID with wrong number of components should be silently skipped."""
        walk = [
            ("1.3.6.1.2.1.17.7.1.2.2.1.2.5.170.187", "99"),
        ]
        result = parse_mac_table(walk, {}, {})
        assert len(result) == 0

    def test_multiple_vlans_same_mac(self):
        """Same MAC can appear on different VLANs."""
        walk = [
            ("1.3.6.1.2.1.17.7.1.2.2.1.2.5.170.187.204.221.238.255", "3"),
            ("1.3.6.1.2.1.17.7.1.2.2.1.2.10.170.187.204.221.238.255", "3"),
        ]
        result = parse_mac_table(walk, {3: 3}, {3: "1/g3"})
        assert len(result) == 2
        assert result[0][1] == 5   # VLAN 5
        assert result[1][1] == 10  # VLAN 10


class TestParseIfNames:
    def test_parses_if_names(self):
        walk = [
            ("1.3.6.1.2.1.31.1.1.1.1.1", "1/g1"),
            ("1.3.6.1.2.1.31.1.1.1.1.49", "1/xg49"),
        ]
        result = parse_if_names(walk)
        assert result == {1: "1/g1", 49: "1/xg49"}

    def test_empty(self):
        assert parse_if_names([]) == {}

    def test_multi_digit_index(self):
        walk = [
            ("1.3.6.1.2.1.31.1.1.1.1.314", "CPU Interface:  0/5/1"),
        ]
        result = parse_if_names(walk)
        assert result == {314: "CPU Interface:  0/5/1"}


class TestParseBridgePortMap:
    def test_parses_mapping(self):
        walk = [
            ("1.3.6.1.2.1.17.1.4.1.2.1", "1"),
            ("1.3.6.1.2.1.17.1.4.1.2.50", "50"),
            ("1.3.6.1.2.1.17.1.4.1.2.314", "314"),
        ]
        result = parse_bridge_port_map(walk)
        assert result == {1: 1, 50: 50, 314: 314}

    def test_empty(self):
        assert parse_bridge_port_map([]) == {}


class TestParseVlanNames:
    def test_parses_names(self):
        walk = [
            ("1.3.6.1.2.1.17.7.1.4.3.1.1.1", "Default"),
            ("1.3.6.1.2.1.17.7.1.4.3.1.1.5", "net"),
            ("1.3.6.1.2.1.17.7.1.4.3.1.1.10", "int"),
        ]
        result = parse_vlan_names(walk)
        assert result == [(1, "Default"), (5, "net"), (10, "int")]

    def test_empty(self):
        assert parse_vlan_names([]) == []


class TestParsePortPvids:
    def test_parses_pvids(self):
        walk = [
            ("1.3.6.1.2.1.17.7.1.4.5.1.1.1", "31"),
            ("1.3.6.1.2.1.17.7.1.4.5.1.1.40", "5"),
        ]
        result = parse_port_pvids(walk)
        assert result == [(1, 31), (40, 5)]

    def test_empty(self):
        assert parse_port_pvids([]) == []


class TestParsePortStatus:
    def test_parses_status_and_speed(self):
        oper_walk = [
            ("1.3.6.1.2.1.2.2.1.8.1", "2"),   # down
            ("1.3.6.1.2.1.2.2.1.8.3", "1"),   # up
        ]
        speed_walk = [
            ("1.3.6.1.2.1.31.1.1.1.15.1", "0"),
            ("1.3.6.1.2.1.31.1.1.1.15.3", "1000"),
        ]
        result = parse_port_status(oper_walk, speed_walk)
        assert (1, 2, 0) in result
        assert (3, 1, 1000) in result

    def test_missing_speed(self):
        """Port with oper status but no speed data gets speed 0."""
        oper_walk = [
            ("1.3.6.1.2.1.2.2.1.8.5", "1"),
        ]
        speed_walk = []
        result = parse_port_status(oper_walk, speed_walk)
        assert (5, 1, 0) in result

    def test_empty(self):
        assert parse_port_status([], []) == []


class TestParseLldpNeighbors:
    def test_parses_neighbors(self):
        walk = [
            # lldpRemChassisIdSubtype (OID .4)
            ("1.0.8802.1.1.2.1.4.1.1.4.97.50.1", "4"),
            # lldpRemChassisId (OID .5) - hex MAC
            ("1.0.8802.1.1.2.1.4.1.1.5.97.50.1", "0xc80084897170"),
            # lldpRemPortId (OID .7)
            ("1.0.8802.1.1.2.1.4.1.1.7.97.50.1", "gi24"),
            # lldpRemSysName (OID .9)
            ("1.0.8802.1.1.2.1.4.1.1.9.97.50.1", "sw-cisco-shed"),
        ]
        result = parse_lldp_neighbors(walk)
        assert len(result) == 1
        assert result[0] == (50, "sw-cisco-shed", "gi24", "C8:00:84:89:71:70")

    def test_multiple_neighbors(self):
        walk = [
            # Neighbor 1
            ("1.0.8802.1.1.2.1.4.1.1.5.97.50.1", "0xaabbccddeeff"),
            ("1.0.8802.1.1.2.1.4.1.1.7.97.50.1", "gi24"),
            ("1.0.8802.1.1.2.1.4.1.1.9.97.50.1", "switch-a"),
            # Neighbor 2
            ("1.0.8802.1.1.2.1.4.1.1.5.97.51.2", "0x112233445566"),
            ("1.0.8802.1.1.2.1.4.1.1.7.97.51.2", "eth0"),
            ("1.0.8802.1.1.2.1.4.1.1.9.97.51.2", "switch-b"),
        ]
        result = parse_lldp_neighbors(walk)
        assert len(result) == 2

    def test_empty(self):
        assert parse_lldp_neighbors([]) == []

    def test_non_hex_chassis_id(self):
        """Chassis ID that is not hex MAC format should be preserved as-is."""
        walk = [
            ("1.0.8802.1.1.2.1.4.1.1.5.97.50.1", "some-string-id"),
            ("1.0.8802.1.1.2.1.4.1.1.7.97.50.1", "gi24"),
            ("1.0.8802.1.1.2.1.4.1.1.9.97.50.1", "neighbor"),
        ]
        result = parse_lldp_neighbors(walk)
        assert len(result) == 1
        assert result[0][3] == "some-string-id"

    def test_raw_binary_port_id(self):
        """Port ID as raw 6-byte binary (MAC) should be formatted."""
        walk = [
            ("1.0.8802.1.1.2.1.4.1.1.5.97.50.1", "0xc80084897170"),
            # Raw binary port ID: 0C:C4:7A:16:3B:4A
            ("1.0.8802.1.1.2.1.4.1.1.7.97.50.1", "\x0c\xc4\x7a\x16\x3b\x4a"),
            ("1.0.8802.1.1.2.1.4.1.1.9.97.50.1", "neighbor"),
        ]
        result = parse_lldp_neighbors(walk)
        assert len(result) == 1
        assert result[0][2] == "0C:C4:7A:16:3B:4A"


class TestFormatHexMac:
    """Tests for _format_hex_mac() which normalises chassis IDs to XX:XX:XX:XX:XX:XX."""

    def test_format_hex_mac_raw_bytes(self):
        """Raw 6-byte binary string (pysnmp OCTET STRING via str()) → formatted MAC."""
        raw = "\xc8\x00\x84\x89\x71\x70"
        assert _format_hex_mac(raw) == "C8:00:84:89:71:70"

    def test_format_hex_mac_raw_bytes_all_zeros(self):
        """Raw 6-byte binary string of all zeros."""
        raw = "\x00\x00\x00\x00\x00\x00"
        assert _format_hex_mac(raw) == "00:00:00:00:00:00"

    def test_format_hex_mac_0x_prefix(self):
        """0x-prefixed 12-hex-digit string → formatted MAC."""
        assert _format_hex_mac("0xc80084897170") == "C8:00:84:89:71:70"

    def test_format_hex_mac_12_hex_digits(self):
        """12 hex digits without 0x prefix → formatted MAC."""
        assert _format_hex_mac("aabbccddeeff") == "AA:BB:CC:DD:EE:FF"

    def test_format_hex_mac_passthrough(self):
        """Non-MAC strings returned unchanged."""
        assert _format_hex_mac("some-string-id") == "some-string-id"
        assert _format_hex_mac("") == ""
        assert _format_hex_mac("short") == "short"


class TestParseVlanEgressPorts:
    def test_parses_egress(self):
        walk = [
            ("1.3.6.1.2.1.17.7.1.4.3.1.2.5", "0xffc00000"),
            ("1.3.6.1.2.1.17.7.1.4.3.1.2.10", "0xff000000"),
        ]
        result = parse_vlan_egress_ports(walk)
        assert result == [(5, "0xffc00000"), (10, "0xff000000")]

    def test_empty(self):
        assert parse_vlan_egress_ports([]) == []


class TestParseVlanUntaggedPorts:
    def test_parses_untagged(self):
        walk = [
            ("1.3.6.1.2.1.17.7.1.4.3.1.4.5", "0xff800000"),
        ]
        result = parse_vlan_untagged_ports(walk)
        assert result == [(5, "0xff800000")]

    def test_empty(self):
        assert parse_vlan_untagged_ports([]) == []


class TestParsePoeStatus:
    def test_parses_poe(self):
        walk = [
            # pethPsePortAdminEnable .1.3.6.1.2.1.105.1.1.1.1.1.1 = INTEGER: 1 (enabled)
            ("1.3.6.1.2.1.105.1.1.1.1.1.1", "1"),
            # pethPsePortDetectionStatus .1.3.6.1.2.1.105.1.1.1.6.1.1 = INTEGER: 3 (deliveringPower)
            ("1.3.6.1.2.1.105.1.1.1.6.1.1", "3"),
            # pethPsePortAdminEnable .1.3.6.1.2.1.105.1.1.1.1.1.2 = INTEGER: 2 (disabled)
            ("1.3.6.1.2.1.105.1.1.1.1.1.2", "2"),
            # pethPsePortDetectionStatus .1.3.6.1.2.1.105.1.1.1.6.1.2 = INTEGER: 1 (disabled)
            ("1.3.6.1.2.1.105.1.1.1.6.1.2", "1"),
        ]
        result = parse_poe_status(walk)
        assert len(result) == 2
        assert (1, 1, 3) in result
        assert (2, 2, 1) in result

    def test_empty(self):
        assert parse_poe_status([]) == []


class TestBridgeCapableHardware:
    def test_includes_netgear_switch(self):
        assert "netgear-switch" in BRIDGE_CAPABLE_HARDWARE

    def test_includes_cisco_switch(self):
        assert "cisco-switch" in BRIDGE_CAPABLE_HARDWARE

    def test_excludes_netgear_switch_plus(self):
        assert "netgear-switch-plus" not in BRIDGE_CAPABLE_HARDWARE


class TestEnrichHostsWithBridgeData:
    def test_enriches_switch_hosts(self):
        host = _make_switch()
        cache = {
            "sw-test": {
                "mac_table": [["AA:BB:CC:DD:EE:FF", 5, 3, "1/g3"]],
                "vlan_names": [[1, "Default"], [5, "net"]],
                "port_pvids": [[1, 31]],
                "port_names": [[1, "1/g1"]],
                "port_status": [[1, 2, 0]],
                "lldp_neighbors": [],
                "vlan_egress_ports": [],
                "vlan_untagged_ports": [],
                "poe_status": [],
            }
        }
        enrich_hosts_with_bridge_data([host], cache)
        assert host.bridge_data is not None
        assert len(host.bridge_data.mac_table) == 1
        assert host.bridge_data.mac_table[0] == ("AA:BB:CC:DD:EE:FF", 5, 3, "1/g3")
        assert len(host.bridge_data.vlan_names) == 2
        assert host.bridge_data.vlan_names[0] == (1, "Default")
        assert host.bridge_data.vlan_names[1] == (5, "net")

    def test_no_data_for_host(self):
        host = _make_switch()
        enrich_hosts_with_bridge_data([host], {})
        assert host.bridge_data is None

    def test_bridge_data_is_frozen(self):
        host = _make_switch()
        cache = {
            "sw-test": {
                "mac_table": [],
                "vlan_names": [],
                "port_pvids": [],
                "port_names": [],
                "port_status": [],
                "lldp_neighbors": [],
                "vlan_egress_ports": [],
                "vlan_untagged_ports": [],
                "poe_status": [],
            }
        }
        enrich_hosts_with_bridge_data([host], cache)
        assert host.bridge_data is not None
        try:
            host.bridge_data.mac_table = ()
            assert False, "Should have raised FrozenInstanceError"
        except AttributeError:
            pass

    def test_missing_keys_use_defaults(self):
        """Cache entries missing some keys should still work with empty defaults."""
        host = _make_switch()
        cache = {
            "sw-test": {
                "mac_table": [["AA:BB:CC:DD:EE:FF", 5, 3, "1/g3"]],
                # Missing all other keys
            }
        }
        enrich_hosts_with_bridge_data([host], cache)
        assert host.bridge_data is not None
        assert len(host.bridge_data.mac_table) == 1
        assert host.bridge_data.vlan_names == ()
        assert host.bridge_data.port_pvids == ()


class TestScanBridge:
    @patch("gdoc2netcfg.supplements.bridge._collect_bridge_data")
    def test_scan_collects_from_switch(self, mock_collect, tmp_path):
        mock_collect.return_value = {
            "mac_table": [["AA:BB:CC:DD:EE:FF", 5, 3, "1/g3"]],
            "vlan_names": [[5, "net"]],
            "port_pvids": [],
            "port_names": [],
            "port_status": [],
            "lldp_neighbors": [],
            "vlan_egress_ports": [],
            "vlan_untagged_ports": [],
            "poe_status": [],
        }
        host = _make_switch()
        cache_path = tmp_path / "bridge.json"
        reachability = {
            "sw-test": HostReachability(hostname="sw-test", active_ips=("10.1.5.10",)),
        }
        result = scan_bridge([host], cache_path, force=True, reachability=reachability)
        assert "sw-test" in result
        mock_collect.assert_called_once()

    @patch("gdoc2netcfg.supplements.bridge._collect_bridge_data")
    def test_scan_skips_non_switches(self, mock_collect, tmp_path):
        host = Host(
            machine_name="desktop",
            hostname="desktop",
            interfaces=[
                NetworkInterface(
                    name=None,
                    mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                    ipv4=IPv4Address("10.1.10.5"),
                ),
            ],
            hardware_type=None,
        )
        cache_path = tmp_path / "bridge.json"
        reachability = {
            "desktop": HostReachability(hostname="desktop", active_ips=("10.1.10.5",)),
        }
        result = scan_bridge([host], cache_path, force=True, reachability=reachability)
        assert result == {}
        mock_collect.assert_not_called()

    @patch("gdoc2netcfg.supplements.bridge._collect_bridge_data")
    def test_scan_skips_unreachable(self, mock_collect, tmp_path):
        host = _make_switch()
        cache_path = tmp_path / "bridge.json"
        reachability = {
            "sw-test": HostReachability(hostname="sw-test", active_ips=()),
        }
        result = scan_bridge([host], cache_path, force=True, reachability=reachability)
        assert result == {}
        mock_collect.assert_not_called()

    @patch("gdoc2netcfg.supplements.bridge._collect_bridge_data")
    def test_scan_uses_cache_when_fresh(self, mock_collect, tmp_path):
        cache_path = tmp_path / "bridge.json"
        existing = {
            "sw-test": {
                "mac_table": [], "vlan_names": [], "port_pvids": [],
                "port_names": [], "port_status": [], "lldp_neighbors": [],
                "vlan_egress_ports": [], "vlan_untagged_ports": [], "poe_status": [],
            }
        }
        save_json_cache(cache_path, existing)
        host = _make_switch()
        result = scan_bridge([host], cache_path, force=False, max_age=9999)
        assert result == existing
        mock_collect.assert_not_called()

    @patch("gdoc2netcfg.supplements.bridge._collect_bridge_data")
    def test_scan_saves_cache(self, mock_collect, tmp_path):
        mock_collect.return_value = {
            "mac_table": [], "vlan_names": [], "port_pvids": [],
            "port_names": [], "port_status": [], "lldp_neighbors": [],
            "vlan_egress_ports": [], "vlan_untagged_ports": [], "poe_status": [],
        }
        host = _make_switch()
        cache_path = tmp_path / "bridge.json"
        reachability = {
            "sw-test": HostReachability(hostname="sw-test", active_ips=("10.1.5.10",)),
        }
        scan_bridge([host], cache_path, force=True, reachability=reachability)
        assert cache_path.exists()
        loaded = json.loads(cache_path.read_text())
        assert "sw-test" in loaded

    @patch("gdoc2netcfg.supplements.bridge._collect_bridge_data")
    def test_scan_no_snmp_response(self, mock_collect, tmp_path):
        mock_collect.return_value = None
        host = _make_switch()
        cache_path = tmp_path / "bridge.json"
        reachability = {
            "sw-test": HostReachability(hostname="sw-test", active_ips=("10.1.5.10",)),
        }
        result = scan_bridge([host], cache_path, force=True, reachability=reachability)
        assert "sw-test" not in result

    @patch("gdoc2netcfg.supplements.bridge._collect_bridge_data")
    def test_scan_includes_hosts_with_snmp_data(self, mock_collect, tmp_path):
        """Hosts with existing snmp_data (not bridge-capable hardware type)
        should also be scanned, since SNMP proved reachable."""
        from gdoc2netcfg.models.host import SNMPData

        host = Host(
            machine_name="bmc-server",
            hostname="bmc-server",
            interfaces=[
                NetworkInterface(
                    name=None,
                    mac=MACAddress.parse("00:25:90:aa:bb:cc"),
                    ipv4=IPv4Address("10.1.5.20"),
                    dhcp_name="bmc-server",
                ),
            ],
            default_ipv4=IPv4Address("10.1.5.20"),
            hardware_type="supermicro-bmc",
            snmp_data=SNMPData(snmp_version="v2c"),
        )
        mock_collect.return_value = {
            "mac_table": [], "vlan_names": [], "port_pvids": [],
            "port_names": [], "port_status": [], "lldp_neighbors": [],
            "vlan_egress_ports": [], "vlan_untagged_ports": [], "poe_status": [],
        }
        cache_path = tmp_path / "bridge.json"
        reachability = {
            "bmc-server": HostReachability(hostname="bmc-server", active_ips=("10.1.5.20",)),
        }
        result = scan_bridge([host], cache_path, force=True, reachability=reachability)
        assert "bmc-server" in result
        mock_collect.assert_called_once()

    @patch("gdoc2netcfg.supplements.bridge._collect_bridge_data")
    def test_scan_skips_without_reachability(self, mock_collect, tmp_path):
        """Without reachability data, hosts are skipped."""
        host = _make_switch()
        cache_path = tmp_path / "bridge.json"
        result = scan_bridge([host], cache_path, force=True, reachability=None)
        assert result == {}
        mock_collect.assert_not_called()

    @patch("gdoc2netcfg.supplements.bridge._collect_bridge_data")
    def test_scan_skips_netgear_switch_plus(self, mock_collect, tmp_path):
        """netgear-switch-plus models lack SNMP and should be skipped."""
        host = Host(
            machine_name="gs110emx-rack1",
            hostname="gs110emx-rack1",
            interfaces=[
                NetworkInterface(
                    name=None,
                    mac=MACAddress.parse("08:bd:43:aa:bb:cc"),
                    ipv4=IPv4Address("10.1.5.30"),
                ),
            ],
            hardware_type="netgear-switch-plus",
        )
        cache_path = tmp_path / "bridge.json"
        reachability = {
            "gs110emx-rack1": HostReachability(
                hostname="gs110emx-rack1", active_ips=("10.1.5.30",)
            ),
        }
        result = scan_bridge([host], cache_path, force=True, reachability=reachability)
        assert result == {}
        mock_collect.assert_not_called()
