"""Tests for bridge/topology validation constraints."""

from gdoc2netcfg.constraints.bridge_validation import validate_vlan_names
from gdoc2netcfg.constraints.errors import Severity
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import BridgeData, Host, NetworkInterface
from gdoc2netcfg.models.network import VLAN, Site


def _make_site_with_vlans():
    return Site(
        name="test",
        domain="test.example.com",
        vlans={
            1: VLAN(id=1, name="tmp", subdomain="tmp", third_octets=(1,)),
            5: VLAN(id=5, name="net", subdomain="net", third_octets=(5,)),
            10: VLAN(id=10, name="int", subdomain="int", third_octets=(10,)),
        },
    )


def _make_switch_with_bridge(hostname, vlan_names, **kwargs):
    host = Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=[
            NetworkInterface(
                name="manage",
                mac=MACAddress.parse("08:bd:43:6b:b8:d8"),
                ipv4=IPv4Address("10.1.5.11"),
            ),
        ],
        hardware_type="netgear-switch",
        bridge_data=BridgeData(
            vlan_names=tuple(vlan_names),
            **kwargs,
        ),
    )
    return host


class TestValidateVlanNames:
    def test_matching_names_no_violations(self):
        site = _make_site_with_vlans()
        host = _make_switch_with_bridge("sw-test", [(5, "net"), (10, "int")])
        result = validate_vlan_names([host], site)
        assert result.is_valid
        assert len(result.warnings) == 0

    def test_mismatched_name_produces_warning(self):
        site = _make_site_with_vlans()
        host = _make_switch_with_bridge("sw-test", [(5, "wrong-name")])
        result = validate_vlan_names([host], site)
        assert len(result.warnings) == 1
        assert "wrong-name" in result.warnings[0].message
        assert "net" in result.warnings[0].message
        assert result.warnings[0].severity == Severity.WARNING
        assert result.warnings[0].code == "bridge_vlan_name_mismatch"

    def test_unknown_vlan_on_switch_produces_warning(self):
        site = _make_site_with_vlans()
        host = _make_switch_with_bridge("sw-test", [(4089, "Auto-Video")])
        result = validate_vlan_names([host], site)
        assert len(result.warnings) == 1
        assert "4089" in result.warnings[0].message
        assert result.warnings[0].code == "bridge_unknown_vlan"

    def test_skips_hosts_without_bridge_data(self):
        site = _make_site_with_vlans()
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
        )
        result = validate_vlan_names([host], site)
        assert result.is_valid
        assert len(result.warnings) == 0

    def test_default_vlan_1_name_ignored(self):
        """VLAN 1 named 'Default' on switch but 'tmp' in spreadsheet is OK."""
        site = _make_site_with_vlans()
        host = _make_switch_with_bridge("sw-test", [(1, "Default")])
        result = validate_vlan_names([host], site)
        assert result.is_valid
        assert len(result.warnings) == 0

    def test_vlan_1_non_default_name_still_compared(self):
        """VLAN 1 named something other than 'Default' IS compared."""
        site = _make_site_with_vlans()
        host = _make_switch_with_bridge("sw-test", [(1, "custom-name")])
        result = validate_vlan_names([host], site)
        assert len(result.warnings) == 1
        assert "custom-name" in result.warnings[0].message
        assert "tmp" in result.warnings[0].message

    def test_multiple_switches_aggregate_warnings(self):
        """Warnings from multiple switches are all collected."""
        site = _make_site_with_vlans()
        sw1 = _make_switch_with_bridge("sw-1", [(99, "mystery")])
        sw2 = _make_switch_with_bridge("sw-2", [(5, "wrong")])
        result = validate_vlan_names([sw1, sw2], site)
        assert len(result.warnings) == 2
        record_ids = {w.record_id for w in result.warnings}
        assert record_ids == {"sw-1", "sw-2"}

    def test_warnings_are_not_errors(self):
        """VLAN name issues are warnings, not errors -- is_valid stays True."""
        site = _make_site_with_vlans()
        host = _make_switch_with_bridge("sw-test", [(5, "wrong"), (999, "bogus")])
        result = validate_vlan_names([host], site)
        assert result.is_valid  # warnings don't fail validation
        assert len(result.warnings) == 2
