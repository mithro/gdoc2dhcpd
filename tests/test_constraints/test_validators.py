"""Tests for constraint validators.

Extracted from the assertions in dnsmasq.py:get_data(), get_mac_info(),
and dhcp_host_config().
"""

from gdoc2netcfg.constraints.errors import Severity
from gdoc2netcfg.constraints.validators import (
    validate_cross_record_constraints,
    validate_field_constraints,
    validate_ipv6_consistency,
    validate_record_constraints,
)
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, NetworkInventory
from gdoc2netcfg.models.network import IPv6Prefix, Site
from gdoc2netcfg.sources.parser import DeviceRecord


def _record(machine="desktop", mac="aa:bb:cc:dd:ee:ff", ip="10.1.10.1"):
    return DeviceRecord(
        sheet_name="Network", row_number=2,
        machine=machine, mac_address=mac, ip=ip,
    )


def _host(hostname, interfaces):
    return Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=interfaces,
    )


def _iface(name=None, mac="aa:bb:cc:dd:ee:ff", ip="10.1.10.1", dhcp_name="test"):
    return NetworkInterface(
        name=name,
        mac=MACAddress.parse(mac),
        ipv4=IPv4Address(ip),
        dhcp_name=dhcp_name,
    )


SITE = Site(name="welland", domain="welland.mithis.com")


class TestFieldConstraints:
    def test_valid_record(self):
        result = validate_field_constraints([_record()])
        assert result.is_valid
        assert len(result.violations) == 0

    def test_missing_mac(self):
        result = validate_field_constraints([_record(mac="")])
        assert len(result.warnings) == 1
        assert result.warnings[0].code == "missing_mac"

    def test_missing_machine(self):
        result = validate_field_constraints([_record(machine="")])
        assert len(result.warnings) == 1
        assert result.warnings[0].code == "missing_machine"

    def test_missing_ip(self):
        result = validate_field_constraints([_record(ip="")])
        assert len(result.warnings) == 1
        assert result.warnings[0].code == "missing_ip"

    def test_multiple_missing_fields(self):
        result = validate_field_constraints([_record(mac="", machine="", ip="")])
        assert len(result.warnings) == 3

    def test_record_id_format(self):
        result = validate_field_constraints([_record(mac="")])
        assert result.warnings[0].record_id == "Network:2"


class TestRecordConstraints:
    def test_valid_host(self):
        host = _host("server", [_iface(name="eth0", dhcp_name="eth0-server")])
        result = validate_record_constraints([host])
        assert result.is_valid

    def test_invalid_dhcp_name(self):
        host = _host("server", [_iface(dhcp_name="bad name!")])
        result = validate_record_constraints([host])
        assert result.has_errors
        assert result.errors[0].code == "invalid_dhcp_name"

    def test_valid_dhcp_name_with_dots(self):
        host = _host("cam", [_iface(dhcp_name="camera.iot")])
        result = validate_record_constraints([host])
        assert result.is_valid

    def test_valid_dhcp_name_with_dashes_underscores(self):
        host = _host("srv", [_iface(dhcp_name="eth0-my_server")])
        result = validate_record_constraints([host])
        assert result.is_valid

    def test_bmc_on_management_network(self):
        """BMC on 10.1.5.X is valid."""
        host = _host("server", [
            _iface(name="bmc", ip="10.1.5.200", dhcp_name="bmc-server"),
        ])
        result = validate_record_constraints([host])
        assert result.is_valid

    def test_bmc_not_on_management_network(self):
        """BMC on 10.1.10.X is an error."""
        host = _host("server", [
            _iface(name="bmc", ip="10.1.10.200", dhcp_name="bmc-server"),
        ])
        result = validate_record_constraints([host])
        assert result.has_errors
        assert result.errors[0].code == "bmc_not_management"

    def test_test_hardware_bmc_correct_subnet(self):
        """Test-hardware BMC on 10.41.1.X is valid."""
        host = _host("board", [
            _iface(name="bmc", ip="10.41.1.200", dhcp_name="bmc-board"),
        ])
        result = validate_record_constraints([host])
        assert result.is_valid

    def test_test_hardware_bmc_wrong_subnet(self):
        """Test-hardware BMC on 10.41.2.X is an error."""
        host = _host("board", [
            _iface(name="bmc", ip="10.41.2.200", dhcp_name="bmc-board"),
        ])
        result = validate_record_constraints([host])
        assert result.has_errors
        assert result.errors[0].code == "bmc_wrong_subnet"

    def test_non_bmc_interface_no_check(self):
        """Non-BMC interfaces don't get BMC placement validation."""
        host = _host("server", [
            _iface(name="eth0", ip="10.1.10.200", dhcp_name="eth0-server"),
        ])
        result = validate_record_constraints([host])
        assert result.is_valid


class TestCrossRecordConstraints:
    def test_valid_inventory(self):
        hosts = [
            _host("a", [_iface(mac="aa:bb:cc:dd:ee:01", ip="10.1.10.1", dhcp_name="a")]),
            _host("b", [_iface(mac="aa:bb:cc:dd:ee:02", ip="10.1.10.2", dhcp_name="b")]),
        ]
        inv = NetworkInventory(
            site=SITE, hosts=hosts,
            ip_to_macs={
                "10.1.10.1": [(MACAddress.parse("aa:bb:cc:dd:ee:01"), "a")],
                "10.1.10.2": [(MACAddress.parse("aa:bb:cc:dd:ee:02"), "b")],
            },
        )
        result = validate_cross_record_constraints(inv)
        assert result.is_valid

    def test_mac_duplicate_ip(self):
        """Same MAC on two different IPs is an error."""
        hosts = [
            _host("a", [_iface(mac="aa:bb:cc:dd:ee:01", ip="10.1.10.1", dhcp_name="a")]),
            _host("b", [_iface(mac="aa:bb:cc:dd:ee:01", ip="10.1.10.2", dhcp_name="b")]),
        ]
        inv = NetworkInventory(site=SITE, hosts=hosts, ip_to_macs={})
        result = validate_cross_record_constraints(inv)
        assert result.has_errors
        assert result.errors[0].code == "mac_duplicate_ip"

    def test_mac_same_ip_ok(self):
        """Same MAC on same IP is fine (e.g., same device listed twice)."""
        hosts = [
            _host("a", [_iface(mac="aa:bb:cc:dd:ee:01", ip="10.1.10.1", dhcp_name="a")]),
            _host("b", [_iface(mac="aa:bb:cc:dd:ee:01", ip="10.1.10.1", dhcp_name="b")]),
        ]
        inv = NetworkInventory(site=SITE, hosts=hosts, ip_to_macs={})
        result = validate_cross_record_constraints(inv)
        # MAC→IP check: only one unique IP, so no error
        mac_errors = [v for v in result.errors if v.code == "mac_duplicate_ip"]
        assert len(mac_errors) == 0

    def test_multiple_macs_on_roaming_ip(self):
        """Multiple MACs on a roaming IP (10.1.20.X) is allowed."""
        inv = NetworkInventory(
            site=SITE, hosts=[],
            ip_to_macs={
                "10.1.20.1": [
                    (MACAddress.parse("aa:bb:cc:dd:ee:01"), "laptop-wifi"),
                    (MACAddress.parse("aa:bb:cc:dd:ee:02"), "laptop-eth"),
                ],
            },
        )
        result = validate_cross_record_constraints(inv)
        ip_errors = [v for v in result.errors if v.code == "ip_multiple_macs"]
        assert len(ip_errors) == 0

    def test_multiple_macs_on_non_roaming_ip(self):
        """Multiple MACs on a non-roaming IP is an error."""
        inv = NetworkInventory(
            site=SITE, hosts=[],
            ip_to_macs={
                "10.1.10.1": [
                    (MACAddress.parse("aa:bb:cc:dd:ee:01"), "a"),
                    (MACAddress.parse("aa:bb:cc:dd:ee:02"), "b"),
                ],
            },
        )
        result = validate_cross_record_constraints(inv)
        assert result.has_errors
        assert result.errors[0].code == "ip_multiple_macs"


IPV6_SITE = Site(
    name="welland",
    domain="welland.mithis.com",
    ipv6_prefixes=[
        IPv6Prefix(prefix="2404:e80:a137:", enabled=True),
        IPv6Prefix(prefix="2001:470:82b3:", enabled=False),
    ],
)


def _ipv6_record(ip="10.1.10.1", extra=None, machine="desktop", iface="eth0"):
    return DeviceRecord(
        sheet_name="Network", row_number=99,
        machine=machine, mac_address="aa:bb:cc:dd:ee:ff", ip=ip,
        interface=iface,
        extra=extra or {},
    )


class TestIPv6Consistency:
    def test_matching_ipv6_no_violations(self):
        """Spreadsheet IPv6 matching the algorithm produces no violations."""
        record = _ipv6_record(extra={
            "IPv6 A": "2404:e80:a137:110::1",
        })
        result = validate_ipv6_consistency([record], IPV6_SITE)
        assert result.is_valid
        assert len(result.violations) == 0

    def test_mismatched_ipv6_is_error(self):
        """Spreadsheet IPv6 differing from algorithm is an error."""
        record = _ipv6_record(extra={
            "IPv6 A": "2404:e80:a137:110::99",  # Algorithm expects ::1
        })
        result = validate_ipv6_consistency([record], IPV6_SITE)
        assert result.has_errors
        assert result.errors[0].code == "ipv6_mismatch"

    def test_disabled_prefix_skipped(self):
        """IPv6 B using disabled prefix is silently skipped."""
        record = _ipv6_record(extra={
            "IPv6 A": "2404:e80:a137:110::1",
            "IPv6 B": "2001:470:82b3:110::1",
        })
        result = validate_ipv6_consistency([record], IPV6_SITE)
        assert result.is_valid
        assert len(result.violations) == 0

    def test_unknown_prefix_is_warning(self):
        """IPv6 with unrecognized prefix produces a warning."""
        record = _ipv6_record(extra={
            "IPv6 A": "fd00:1234:5678:110::1",
        })
        result = validate_ipv6_consistency([record], IPV6_SITE)
        assert len(result.warnings) == 1
        assert result.warnings[0].code == "ipv6_unknown_prefix"

    def test_no_ipv6_columns_no_violations(self):
        """Records without IPv6 columns produce no violations."""
        record = _ipv6_record(extra={"Location": "rack-1"})
        result = validate_ipv6_consistency([record], IPV6_SITE)
        assert len(result.violations) == 0

    def test_empty_ipv6_value_no_violation(self):
        """Empty IPv6 column value is not a violation."""
        record = _ipv6_record(extra={"IPv6 A": ""})
        result = validate_ipv6_consistency([record], IPV6_SITE)
        assert len(result.violations) == 0

    def test_non_mappable_ip_with_ipv6_warns(self):
        """Public IP with spreadsheet IPv6 warns (no algorithmic mapping)."""
        record = _ipv6_record(
            ip="87.121.95.37",
            extra={"IPv6 A": "2404:e80:a137:110::1"},
        )
        result = validate_ipv6_consistency([record], IPV6_SITE)
        assert len(result.warnings) == 1
        assert result.warnings[0].code == "ipv6_no_algorithmic"
