"""Tests for SNMP availability validation constraints."""

from gdoc2netcfg.constraints.errors import Severity
from gdoc2netcfg.constraints.snmp_validation import validate_snmp_availability
from gdoc2netcfg.derivations.hardware import (
    HARDWARE_CISCO_SWITCH,
    HARDWARE_NETGEAR_SWITCH,
    HARDWARE_NETGEAR_SWITCH_PLUS,
    HARDWARE_SUPERMICRO_BMC,
    HARDWARE_SUPERMICRO_BMC_LEGACY,
)
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, SNMPData
from gdoc2netcfg.supplements.reachability import HostReachability


def _make_host(
    hostname: str,
    hardware_type: str | None = None,
    snmp_data: SNMPData | None = None,
) -> Host:
    return Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=[
            NetworkInterface(
                name=None,
                mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                ipv4=IPv4Address("10.1.10.100"),
                dhcp_name=hostname,
            ),
        ],
        default_ipv4=IPv4Address("10.1.10.100"),
        hardware_type=hardware_type,
        snmp_data=snmp_data,
    )


def _snmp_data() -> SNMPData:
    return SNMPData(
        snmp_version="v2c",
        system_info=(("sysName", "test-device"),),
    )


class TestKnownDeviceUp:
    def test_netgear_up_no_snmp_error(self):
        """Known device UP + no SNMP → error."""
        host = _make_host("switch", hardware_type=HARDWARE_NETGEAR_SWITCH)
        reachability = {
            "switch": HostReachability(hostname="switch", active_ips=("10.1.10.100",)),
        }
        result = validate_snmp_availability([host], reachability)

        errors = [v for v in result.errors if v.code == "snmp_no_response"]
        assert len(errors) == 1
        assert "netgear-switch" in errors[0].message
        assert errors[0].severity == Severity.ERROR
        assert errors[0].record_id == "switch"

    def test_netgear_up_has_snmp_ok(self):
        """Known device UP + has SNMP → no error."""
        host = _make_host(
            "switch",
            hardware_type=HARDWARE_NETGEAR_SWITCH,
            snmp_data=_snmp_data(),
        )
        reachability = {
            "switch": HostReachability(hostname="switch", active_ips=("10.1.10.100",)),
        }
        result = validate_snmp_availability([host], reachability)
        assert len(result.violations) == 0

    def test_legacy_bmc_up_no_snmp_ok(self):
        """Legacy BMC UP + no SNMP → no error (not SNMP-required)."""
        host = _make_host("bmc.tweed", hardware_type=HARDWARE_SUPERMICRO_BMC_LEGACY)
        reachability = {
            "bmc.tweed": HostReachability(
                hostname="bmc.tweed", active_ips=("10.1.5.20",)
            ),
        }
        result = validate_snmp_availability([host], reachability)
        assert len(result.violations) == 0

    def test_netgear_plus_up_no_snmp_ok(self):
        """Netgear Plus device UP + no SNMP → no error (not SNMP-required)."""
        host = _make_host("gs110emx-rack1", hardware_type=HARDWARE_NETGEAR_SWITCH_PLUS)
        reachability = {
            "gs110emx-rack1": HostReachability(
                hostname="gs110emx-rack1", active_ips=("10.1.10.100",)
            ),
        }
        result = validate_snmp_availability([host], reachability)
        assert len(result.violations) == 0

    def test_cisco_up_no_snmp_error(self):
        """Cisco switch UP + no SNMP → error."""
        host = _make_host("sw-cisco-shed", hardware_type=HARDWARE_CISCO_SWITCH)
        reachability = {
            "sw-cisco-shed": HostReachability(
                hostname="sw-cisco-shed", active_ips=("10.1.5.35",)
            ),
        }
        result = validate_snmp_availability([host], reachability)

        errors = [v for v in result.errors if v.code == "snmp_no_response"]
        assert len(errors) == 1
        assert "cisco-switch" in errors[0].message
        assert errors[0].severity == Severity.ERROR
        assert errors[0].record_id == "sw-cisco-shed"

    def test_cisco_up_has_snmp_ok(self):
        """Cisco switch UP + has SNMP → no error."""
        host = _make_host(
            "sw-cisco-shed",
            hardware_type=HARDWARE_CISCO_SWITCH,
            snmp_data=_snmp_data(),
        )
        reachability = {
            "sw-cisco-shed": HostReachability(
                hostname="sw-cisco-shed", active_ips=("10.1.5.35",)
            ),
        }
        result = validate_snmp_availability([host], reachability)
        assert len(result.violations) == 0

    def test_bmc_up_no_snmp_error(self):
        """Supermicro BMC UP + no SNMP → error."""
        host = _make_host("bmc.server", hardware_type=HARDWARE_SUPERMICRO_BMC)
        reachability = {
            "bmc.server": HostReachability(
                hostname="bmc.server", active_ips=("10.1.5.10",)
            ),
        }
        result = validate_snmp_availability([host], reachability)

        errors = [v for v in result.errors if v.code == "snmp_no_response"]
        assert len(errors) == 1
        assert "supermicro-bmc" in errors[0].message


class TestKnownDeviceDown:
    def test_netgear_down_no_error(self):
        """Known device DOWN → no error."""
        host = _make_host("switch", hardware_type=HARDWARE_NETGEAR_SWITCH)
        reachability = {
            "switch": HostReachability(hostname="switch", active_ips=()),
        }
        result = validate_snmp_availability([host], reachability)
        assert len(result.violations) == 0

    def test_known_device_not_in_reachability(self):
        """Known device not in reachability map → no error."""
        host = _make_host("switch", hardware_type=HARDWARE_NETGEAR_SWITCH)
        reachability = {}  # switch not listed
        result = validate_snmp_availability([host], reachability)
        assert len(result.violations) == 0


class TestUnknownDevice:
    def test_unknown_hardware_no_snmp_ok(self):
        """Unknown device without SNMP → no error."""
        host = _make_host("desktop", hardware_type=None)
        reachability = {
            "desktop": HostReachability(
                hostname="desktop", active_ips=("10.1.10.100",)
            ),
        }
        result = validate_snmp_availability([host], reachability)
        assert len(result.violations) == 0


class TestNoReachabilityData:
    def test_no_reachability_skips_validation(self):
        """No reachability data → skip all validation."""
        host = _make_host("switch", hardware_type=HARDWARE_NETGEAR_SWITCH)
        result = validate_snmp_availability([host], reachability=None)
        assert len(result.violations) == 0


class TestMultipleHosts:
    def test_mixed_hosts(self):
        """Multiple hosts: only known UP devices without SNMP get errors."""
        hosts = [
            _make_host("switch-1", hardware_type=HARDWARE_NETGEAR_SWITCH),
            _make_host(
                "switch-2",
                hardware_type=HARDWARE_NETGEAR_SWITCH,
                snmp_data=_snmp_data(),
            ),
            _make_host("desktop", hardware_type=None),
            _make_host("switch-3", hardware_type=HARDWARE_NETGEAR_SWITCH),
        ]
        reachability = {
            "switch-1": HostReachability(
                hostname="switch-1", active_ips=("10.1.10.1",)
            ),
            "switch-2": HostReachability(
                hostname="switch-2", active_ips=("10.1.10.2",)
            ),
            "desktop": HostReachability(
                hostname="desktop", active_ips=("10.1.10.3",)
            ),
            "switch-3": HostReachability(hostname="switch-3", active_ips=()),
        }
        result = validate_snmp_availability(hosts, reachability)

        errors = result.errors
        assert len(errors) == 1
        assert errors[0].record_id == "switch-1"
