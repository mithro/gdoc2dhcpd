"""Tests for device lookup utilities."""

from __future__ import annotations

import pytest

from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface
from gdoc2netcfg.utils.lookup import (
    CREDENTIAL_TYPES,
    LookupResult,
    _match_by_mac,
    available_credential_fields,
    detect_query_type,
    get_credential_fields,
    lookup_host,
    suggest_matches,
)


# --- Helpers ----------------------------------------------------------------

def _make_host(
    machine_name: str,
    hostname: str,
    ip: str = "10.1.10.1",
    mac: str = "aa:bb:cc:dd:ee:01",
    extra: dict[str, str] | None = None,
) -> Host:
    """Build a minimal Host for testing."""
    iface = NetworkInterface(
        name=None,
        mac=MACAddress(mac),
        ip_addresses=(IPv4Address(ip),),
    )
    return Host(
        machine_name=machine_name,
        hostname=hostname,
        interfaces=[iface],
        extra=extra or {},
    )


def _make_multi_iface_host(
    machine_name: str,
    hostname: str,
    interfaces: list[tuple[str | None, str, str]],
    extra: dict[str, str] | None = None,
) -> Host:
    """Build a Host with multiple interfaces.

    Each interface is (name, ip, mac).
    """
    ifaces = [
        NetworkInterface(
            name=name,
            mac=MACAddress(mac),
            ip_addresses=(IPv4Address(ip),),
        )
        for name, ip, mac in interfaces
    ]
    return Host(
        machine_name=machine_name,
        hostname=hostname,
        interfaces=ifaces,
        extra=extra or {},
    )


# --- TestDetectQueryType ----------------------------------------------------

class TestDetectQueryType:
    def test_mac_colon_format(self):
        assert detect_query_type("aa:bb:cc:dd:ee:ff") == "mac"

    def test_mac_colon_uppercase(self):
        assert detect_query_type("AA:BB:CC:DD:EE:FF") == "mac"

    def test_mac_dash_format(self):
        assert detect_query_type("aa-bb-cc-dd-ee-ff") == "mac"

    def test_mac_dot_format(self):
        assert detect_query_type("aabb.ccdd.eeff") == "mac"

    def test_ipv4(self):
        assert detect_query_type("10.1.10.1") == "ip"

    def test_ipv4_high_octets(self):
        assert detect_query_type("192.168.1.255") == "ip"

    def test_hostname_simple(self):
        assert detect_query_type("switch1") == "hostname"

    def test_hostname_fqdn(self):
        assert detect_query_type("switch1.net.welland.mithis.com") == "hostname"

    def test_hostname_with_dots_but_not_ip(self):
        assert detect_query_type("bmc.big-storage") == "hostname"

    def test_whitespace_stripped(self):
        assert detect_query_type("  10.1.10.1  ") == "ip"


# --- TestMatchByHostname ----------------------------------------------------

class TestMatchByHostname:
    @pytest.fixture
    def hosts(self):
        return [
            _make_host("switch1", "switch1.net.welland.mithis.com",
                        ip="10.1.30.1", mac="aa:bb:cc:dd:ee:01"),
            _make_host("desktop", "desktop.int.welland.mithis.com",
                        ip="10.1.10.2", mac="aa:bb:cc:dd:ee:02"),
            _make_host("big-storage", "big-storage.int.welland.mithis.com",
                        ip="10.1.10.3", mac="aa:bb:cc:dd:ee:03"),
            _make_host("switch10", "switch10.net.welland.mithis.com",
                        ip="10.1.30.10", mac="aa:bb:cc:dd:ee:04"),
        ]

    def test_exact_hostname_match(self, hosts):
        results = lookup_host(
            "switch1.net.welland.mithis.com", hosts, "welland.mithis.com",
        )
        assert len(results) == 1
        assert results[0].host.hostname == "switch1.net.welland.mithis.com"
        assert results[0].match_type == "exact"

    def test_exact_machine_name_match(self, hosts):
        results = lookup_host("switch1", hosts, "welland.mithis.com")
        assert len(results) >= 1
        assert results[0].host.machine_name == "switch1"
        assert results[0].match_type == "exact"

    def test_case_insensitive(self, hosts):
        results = lookup_host("SWITCH1", hosts, "welland.mithis.com")
        assert len(results) >= 1
        assert results[0].host.machine_name == "switch1"

    def test_prefix_match(self, hosts):
        results = lookup_host("desktop", hosts, "welland.mithis.com")
        # "desktop" exactly matches machine_name, so it's exact
        assert results[0].match_type == "exact"

    def test_prefix_match_domain_stripping(self, hosts):
        """Query like 'switch1' that has exact machine_name match AND prefix."""
        results = lookup_host("switch1", hosts, "welland.mithis.com")
        # Exact match on machine_name comes first
        assert results[0].host.machine_name == "switch1"
        assert results[0].match_type == "exact"

    def test_substring_match(self, hosts):
        results = lookup_host("storage", hosts, "welland.mithis.com")
        assert len(results) == 1
        assert results[0].host.machine_name == "big-storage"
        assert results[0].match_type == "substring"

    def test_ordering_exact_before_prefix_before_substring(self, hosts):
        """'switch1' should match: exact(switch1), prefix(switch1.net..),
        then substring(switch10) should come last."""
        results = lookup_host("switch1", hosts, "welland.mithis.com")
        types = [r.match_type for r in results]
        # Exact first, then possibly substring for switch10
        assert types[0] == "exact"
        # switch10 contains "switch1" as substring
        if len(results) > 1:
            assert results[-1].match_type == "substring"
            assert results[-1].host.machine_name == "switch10"

    def test_no_match(self, hosts):
        results = lookup_host("nonexistent", hosts, "welland.mithis.com")
        assert results == []


# --- TestMatchByIP ----------------------------------------------------------

class TestMatchByIP:
    @pytest.fixture
    def hosts(self):
        return [
            _make_host("switch1", "switch1.net.welland.mithis.com",
                        ip="10.1.30.1", mac="aa:bb:cc:dd:ee:01"),
            _make_host("server1", "server1.int.welland.mithis.com",
                        ip="10.1.10.5", mac="aa:bb:cc:dd:ee:02"),
        ]

    def test_exact_ip_match(self, hosts):
        results = lookup_host("10.1.30.1", hosts, "welland.mithis.com")
        assert len(results) == 1
        assert results[0].host.machine_name == "switch1"
        assert results[0].match_type == "exact"

    def test_wildcard_second_octet(self, hosts):
        # Query with different second octet (e.g., Monarto IP 10.2.30.1
        # matching Welland host at 10.1.30.1)
        results = lookup_host("10.2.30.1", hosts, "welland.mithis.com")
        assert len(results) == 1
        assert results[0].host.machine_name == "switch1"
        assert results[0].match_type == "wildcard"

    def test_exact_before_wildcard(self, hosts):
        """If a host has exact match, it comes before wildcard matches."""
        results = lookup_host("10.1.30.1", hosts, "welland.mithis.com")
        assert results[0].match_type == "exact"

    def test_no_match(self, hosts):
        results = lookup_host("10.1.99.99", hosts, "welland.mithis.com")
        assert results == []


# --- TestMatchByMAC ---------------------------------------------------------

class TestMatchByMAC:
    @pytest.fixture
    def hosts(self):
        return [
            _make_host("switch1", "switch1.net.welland.mithis.com",
                        ip="10.1.30.1", mac="aa:bb:cc:dd:ee:01"),
            _make_host("server1", "server1.int.welland.mithis.com",
                        ip="10.1.10.5", mac="11:22:33:44:55:66"),
        ]

    def test_exact_mac_match(self, hosts):
        results = lookup_host("aa:bb:cc:dd:ee:01", hosts, "welland.mithis.com")
        assert len(results) == 1
        assert results[0].host.machine_name == "switch1"
        assert results[0].match_type == "exact"

    def test_dash_format_normalized(self, hosts):
        results = lookup_host("aa-bb-cc-dd-ee-01", hosts, "welland.mithis.com")
        assert len(results) == 1
        assert results[0].host.machine_name == "switch1"

    def test_dot_format_normalized(self, hosts):
        results = lookup_host("aabb.ccdd.ee01", hosts, "welland.mithis.com")
        assert len(results) == 1
        assert results[0].host.machine_name == "switch1"

    def test_uppercase_mac(self, hosts):
        results = lookup_host("AA:BB:CC:DD:EE:01", hosts, "welland.mithis.com")
        assert len(results) == 1
        assert results[0].host.machine_name == "switch1"

    def test_no_match(self, hosts):
        results = lookup_host("ff:ff:ff:ff:ff:ff", hosts, "welland.mithis.com")
        assert results == []

    def test_invalid_mac_raises(self, hosts):
        """An invalid MAC passed directly to _match_by_mac raises ValueError."""
        with pytest.raises(ValueError):
            _match_by_mac("not-a-mac", hosts)

    def test_invalid_mac_detected_as_hostname(self, hosts):
        """A MAC-like string with non-hex chars is treated as hostname."""
        # 'zz' is not valid hex, so detect_query_type classifies as hostname
        results = lookup_host("zz:zz:zz:zz:zz:zz", hosts, "welland.mithis.com")
        assert results == []


# --- TestSuggestMatches -----------------------------------------------------

class TestSuggestMatches:
    def test_close_hostname(self):
        hosts = [
            _make_host("switch1", "switch1.net.welland.mithis.com",
                        ip="10.1.30.1", mac="aa:bb:cc:dd:ee:01"),
            _make_host("switch2", "switch2.net.welland.mithis.com",
                        ip="10.1.30.2", mac="aa:bb:cc:dd:ee:02"),
        ]
        suggestions = suggest_matches("swtich1", hosts)
        assert len(suggestions) > 0
        assert "switch1" in suggestions

    def test_max_limit(self):
        hosts = [
            _make_host(f"host{i}", f"host{i}.test.com",
                        ip=f"10.1.10.{i}", mac=f"aa:bb:cc:dd:ee:{i:02x}")
            for i in range(1, 20)
        ]
        suggestions = suggest_matches("host", hosts, max_suggestions=3)
        assert len(suggestions) <= 3

    def test_no_close_matches(self):
        hosts = [
            _make_host("alpha", "alpha.test.com",
                        ip="10.1.10.1", mac="aa:bb:cc:dd:ee:01"),
        ]
        suggestions = suggest_matches("zzzzzzzzzzz", hosts)
        assert suggestions == []


# --- TestGetCredentialFields ------------------------------------------------

class TestGetCredentialFields:
    def test_password_type(self):
        host = _make_host("switch1", "switch1", extra={"Password": "secret123"})
        result = get_credential_fields(host, credential_type="password")
        assert result == {"Password": "secret123"}

    def test_snmp_type(self):
        host = _make_host("switch1", "switch1",
                          extra={"SNMP Community": "public"})
        result = get_credential_fields(host, credential_type="snmp")
        assert result == {"SNMP Community": "public"}

    def test_ipmi_type(self):
        host = _make_host("server1", "server1", extra={
            "IPMI Username": "admin",
            "IPMI Password": "hunter2",
        })
        result = get_credential_fields(host, credential_type="ipmi")
        assert result == {"IPMI Username": "admin", "IPMI Password": "hunter2"}

    def test_ipmi_partial(self):
        """If only username is set, only that field is returned."""
        host = _make_host("server1", "server1", extra={
            "IPMI Username": "admin",
        })
        result = get_credential_fields(host, credential_type="ipmi")
        assert result == {"IPMI Username": "admin"}

    def test_default_is_password(self):
        host = _make_host("switch1", "switch1", extra={"Password": "secret"})
        result = get_credential_fields(host)
        assert result == {"Password": "secret"}

    def test_arbitrary_field(self):
        host = _make_host("switch1", "switch1",
                          extra={"Custom Field": "custom_val"})
        result = get_credential_fields(host, field_name="Custom Field")
        assert result == {"Custom Field": "custom_val"}

    def test_missing_field_returns_empty(self):
        host = _make_host("switch1", "switch1", extra={})
        result = get_credential_fields(host, credential_type="password")
        assert result == {}

    def test_blank_field_returns_empty(self):
        host = _make_host("switch1", "switch1", extra={"Password": ""})
        result = get_credential_fields(host, credential_type="password")
        assert result == {}

    def test_unknown_type_raises(self):
        host = _make_host("switch1", "switch1")
        with pytest.raises(ValueError, match="Unknown credential type"):
            get_credential_fields(host, credential_type="bogus")

    def test_missing_arbitrary_field(self):
        host = _make_host("switch1", "switch1", extra={})
        result = get_credential_fields(host, field_name="Nonexistent")
        assert result == {}


# --- TestAvailableCredentialFields ------------------------------------------

class TestAvailableCredentialFields:
    def test_non_empty_fields(self):
        host = _make_host("switch1", "switch1", extra={
            "Password": "secret",
            "SNMP Community": "public",
            "Notes": "",
        })
        available = available_credential_fields(host)
        assert "Password" in available
        assert "SNMP Community" in available
        assert "Notes" not in available

    def test_empty_extra(self):
        host = _make_host("switch1", "switch1", extra={})
        assert available_credential_fields(host) == []

    def test_all_blank(self):
        host = _make_host("switch1", "switch1", extra={
            "Password": "",
            "SNMP Community": "",
        })
        assert available_credential_fields(host) == []
