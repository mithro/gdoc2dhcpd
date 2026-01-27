"""Tests for IPv4 → IPv6 derivation.

Ported from the doctests in dnsmasq.py:ipv4_to_ipv6_list().
"""

from gdoc2netcfg.derivations.ipv6 import ipv4_to_ipv6, ipv4_to_ipv6_list
from gdoc2netcfg.models.addressing import IPv4Address
from gdoc2netcfg.models.network import IPv6Prefix

LAUNTEL = IPv6Prefix(prefix="2404:e80:a137:", name="Launtel")
HENET = IPv6Prefix(prefix="2001:470:82b3:", name="HE.net")
HENET_DISABLED = IPv6Prefix(prefix="2001:470:82b3:", name="HE.net", enabled=False)


class TestIpv4ToIpv6:
    def test_basic_mapping(self):
        """10.1.10.124 → 2404:e80:a137:110::124"""
        result = ipv4_to_ipv6(IPv4Address("10.1.10.124"), LAUNTEL)
        assert result is not None
        assert str(result) == "2404:e80:a137:110::124"
        assert result.prefix == "2404:e80:a137:"

    def test_zero_padded_third_octet(self):
        """Third octet is zero-padded to 2 digits: 10.1.5.1 → ...105::1"""
        result = ipv4_to_ipv6(IPv4Address("10.1.5.1"), LAUNTEL)
        assert str(result) == "2404:e80:a137:105::1"

    def test_large_octets(self):
        """10.12.80.240 → 2404:e80:a137:1280::240"""
        result = ipv4_to_ipv6(IPv4Address("10.12.80.240"), LAUNTEL)
        assert str(result) == "2404:e80:a137:1280::240"

    def test_non_10_network_returns_none(self):
        """Only 10.x.x.x addresses are mappable."""
        result = ipv4_to_ipv6(IPv4Address("192.168.1.1"), LAUNTEL)
        assert result is None

    def test_different_prefix(self):
        result = ipv4_to_ipv6(IPv4Address("10.1.10.124"), HENET)
        assert str(result) == "2001:470:82b3:110::124"

    def test_single_digit_second_octet(self):
        """Second octet is not padded: 10.1.90.10 → ...190::10"""
        result = ipv4_to_ipv6(IPv4Address("10.1.90.10"), LAUNTEL)
        assert str(result) == "2404:e80:a137:190::10"


class TestIpv4ToIpv6List:
    def test_single_prefix(self):
        result = ipv4_to_ipv6_list(IPv4Address("10.1.10.124"), [LAUNTEL])
        assert len(result) == 1
        assert str(result[0]) == "2404:e80:a137:110::124"

    def test_dual_prefix(self):
        result = ipv4_to_ipv6_list(IPv4Address("10.1.10.124"), [LAUNTEL, HENET])
        assert len(result) == 2
        assert str(result[0]) == "2404:e80:a137:110::124"
        assert str(result[1]) == "2001:470:82b3:110::124"

    def test_disabled_prefix_skipped(self):
        result = ipv4_to_ipv6_list(
            IPv4Address("10.1.10.124"), [LAUNTEL, HENET_DISABLED]
        )
        assert len(result) == 1

    def test_non_mappable_returns_empty(self):
        result = ipv4_to_ipv6_list(IPv4Address("192.168.1.1"), [LAUNTEL])
        assert result == []

    def test_no_prefixes_returns_empty(self):
        result = ipv4_to_ipv6_list(IPv4Address("10.1.10.124"), [])
        assert result == []
