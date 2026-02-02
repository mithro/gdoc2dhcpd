"""Tests for VLAN builder: VLANDefinition → VLAN model objects."""

from gdoc2netcfg.derivations.vlan import (
    _is_global_vlan,
    build_network_subdomains,
    build_vlans_from_definitions,
)
from gdoc2netcfg.sources.vlan_parser import VLANDefinition


def _welland_definitions() -> list[VLANDefinition]:
    """Sample VLANDefinitions matching the Welland VLAN Allocations sheet."""
    return [
        VLANDefinition(
            id=1, name="tmp", ip_range="10.1.1.X",
            netmask="255.255.255.0", cidr="/24",
        ),
        VLANDefinition(
            id=5, name="net", ip_range="10.1.5.X",
            netmask="255.255.255.0", cidr="/24",
        ),
        VLANDefinition(
            id=6, name="pwr", ip_range="10.1.6.X",
            netmask="255.255.255.0", cidr="/24",
        ),
        VLANDefinition(
            id=7, name="store", ip_range="10.1.7.X",
            netmask="255.255.255.0", cidr="/24",
        ),
        VLANDefinition(
            id=10, name="int", ip_range="10.1.10.X",
            netmask="255.255.248.0", cidr="/21",
        ),
        VLANDefinition(
            id=20, name="roam", ip_range="10.1.20.X",
            netmask="255.255.255.0", cidr="/24",
        ),
        VLANDefinition(
            id=31, name="fpgas", ip_range="10.31.X.X",
            netmask="255.255.0.0", cidr="/16",
        ),
        VLANDefinition(
            id=41, name="sm", ip_range="10.41.X.X",
            netmask="255.255.0.0", cidr="/16",
        ),
        VLANDefinition(
            id=90, name="iot", ip_range="10.1.90.X",
            netmask="255.255.255.0", cidr="/24",
        ),
        VLANDefinition(
            id=99, name="guest", ip_range="10.1.99.X",
            netmask="255.255.255.0", cidr="/24",
        ),
    ]


class TestIsGlobalVlan:
    """Unit tests for CIDR-based global VLAN detection."""

    def test_slash_16_is_global(self):
        assert _is_global_vlan("/16") is True

    def test_slash_8_is_global(self):
        assert _is_global_vlan("/8") is True

    def test_slash_24_is_site_local(self):
        assert _is_global_vlan("/24") is False

    def test_slash_21_is_site_local(self):
        assert _is_global_vlan("/21") is False

    def test_slash_17_is_site_local(self):
        assert _is_global_vlan("/17") is False

    def test_empty_string(self):
        assert _is_global_vlan("") is False

    def test_invalid_cidr(self):
        assert _is_global_vlan("/abc") is False

    def test_missing_leading_slash(self):
        assert _is_global_vlan("16") is False

    def test_negative_prefix(self):
        assert _is_global_vlan("/-1") is False

    def test_prefix_out_of_ipv4_range(self):
        assert _is_global_vlan("/33") is False


class TestBuildVlansFromDefinitions:
    def test_builds_all_vlans(self):
        vlans = build_vlans_from_definitions(_welland_definitions(), site_octet=1)
        assert len(vlans) == 10

    def test_vlan_ids(self):
        vlans = build_vlans_from_definitions(_welland_definitions(), site_octet=1)
        assert sorted(vlans.keys()) == [1, 5, 6, 7, 10, 20, 31, 41, 90, 99]

    def test_vlan_names(self):
        vlans = build_vlans_from_definitions(_welland_definitions(), site_octet=1)
        assert vlans[5].name == "net"
        assert vlans[10].name == "int"
        assert vlans[31].name == "fpgas"
        assert vlans[41].name == "sm"

    def test_subdomain_equals_name(self):
        vlans = build_vlans_from_definitions(_welland_definitions(), site_octet=1)
        for vlan in vlans.values():
            assert vlan.subdomain == vlan.name

    def test_simple_vlan_third_octets(self):
        """A /24 VLAN covers a single third octet."""
        vlans = build_vlans_from_definitions(_welland_definitions(), site_octet=1)
        assert vlans[5].third_octets == (5,)
        assert vlans[1].third_octets == (1,)
        assert vlans[20].third_octets == (20,)
        assert vlans[90].third_octets == (90,)
        assert vlans[99].third_octets == (99,)

    def test_int_vlan_covers_octets_8_to_15(self):
        """VLAN 10 (int) with /21 should cover third octets 8-15."""
        vlans = build_vlans_from_definitions(_welland_definitions(), site_octet=1)
        assert vlans[10].third_octets == (8, 9, 10, 11, 12, 13, 14, 15)

    def test_global_vlans_detected(self):
        """VLANs 31 and 41 are global (/16 prefix)."""
        vlans = build_vlans_from_definitions(_welland_definitions(), site_octet=1)
        assert vlans[31].is_global is True
        assert vlans[41].is_global is True

    def test_site_vlans_not_global(self):
        vlans = build_vlans_from_definitions(_welland_definitions(), site_octet=1)
        for vid in [1, 5, 6, 7, 10, 20, 90, 99]:
            assert vlans[vid].is_global is False, f"VLAN {vid} should not be global"

    def test_global_vlans_empty_third_octets(self):
        vlans = build_vlans_from_definitions(_welland_definitions(), site_octet=1)
        assert vlans[31].third_octets == ()
        assert vlans[41].third_octets == ()

    def test_covered_third_octets_property(self):
        vlans = build_vlans_from_definitions(_welland_definitions(), site_octet=1)
        # Site VLANs use their third_octets
        assert vlans[5].covered_third_octets == (5,)
        assert vlans[10].covered_third_octets == (8, 9, 10, 11, 12, 13, 14, 15)
        # Global VLANs return empty
        assert vlans[31].covered_third_octets == ()

    def test_monarto_uses_same_definitions(self):
        """Welland definitions work for monarto (site_octet=2) without changes.

        Global VLANs are detected by /16 CIDR, not by comparing the IP
        range's second octet to site_octet.  This means the shared VLAN
        Allocations sheet (which has 10.1.X.X IP ranges) produces correct
        results for any site.
        """
        vlans = build_vlans_from_definitions(_welland_definitions(), site_octet=2)

        # All 10 VLANs built
        assert len(vlans) == 10

        # Site-local VLANs: same third octets regardless of site_octet
        assert vlans[5].is_global is False
        assert vlans[5].third_octets == (5,)
        assert vlans[10].is_global is False
        assert vlans[10].third_octets == (8, 9, 10, 11, 12, 13, 14, 15)
        assert vlans[90].is_global is False
        assert vlans[90].third_octets == (90,)

        # Global VLANs: still detected by /16 CIDR
        assert vlans[31].is_global is True
        assert vlans[31].third_octets == ()
        assert vlans[41].is_global is True
        assert vlans[41].third_octets == ()


class TestBuildNetworkSubdomains:
    def test_maps_all_covered_octets(self):
        vlans = build_vlans_from_definitions(_welland_definitions(), site_octet=1)
        subdomains = build_network_subdomains(vlans)

        # Simple VLANs: third octet == VLAN id
        assert subdomains[1] == "tmp"
        assert subdomains[5] == "net"
        assert subdomains[6] == "pwr"
        assert subdomains[7] == "store"
        assert subdomains[20] == "roam"
        assert subdomains[90] == "iot"
        assert subdomains[99] == "guest"

    def test_int_vlan_maps_all_octets(self):
        """VLAN 10 (int) should map octets 8-15 to 'int'."""
        vlans = build_vlans_from_definitions(_welland_definitions(), site_octet=1)
        subdomains = build_network_subdomains(vlans)

        for octet in range(8, 16):
            assert subdomains[octet] == "int", f"Octet {octet} should map to 'int'"

    def test_global_vlans_not_in_subdomains(self):
        """Global VLANs (31, 41) should not appear in subdomains mapping."""
        vlans = build_vlans_from_definitions(_welland_definitions(), site_octet=1)
        subdomains = build_network_subdomains(vlans)

        # No third-octet mapping for global VLANs
        assert 31 not in subdomains
        assert 41 not in subdomains

    def test_unmapped_octets_absent(self):
        vlans = build_vlans_from_definitions(_welland_definitions(), site_octet=1)
        subdomains = build_network_subdomains(vlans)

        assert 50 not in subdomains
        assert 100 not in subdomains
