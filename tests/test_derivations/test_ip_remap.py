"""Tests for IPv4 site remapping."""

from gdoc2netcfg.derivations.ip_remap import remap_ipv4_to_site
from gdoc2netcfg.models.addressing import IPv4Address
from gdoc2netcfg.models.network import VLAN, Site


def _site(site_octet: int) -> Site:
    """Build a minimal Site with typical VLANs for testing."""
    return Site(
        name="test",
        domain="test.mithis.com",
        site_octet=site_octet,
        vlans={
            5: VLAN(id=5, name="net", subdomain="net", third_octets=(5,)),
            10: VLAN(id=10, name="int", subdomain="int",
                     third_octets=(8, 9, 10, 11, 12, 13, 14, 15)),
            90: VLAN(id=90, name="iot", subdomain="iot", third_octets=(90,)),
            31: VLAN(id=31, name="fpgas", subdomain="fpgas",
                     third_octets=(), is_global=True),
            41: VLAN(id=41, name="sm", subdomain="sm",
                     third_octets=(), is_global=True),
        },
    )


class TestRemapIpv4ToSite:
    """Core remapping behaviour."""

    def test_welland_ip_remapped_to_monarto(self):
        """10.1.10.124 → 10.2.10.124 when site_octet=2."""
        site = _site(site_octet=2)
        result = remap_ipv4_to_site(IPv4Address("10.1.10.124"), site)
        assert str(result) == "10.2.10.124"

    def test_monarto_ip_unchanged_on_monarto(self):
        """10.2.10.124 stays 10.2.10.124 when site_octet=2."""
        site = _site(site_octet=2)
        result = remap_ipv4_to_site(IPv4Address("10.2.10.124"), site)
        assert str(result) == "10.2.10.124"

    def test_welland_ip_unchanged_on_welland(self):
        """10.1.10.124 stays 10.1.10.124 when site_octet=1."""
        site = _site(site_octet=1)
        result = remap_ipv4_to_site(IPv4Address("10.1.10.124"), site)
        assert str(result) == "10.1.10.124"

    def test_monarto_ip_remapped_to_welland(self):
        """10.2.90.5 → 10.1.90.5 when site_octet=1."""
        site = _site(site_octet=1)
        result = remap_ipv4_to_site(IPv4Address("10.2.90.5"), site)
        assert str(result) == "10.1.90.5"


class TestRemapPreservesGlobalVlans:
    """Global VLAN addresses must not be remapped."""

    def test_fpgas_vlan_untouched(self):
        """10.31.0.101 stays 10.31.0.101 regardless of site_octet."""
        site = _site(site_octet=2)
        result = remap_ipv4_to_site(IPv4Address("10.31.0.101"), site)
        assert str(result) == "10.31.0.101"

    def test_sm_vlan_untouched(self):
        """10.41.1.18 stays 10.41.1.18."""
        site = _site(site_octet=2)
        result = remap_ipv4_to_site(IPv4Address("10.41.1.18"), site)
        assert str(result) == "10.41.1.18"

    def test_fpgas_untouched_on_welland(self):
        site = _site(site_octet=1)
        result = remap_ipv4_to_site(IPv4Address("10.31.0.101"), site)
        assert str(result) == "10.31.0.101"


class TestRemapNonTenAddresses:
    """Non-10.X.X.X addresses pass through unchanged."""

    def test_private_172(self):
        site = _site(site_octet=2)
        result = remap_ipv4_to_site(IPv4Address("172.16.1.1"), site)
        assert str(result) == "172.16.1.1"

    def test_public_ip(self):
        site = _site(site_octet=2)
        result = remap_ipv4_to_site(IPv4Address("8.8.8.8"), site)
        assert str(result) == "8.8.8.8"

    def test_loopback(self):
        site = _site(site_octet=2)
        result = remap_ipv4_to_site(IPv4Address("127.0.0.1"), site)
        assert str(result) == "127.0.0.1"


class TestRemapPreservesThirdAndFourthOctets:
    """Remapping only changes the second octet."""

    def test_various_third_octets(self):
        site = _site(site_octet=2)
        for third in [1, 5, 6, 7, 10, 20, 90, 99]:
            result = remap_ipv4_to_site(
                IPv4Address(f"10.1.{third}.200"), site
            )
            assert str(result) == f"10.2.{third}.200"

    def test_fourth_octet_preserved(self):
        site = _site(site_octet=2)
        for fourth in [1, 100, 200, 254]:
            result = remap_ipv4_to_site(
                IPv4Address(f"10.1.90.{fourth}"), site
            )
            assert str(result) == f"10.2.90.{fourth}"
