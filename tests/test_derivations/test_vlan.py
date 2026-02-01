"""Tests for IP → VLAN and IP → subdomain derivations."""

from gdoc2netcfg.derivations.vlan import ip_to_subdomain, ip_to_vlan_id
from gdoc2netcfg.models.addressing import IPv4Address
from gdoc2netcfg.models.network import VLAN, Site

# Build a site with the standard VLAN/subdomain configuration
# Uses spreadsheet-accurate data: VLAN 10 covers octets 8-15 (/21),
# VLANs 31=fpgas, 41=sm (matching spreadsheet names), both global.
SITE = Site(
    name="welland",
    domain="welland.mithis.com",
    site_octet=1,
    vlans={
        1: VLAN(id=1, name="tmp", subdomain="tmp", third_octets=(1,)),
        5: VLAN(id=5, name="net", subdomain="net", third_octets=(5,)),
        6: VLAN(id=6, name="pwr", subdomain="pwr", third_octets=(6,)),
        7: VLAN(id=7, name="store", subdomain="store", third_octets=(7,)),
        10: VLAN(id=10, name="int", subdomain="int", third_octets=(8, 9, 10, 11, 12, 13, 14, 15)),
        20: VLAN(id=20, name="roam", subdomain="roam", third_octets=(20,)),
        31: VLAN(id=31, name="fpgas", subdomain="fpgas", is_global=True),
        41: VLAN(id=41, name="sm", subdomain="sm", is_global=True),
        90: VLAN(id=90, name="iot", subdomain="iot", third_octets=(90,)),
        99: VLAN(id=99, name="guest", subdomain="guest", third_octets=(99,)),
    },
    network_subdomains={
        1: "tmp", 5: "net", 6: "pwr", 7: "store",
        8: "int", 9: "int", 10: "int", 11: "int",
        12: "int", 13: "int", 14: "int", 15: "int",
        20: "roam", 90: "iot", 99: "guest",
    },
)


class TestIpToVlanId:
    def test_tmp_vlan(self):
        assert ip_to_vlan_id(IPv4Address("10.1.1.1"), SITE) == 1

    def test_net_vlan(self):
        assert ip_to_vlan_id(IPv4Address("10.1.5.100"), SITE) == 5

    def test_pwr_vlan(self):
        assert ip_to_vlan_id(IPv4Address("10.1.6.1"), SITE) == 6

    def test_store_vlan(self):
        assert ip_to_vlan_id(IPv4Address("10.1.7.1"), SITE) == 7

    def test_int_vlan_range(self):
        """10.1.8-15.x all map to VLAN 10 (matches /21 CIDR)."""
        assert ip_to_vlan_id(IPv4Address("10.1.8.1"), SITE) == 10
        assert ip_to_vlan_id(IPv4Address("10.1.10.1"), SITE) == 10
        assert ip_to_vlan_id(IPv4Address("10.1.11.1"), SITE) == 10
        assert ip_to_vlan_id(IPv4Address("10.1.15.254"), SITE) == 10

    def test_int_vlan_boundary(self):
        """Octets just outside the /21 range should NOT match VLAN 10."""
        # Octet 7 is store, not int
        assert ip_to_vlan_id(IPv4Address("10.1.7.1"), SITE) == 7
        # Octet 16 is not covered by any VLAN
        assert ip_to_vlan_id(IPv4Address("10.1.16.1"), SITE) is None

    def test_roam_vlan(self):
        assert ip_to_vlan_id(IPv4Address("10.1.20.1"), SITE) == 20

    def test_iot_vlan(self):
        assert ip_to_vlan_id(IPv4Address("10.1.90.10"), SITE) == 90

    def test_guest_vlan(self):
        assert ip_to_vlan_id(IPv4Address("10.1.99.1"), SITE) == 99

    def test_fpgas_vlan(self):
        """10.31.x.x → VLAN 31 (fpgas) — global VLAN."""
        assert ip_to_vlan_id(IPv4Address("10.31.1.1"), SITE) == 31

    def test_sm_vlan(self):
        """10.41.x.x → VLAN 41 (sm) — global VLAN."""
        assert ip_to_vlan_id(IPv4Address("10.41.1.1"), SITE) == 41

    def test_non_10_returns_none(self):
        assert ip_to_vlan_id(IPv4Address("192.168.1.1"), SITE) is None

    def test_unknown_subnet_returns_none(self):
        assert ip_to_vlan_id(IPv4Address("10.1.50.1"), SITE) is None

    def test_non_site_second_octet_unknown(self):
        """10.2.x.x with Welland site_octet=1 returns None."""
        assert ip_to_vlan_id(IPv4Address("10.2.10.1"), SITE) is None


class TestIpToVlanIdMonarto:
    """VLAN lookup with Monarto site (site_octet=2)."""

    MONARTO = Site(
        name="monarto",
        domain="monarto.mithis.com",
        site_octet=2,
        vlans={
            5: VLAN(id=5, name="net", subdomain="net", third_octets=(5,)),
            10: VLAN(id=10, name="int", subdomain="int", third_octets=(8, 9, 10, 11, 12, 13, 14, 15)),
            31: VLAN(id=31, name="fpgas", subdomain="fpgas", is_global=True),
        },
        network_subdomains={5: "net", 8: "int", 9: "int", 10: "int", 11: "int", 12: "int", 13: "int", 14: "int", 15: "int"},
    )

    def test_monarto_site_vlan(self):
        """10.2.5.X maps to VLAN 5 for Monarto."""
        assert ip_to_vlan_id(IPv4Address("10.2.5.1"), self.MONARTO) == 5

    def test_monarto_int_vlan(self):
        """10.2.10.X maps to VLAN 10 for Monarto."""
        assert ip_to_vlan_id(IPv4Address("10.2.10.1"), self.MONARTO) == 10

    def test_monarto_global_vlan(self):
        """Global VLANs work regardless of site_octet."""
        assert ip_to_vlan_id(IPv4Address("10.31.1.1"), self.MONARTO) == 31

    def test_monarto_rejects_welland(self):
        """10.1.X.X is not valid for Monarto."""
        assert ip_to_vlan_id(IPv4Address("10.1.5.1"), self.MONARTO) is None


class TestIpToSubdomain:
    def test_int_subdomain(self):
        assert ip_to_subdomain(IPv4Address("10.1.10.124"), SITE) == "int"

    def test_iot_subdomain(self):
        assert ip_to_subdomain(IPv4Address("10.1.90.10"), SITE) == "iot"

    def test_net_subdomain(self):
        assert ip_to_subdomain(IPv4Address("10.1.5.100"), SITE) == "net"

    def test_int_shared_subdomain(self):
        """Multiple octets (8-15) map to 'int' via /21 CIDR."""
        assert ip_to_subdomain(IPv4Address("10.1.8.1"), SITE) == "int"
        assert ip_to_subdomain(IPv4Address("10.1.11.1"), SITE) == "int"
        assert ip_to_subdomain(IPv4Address("10.1.15.1"), SITE) == "int"

    def test_non_10_site_returns_none(self):
        assert ip_to_subdomain(IPv4Address("192.168.1.1"), SITE) is None
        assert ip_to_subdomain(IPv4Address("10.31.1.1"), SITE) is None

    def test_unmapped_octet_returns_none(self):
        assert ip_to_subdomain(IPv4Address("10.1.50.1"), SITE) is None

    def test_monarto_subdomain(self):
        """ip_to_subdomain uses site_octet, not hardcoded 1."""
        monarto = Site(
            name="monarto",
            domain="monarto.mithis.com",
            site_octet=2,
            network_subdomains={5: "net", 10: "int"},
        )
        assert ip_to_subdomain(IPv4Address("10.2.5.1"), monarto) == "net"
        assert ip_to_subdomain(IPv4Address("10.1.5.1"), monarto) is None
