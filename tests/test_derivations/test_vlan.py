"""Tests for IP → VLAN and IP → subdomain derivations."""

from gdoc2netcfg.derivations.vlan import ip_to_subdomain, ip_to_vlan_id
from gdoc2netcfg.models.addressing import IPv4Address
from gdoc2netcfg.models.network import VLAN, Site

# Build a site with the standard VLAN/subdomain configuration
SITE = Site(
    name="welland",
    domain="welland.mithis.com",
    vlans={
        1: VLAN(id=1, name="tmp", subdomain="tmp"),
        5: VLAN(id=5, name="net", subdomain="net"),
        6: VLAN(id=6, name="pwr", subdomain="pwr"),
        10: VLAN(id=10, name="int", subdomain="int"),
        20: VLAN(id=20, name="roam", subdomain="roam"),
        31: VLAN(id=31, name="sm", subdomain="sm"),
        41: VLAN(id=41, name="fpgas", subdomain="fpgas"),
        90: VLAN(id=90, name="iot", subdomain="iot"),
        99: VLAN(id=99, name="guest", subdomain="guest"),
    },
    network_subdomains={
        1: "tmp", 5: "net", 6: "pwr",
        10: "int", 11: "int", 15: "int", 16: "int",
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

    def test_int_vlan_range(self):
        """10.1.10-17.x all map to VLAN 10."""
        assert ip_to_vlan_id(IPv4Address("10.1.10.1"), SITE) == 10
        assert ip_to_vlan_id(IPv4Address("10.1.11.1"), SITE) == 10
        assert ip_to_vlan_id(IPv4Address("10.1.15.1"), SITE) == 10
        assert ip_to_vlan_id(IPv4Address("10.1.17.1"), SITE) == 10

    def test_roam_vlan(self):
        assert ip_to_vlan_id(IPv4Address("10.1.20.1"), SITE) == 20

    def test_iot_vlan(self):
        assert ip_to_vlan_id(IPv4Address("10.1.90.10"), SITE) == 90

    def test_guest_vlan(self):
        assert ip_to_vlan_id(IPv4Address("10.1.99.1"), SITE) == 99

    def test_sm_vlan(self):
        """10.31.x.x → VLAN 31 (Supermicro test)."""
        assert ip_to_vlan_id(IPv4Address("10.31.1.1"), SITE) == 31

    def test_fpgas_vlan(self):
        """10.41.x.x → VLAN 41 (FPGA test)."""
        assert ip_to_vlan_id(IPv4Address("10.41.1.1"), SITE) == 41

    def test_non_10_returns_none(self):
        assert ip_to_vlan_id(IPv4Address("192.168.1.1"), SITE) is None

    def test_unknown_subnet_returns_none(self):
        assert ip_to_vlan_id(IPv4Address("10.1.50.1"), SITE) is None

    def test_non_1_second_octet_unknown(self):
        """10.2.x.x with unknown second octet returns None."""
        assert ip_to_vlan_id(IPv4Address("10.2.10.1"), SITE) is None


class TestIpToSubdomain:
    def test_int_subdomain(self):
        assert ip_to_subdomain(IPv4Address("10.1.10.124"), SITE) == "int"

    def test_iot_subdomain(self):
        assert ip_to_subdomain(IPv4Address("10.1.90.10"), SITE) == "iot"

    def test_net_subdomain(self):
        assert ip_to_subdomain(IPv4Address("10.1.5.100"), SITE) == "net"

    def test_int_shared_subdomain(self):
        """Multiple octets (10, 11, 15, 16) map to 'int'."""
        assert ip_to_subdomain(IPv4Address("10.1.11.1"), SITE) == "int"
        assert ip_to_subdomain(IPv4Address("10.1.15.1"), SITE) == "int"
        assert ip_to_subdomain(IPv4Address("10.1.16.1"), SITE) == "int"

    def test_non_10_1_returns_none(self):
        assert ip_to_subdomain(IPv4Address("192.168.1.1"), SITE) is None
        assert ip_to_subdomain(IPv4Address("10.31.1.1"), SITE) is None

    def test_unmapped_octet_returns_none(self):
        assert ip_to_subdomain(IPv4Address("10.1.50.1"), SITE) is None
