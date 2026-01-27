"""Tests for the Cisco SG300 generator."""

from gdoc2netcfg.generators.cisco_sg300 import generate_cisco_sg300
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, NetworkInventory
from gdoc2netcfg.models.network import VLAN, Site

SITE = Site(
    name="welland",
    domain="welland.mithis.com",
    vlans={
        10: VLAN(id=10, name="int", subdomain="int"),
        90: VLAN(id=90, name="iot", subdomain="iot"),
    },
)


def _host(mac, ip, vlan_id, dhcp_name="test"):
    return Host(
        machine_name=dhcp_name,
        hostname=dhcp_name,
        interfaces=[
            NetworkInterface(
                name=None,
                mac=MACAddress.parse(mac),
                ipv4=IPv4Address(ip),
                vlan_id=vlan_id,
                dhcp_name=dhcp_name,
            )
        ],
    )


class TestCiscoSG300Generator:
    def test_generates_vlan_database(self):
        hosts = [_host("aa:bb:cc:dd:ee:01", "10.1.10.1", 10)]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_cisco_sg300(inv)

        assert "vlan database" in output
        assert "vlan 10" in output

    def test_generates_mac_mappings(self):
        hosts = [_host("aa:bb:cc:dd:ee:01", "10.1.10.1", 10)]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_cisco_sg300(inv)

        assert "map mac aa:bb:cc:dd:ee:01 48 macs-group 10" in output

    def test_generates_clear_commands(self):
        hosts = [_host("aa:bb:cc:dd:ee:01", "10.1.10.1", 10)]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_cisco_sg300(inv)

        assert "no map mac aa:bb:cc:dd:ee:01 48" in output

    def test_generates_interface_config(self):
        hosts = [_host("aa:bb:cc:dd:ee:01", "10.1.10.1", 10)]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_cisco_sg300(inv)

        assert "interface range gigabitethernet1-28" in output
        assert "switchport mode general" in output
        assert "switchport general allowed vlan add 10 tagged" in output
        assert "switchport general map macs-group 10 vlan 10" in output

    def test_skips_bridge_macs(self):
        hosts = [_host("02:00:0a:01:10:01", "10.1.10.1", 10)]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_cisco_sg300(inv)

        assert "02:00:0a:01:10:01" not in output

    def test_multiple_vlans(self):
        hosts = [
            _host("aa:bb:cc:dd:ee:01", "10.1.10.1", 10, "desktop"),
            _host("aa:bb:cc:dd:ee:02", "10.1.90.1", 90, "thermostat"),
        ]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_cisco_sg300(inv)

        assert "vlan 10" in output
        assert "vlan 90" in output
        assert "macs-group 10" in output
        assert "macs-group 90" in output

    def test_optimization_count_in_header(self):
        hosts = [_host("aa:bb:cc:dd:ee:01", "10.1.10.1", 10)]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_cisco_sg300(inv)

        assert "1 MACs optimized to 1 entries" in output
