"""Tests for the tc MAC-based VLAN generator."""

from gdoc2netcfg.generators.tc_mac_vlan import generate_tc_mac_vlan
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, NetworkInventory
from gdoc2netcfg.models.network import VLAN, Site

SITE = Site(
    name="welland",
    domain="welland.mithis.com",
    vlans={10: VLAN(id=10, name="int", subdomain="int")},
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


class TestTcMacVlanGenerator:
    def test_generates_bash_script(self):
        hosts = [_host("aa:bb:cc:dd:ee:01", "10.1.10.1", 10)]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_tc_mac_vlan(inv)

        assert output.startswith("#!/bin/bash")

    def test_sets_up_clsact_qdisc(self):
        hosts = [_host("aa:bb:cc:dd:ee:01", "10.1.10.1", 10)]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_tc_mac_vlan(inv)

        assert "tc qdisc del dev br-raw clsact" in output
        assert "tc qdisc add dev br-raw clsact" in output

    def test_pass_tagged_traffic(self):
        hosts = [_host("aa:bb:cc:dd:ee:01", "10.1.10.1", 10)]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_tc_mac_vlan(inv)

        assert "protocol 802.1Q flower action pass" in output

    def test_ingress_rules(self):
        hosts = [_host("aa:bb:cc:dd:ee:01", "10.1.10.1", 10, "desktop")]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_tc_mac_vlan(inv)

        assert "src_mac aa:bb:cc:dd:ee:01 action vlan push id 10" in output

    def test_egress_rules(self):
        hosts = [_host("aa:bb:cc:dd:ee:01", "10.1.10.1", 10, "desktop")]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_tc_mac_vlan(inv)

        assert "dst_mac aa:bb:cc:dd:ee:01 action vlan pop" in output

    def test_custom_bridge_name(self):
        hosts = [_host("aa:bb:cc:dd:ee:01", "10.1.10.1", 10)]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_tc_mac_vlan(inv, bridge="br-custom")

        assert "br-custom" in output
        assert "br-raw" not in output

    def test_skips_bridge_macs(self):
        hosts = [_host("02:00:0a:01:10:01", "10.1.10.1", 10)]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_tc_mac_vlan(inv)

        assert "02:00:0a:01:10:01" not in output
