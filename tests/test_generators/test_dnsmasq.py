"""Tests for the dnsmasq internal generator."""

from gdoc2netcfg.derivations.dns_names import derive_all_dns_names
from gdoc2netcfg.generators.dnsmasq import generate_dnsmasq_internal
from gdoc2netcfg.models.addressing import IPv4Address, IPv6Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, NetworkInventory
from gdoc2netcfg.models.network import IPv6Prefix, Site

SITE = Site(
    name="welland",
    domain="welland.mithis.com",
    ipv6_prefixes=[IPv6Prefix(prefix="2404:e80:a137:", name="Launtel")],
    network_subdomains={10: "int"},
)


def _make_inventory(hosts=None, ip_to_hostname=None, ip_to_macs=None):
    return NetworkInventory(
        site=SITE,
        hosts=hosts or [],
        ip_to_hostname=ip_to_hostname or {},
        ip_to_macs=ip_to_macs or {},
    )


def _host_with_iface(hostname, mac, ip, interface_name=None, dhcp_name="test"):
    ipv4 = IPv4Address(ip)
    ipv6s = []
    if ip.startswith("10."):
        parts = ip.split(".")
        aa = parts[1]
        bb = parts[2].zfill(2)
        ccc = parts[3]
        ipv6s = [IPv6Address(f"2404:e80:a137:{aa}{bb}::{ccc}", "2404:e80:a137:")]

    iface = NetworkInterface(
        name=interface_name,
        mac=MACAddress.parse(mac),
        ipv4=ipv4,
        ipv6_addresses=ipv6s,
        dhcp_name=dhcp_name,
    )
    host = Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=[iface],
        default_ipv4=ipv4,
        subdomain="int" if ip.startswith("10.1.10.") else None,
    )
    # Run DNS name derivation to populate dns_names
    derive_all_dns_names(host, SITE)
    return host


class TestDnsmasqGenerator:
    def test_generates_dhcp_host_section(self):
        inv = _make_inventory(
            ip_to_macs={
                "10.1.10.1": [(MACAddress.parse("aa:bb:cc:dd:ee:ff"), "desktop")],
            },
        )
        output = generate_dnsmasq_internal(inv)
        assert "# DHCP Host Configuration" in output
        assert "dhcp-host=aa:bb:cc:dd:ee:ff,10.1.10.1," in output

    def test_dhcp_host_includes_ipv6(self):
        inv = _make_inventory(
            ip_to_macs={
                "10.1.10.1": [(MACAddress.parse("aa:bb:cc:dd:ee:ff"), "desktop")],
            },
        )
        output = generate_dnsmasq_internal(inv)
        assert "[2404:e80:a137:110::1]" in output

    def test_generates_ptr_records(self):
        inv = _make_inventory(
            ip_to_hostname={"10.1.10.1": "desktop"},
        )
        output = generate_dnsmasq_internal(inv)
        assert "ptr-record=/desktop.welland.mithis.com/10.1.10.1" in output
        assert "# Reverse names for IP addresses (IPv4)" in output

    def test_generates_ipv6_ptr_records(self):
        inv = _make_inventory(
            ip_to_hostname={"10.1.10.1": "desktop"},
        )
        output = generate_dnsmasq_internal(inv)
        assert "# Reverse names for IP addresses (IPv6)" in output
        assert "ip6.arpa" in output

    def test_generates_host_records(self):
        host = _host_with_iface("desktop", "aa:bb:cc:dd:ee:ff", "10.1.10.1")
        inv = _make_inventory(hosts=[host])
        output = generate_dnsmasq_internal(inv)

        assert "host-record=desktop.welland.mithis.com,10.1.10.1," in output
        assert "host-record=desktop,10.1.10.1," in output

    def test_generates_subdomain_variant(self):
        host = _host_with_iface("desktop", "aa:bb:cc:dd:ee:ff", "10.1.10.1")
        inv = _make_inventory(hosts=[host])
        output = generate_dnsmasq_internal(inv)

        assert "host-record=desktop.int.welland.mithis.com," in output

    def test_generates_ipv4_only_record(self):
        host = _host_with_iface("desktop", "aa:bb:cc:dd:ee:ff", "10.1.10.1")
        inv = _make_inventory(hosts=[host])
        output = generate_dnsmasq_internal(inv)

        assert "host-record=ipv4.desktop.welland.mithis.com,10.1.10.1" in output

    def test_generates_ipv6_only_record(self):
        host = _host_with_iface("desktop", "aa:bb:cc:dd:ee:ff", "10.1.10.1")
        inv = _make_inventory(hosts=[host])
        output = generate_dnsmasq_internal(inv)

        assert "host-record=ipv6.desktop.welland.mithis.com," in output

    def test_generates_caa_record(self):
        host = _host_with_iface("desktop", "aa:bb:cc:dd:ee:ff", "10.1.10.1")
        inv = _make_inventory(hosts=[host])
        output = generate_dnsmasq_internal(inv)

        assert "dns-rr=desktop.welland.mithis.com,257," in output

    def test_generates_sshfp_records(self):
        host = _host_with_iface("server", "aa:bb:cc:dd:ee:ff", "10.1.10.1")
        host.sshfp_records = ["server IN SSHFP 1 2 abc123"]
        inv = _make_inventory(hosts=[host])
        output = generate_dnsmasq_internal(inv)

        assert "# SSHFP Records" in output
        assert "dns-rr=server.welland.mithis.com,44,1:2:abc123" in output

    def test_sshfp_skipped_when_no_records(self):
        host = _host_with_iface("desktop", "aa:bb:cc:dd:ee:ff", "10.1.10.1")
        inv = _make_inventory(hosts=[host])
        output = generate_dnsmasq_internal(inv)

        # SSHFP section header exists but no dns-rr type 44 entries
        assert "# SSHFP Records" in output
        lines = [l for l in output.split("\n") if l.startswith("dns-rr=") and ",44," in l]
        assert len(lines) == 0
