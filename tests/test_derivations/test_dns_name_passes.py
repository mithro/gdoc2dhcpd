"""Tests for the DNS name derivation passes.

Tests each of the four passes independently, plus the combined
derive_all_dns_names orchestrator.
"""

from gdoc2netcfg.derivations.dns_names import (
    derive_all_dns_names,
    derive_dns_names_hostname,
    derive_dns_names_interface,
    derive_dns_names_ip_prefix,
    derive_dns_names_subdomain,
)
from gdoc2netcfg.models.addressing import IPv4Address, IPv6Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface
from gdoc2netcfg.models.network import IPv6Prefix, Site

DOMAIN = "welland.mithis.com"
SITE = Site(
    name="welland",
    domain=DOMAIN,
    ipv6_prefixes=[IPv6Prefix(prefix="2404:e80:a137:", name="Launtel")],
    network_subdomains={10: "int", 11: "int", 90: "iot"},
)


def _make_host(
    hostname="desktop",
    ip="10.1.10.100",
    interfaces=None,
    subdomain="int",
):
    """Build a Host with sensible defaults for testing."""
    ipv4 = IPv4Address(ip)
    parts = ip.split(".")
    aa = parts[1]
    bb = parts[2].zfill(2)
    ccc = parts[3]
    ipv6 = IPv6Address(f"2404:e80:a137:{aa}{bb}::{ccc}", "2404:e80:a137:")

    if interfaces is None:
        interfaces = [
            NetworkInterface(
                name=None,
                mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                ipv4=ipv4,
                ipv6_addresses=[ipv6],
                dhcp_name=hostname,
            )
        ]

    return Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=interfaces,
        default_ipv4=ipv4,
        subdomain=subdomain,
    )


def _make_multi_iface_host():
    """Build a host with two named interfaces."""
    ipv4_eth0 = IPv4Address("10.1.10.100")
    ipv6_eth0 = IPv6Address("2404:e80:a137:110::100", "2404:e80:a137:")
    ipv4_eth1 = IPv4Address("10.1.10.101")
    ipv6_eth1 = IPv6Address("2404:e80:a137:110::101", "2404:e80:a137:")

    return Host(
        machine_name="ten64",
        hostname="ten64",
        interfaces=[
            NetworkInterface(
                name="eth0",
                mac=MACAddress.parse("aa:bb:cc:dd:ee:01"),
                ipv4=ipv4_eth0,
                ipv6_addresses=[ipv6_eth0],
                dhcp_name="eth0-ten64",
            ),
            NetworkInterface(
                name="eth1",
                mac=MACAddress.parse("aa:bb:cc:dd:ee:02"),
                ipv4=ipv4_eth1,
                ipv6_addresses=[ipv6_eth1],
                dhcp_name="eth1-ten64",
            ),
        ],
        default_ipv4=ipv4_eth0,
        subdomain="int",
    )


class TestPass1Hostname:
    def test_adds_fqdn_and_short_name(self):
        host = _make_host()
        names = derive_dns_names_hostname(host, DOMAIN)

        assert len(names) == 2
        assert names[0].name == "desktop.welland.mithis.com"
        assert names[0].is_fqdn is True
        assert names[1].name == "desktop"
        assert names[1].is_fqdn is False

    def test_ipv4_set_on_both(self):
        host = _make_host()
        names = derive_dns_names_hostname(host, DOMAIN)

        assert str(names[0].ipv4) == "10.1.10.100"
        assert str(names[1].ipv4) == "10.1.10.100"

    def test_ipv6_set_on_both(self):
        host = _make_host()
        names = derive_dns_names_hostname(host, DOMAIN)

        assert len(names[0].ipv6_addresses) == 1
        assert str(names[0].ipv6_addresses[0]) == "2404:e80:a137:110::100"
        assert len(names[1].ipv6_addresses) == 1

    def test_no_default_ip_returns_empty(self):
        host = _make_host()
        host.default_ipv4 = None
        names = derive_dns_names_hostname(host, DOMAIN)
        assert names == []

    def test_iot_hostname(self):
        host = _make_host(hostname="thermostat.iot", ip="10.1.90.10", subdomain="iot")
        names = derive_dns_names_hostname(host, DOMAIN)

        assert names[0].name == "thermostat.iot.welland.mithis.com"
        assert names[1].name == "thermostat.iot"


class TestPass2Interface:
    def test_no_named_interfaces_returns_empty(self):
        host = _make_host()
        names = derive_dns_names_interface(host, DOMAIN)
        assert names == []

    def test_named_interfaces_get_fqdn_and_short(self):
        host = _make_multi_iface_host()
        names = derive_dns_names_interface(host, DOMAIN)

        assert len(names) == 4  # 2 interfaces × (FQDN + short)
        fqdns = [n for n in names if n.is_fqdn]
        shorts = [n for n in names if not n.is_fqdn]
        assert len(fqdns) == 2
        assert len(shorts) == 2

    def test_interface_name_format(self):
        host = _make_multi_iface_host()
        names = derive_dns_names_interface(host, DOMAIN)

        name_strs = [n.name for n in names]
        assert "eth0.ten64.welland.mithis.com" in name_strs
        assert "eth0.ten64" in name_strs
        assert "eth1.ten64.welland.mithis.com" in name_strs
        assert "eth1.ten64" in name_strs

    def test_interface_ip_matches_interface(self):
        host = _make_multi_iface_host()
        names = derive_dns_names_interface(host, DOMAIN)

        eth0_fqdn = next(n for n in names if n.name == "eth0.ten64.welland.mithis.com")
        assert str(eth0_fqdn.ipv4) == "10.1.10.100"

        eth1_fqdn = next(n for n in names if n.name == "eth1.ten64.welland.mithis.com")
        assert str(eth1_fqdn.ipv4) == "10.1.10.101"


class TestPass3Subdomain:
    def test_adds_subdomain_for_fqdn_names(self):
        host = _make_host()
        host.dns_names = derive_dns_names_hostname(host, DOMAIN)
        names = derive_dns_names_subdomain(host, DOMAIN, SITE)

        assert len(names) == 1
        assert names[0].name == "desktop.int.welland.mithis.com"
        assert names[0].is_fqdn is True

    def test_no_subdomain_for_short_names(self):
        host = _make_host()
        host.dns_names = derive_dns_names_hostname(host, DOMAIN)
        names = derive_dns_names_subdomain(host, DOMAIN, SITE)

        # Only FQDN names get subdomain variants
        short_variants = [n for n in names if not n.is_fqdn]
        assert len(short_variants) == 0

    def test_interface_fqdn_gets_subdomain(self):
        host = _make_multi_iface_host()
        host.dns_names = derive_dns_names_hostname(host, DOMAIN)
        host.dns_names.extend(derive_dns_names_interface(host, DOMAIN))
        names = derive_dns_names_subdomain(host, DOMAIN, SITE)

        name_strs = [n.name for n in names]
        assert "ten64.int.welland.mithis.com" in name_strs
        assert "eth0.ten64.int.welland.mithis.com" in name_strs
        assert "eth1.ten64.int.welland.mithis.com" in name_strs

    def test_no_subdomain_for_non_10_1_ip(self):
        host = _make_host(ip="10.31.1.5", subdomain=None)
        host.dns_names = derive_dns_names_hostname(host, DOMAIN)
        names = derive_dns_names_subdomain(host, DOMAIN, SITE)
        assert names == []

    def test_preserves_ipv4_and_ipv6(self):
        host = _make_host()
        host.dns_names = derive_dns_names_hostname(host, DOMAIN)
        names = derive_dns_names_subdomain(host, DOMAIN, SITE)

        assert str(names[0].ipv4) == "10.1.10.100"
        assert len(names[0].ipv6_addresses) == 1


class TestPass4IpPrefix:
    def test_adds_ipv4_and_ipv6_prefixes(self):
        host = _make_host()
        host.dns_names = derive_dns_names_hostname(host, DOMAIN)
        names = derive_dns_names_ip_prefix(host, DOMAIN)

        # Only the FQDN entry has both IPv4 and IPv6
        assert len(names) == 2
        name_strs = [n.name for n in names]
        assert "ipv4.desktop.welland.mithis.com" in name_strs
        assert "ipv6.desktop.welland.mithis.com" in name_strs

    def test_ipv4_prefix_has_only_ipv4(self):
        host = _make_host()
        host.dns_names = derive_dns_names_hostname(host, DOMAIN)
        names = derive_dns_names_ip_prefix(host, DOMAIN)

        ipv4_name = next(n for n in names if n.name.startswith("ipv4."))
        assert ipv4_name.ipv4 is not None
        assert ipv4_name.ipv6_addresses == ()

    def test_ipv6_prefix_has_only_ipv6(self):
        host = _make_host()
        host.dns_names = derive_dns_names_hostname(host, DOMAIN)
        names = derive_dns_names_ip_prefix(host, DOMAIN)

        ipv6_name = next(n for n in names if n.name.startswith("ipv6."))
        assert ipv6_name.ipv4 is None
        assert len(ipv6_name.ipv6_addresses) == 1

    def test_no_ipv6_means_no_prefixes(self):
        """If host has no IPv6 addresses, no prefixed names are generated."""
        ipv4 = IPv4Address("192.168.1.1")
        host = Host(
            machine_name="printer",
            hostname="printer",
            interfaces=[
                NetworkInterface(
                    name=None,
                    mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                    ipv4=ipv4,
                    ipv6_addresses=[],
                    dhcp_name="printer",
                )
            ],
            default_ipv4=ipv4,
        )
        host.dns_names = derive_dns_names_hostname(host, DOMAIN)
        names = derive_dns_names_ip_prefix(host, DOMAIN)
        assert names == []

    def test_scans_all_previous_fqdn_names(self):
        """Pass 4 should create prefixed variants for all FQDNs."""
        host = _make_multi_iface_host()
        host.dns_names = derive_dns_names_hostname(host, DOMAIN)
        host.dns_names.extend(derive_dns_names_interface(host, DOMAIN))
        host.dns_names.extend(derive_dns_names_subdomain(host, DOMAIN, SITE))
        names = derive_dns_names_ip_prefix(host, DOMAIN)

        # All FQDNs with both IPv4+IPv6 get ipv4. and ipv6. variants
        fqdn_with_dual = [
            n for n in host.dns_names
            if n.is_fqdn and n.ipv4 is not None and n.ipv6_addresses
        ]
        assert len(names) == len(fqdn_with_dual) * 2


class TestDeriveAllDnsNames:
    def test_single_interface_host(self):
        host = _make_host()
        derive_all_dns_names(host, SITE)

        name_strs = [n.name for n in host.dns_names]
        # Pass 1: hostname
        assert "desktop.welland.mithis.com" in name_strs
        assert "desktop" in name_strs
        # Pass 3: subdomain
        assert "desktop.int.welland.mithis.com" in name_strs
        # Pass 4: ipv4/ipv6 prefixes
        assert "ipv4.desktop.welland.mithis.com" in name_strs
        assert "ipv6.desktop.welland.mithis.com" in name_strs

    def test_multi_interface_host(self):
        host = _make_multi_iface_host()
        derive_all_dns_names(host, SITE)

        name_strs = [n.name for n in host.dns_names]
        # Pass 1
        assert "ten64.welland.mithis.com" in name_strs
        # Pass 2
        assert "eth0.ten64.welland.mithis.com" in name_strs
        assert "eth1.ten64.welland.mithis.com" in name_strs
        # Pass 3
        assert "ten64.int.welland.mithis.com" in name_strs
        assert "eth0.ten64.int.welland.mithis.com" in name_strs
        # Pass 4
        assert "ipv4.ten64.welland.mithis.com" in name_strs
        assert "ipv6.ten64.welland.mithis.com" in name_strs

    def test_all_fqdns_flagged_correctly(self):
        host = _make_host()
        derive_all_dns_names(host, SITE)

        for dns_name in host.dns_names:
            if dns_name.name.endswith(f".{DOMAIN}") or dns_name.name.startswith("ipv"):
                assert dns_name.is_fqdn, f"{dns_name.name} should be FQDN"
            else:
                assert not dns_name.is_fqdn, f"{dns_name.name} should not be FQDN"

    def test_host_with_no_subdomain(self):
        host = _make_host(ip="10.31.1.5", subdomain=None)
        derive_all_dns_names(host, SITE)

        name_strs = [n.name for n in host.dns_names]
        # No subdomain variants
        assert not any(".int." in n or ".sm." in n for n in name_strs if "." in n)
        # Still has hostname and ip-prefix
        assert "desktop.welland.mithis.com" in name_strs
        assert "ipv4.desktop.welland.mithis.com" in name_strs
