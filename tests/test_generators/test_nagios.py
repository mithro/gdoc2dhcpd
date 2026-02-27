"""Tests for the Nagios monitoring generator."""

from gdoc2netcfg.generators.nagios import generate_nagios
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, NetworkInventory
from gdoc2netcfg.models.network import Site

SITE = Site(name="welland", domain="welland.mithis.com")


def _host(hostname, ip, driver="", parent=""):
    extra = {}
    if driver:
        extra["Driver"] = driver
    if parent:
        extra["Parent"] = parent

    return Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=[
            NetworkInterface(
                name=None,
                mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                ip_addresses=(IPv4Address(ip),),
            )
        ],
        extra=extra,
    )


class TestNagiosGenerator:
    def test_generates_switch_host_definition(self):
        hosts = [_host("switch-core", "10.1.5.1", driver="switch")]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_nagios(inv)

        assert "define host {" in output
        assert "host_name   switch-core" in output
        assert "address     10.1.5.1" in output
        assert "hostgroups  allhosts,switches" in output

    def test_includes_parent(self):
        hosts = [_host("switch-floor2", "10.1.5.2", driver="switch", parent="switch-core")]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_nagios(inv)

        assert "parents     switch-core" in output

    def test_skips_non_switches(self):
        hosts = [
            _host("desktop", "10.1.10.1", driver="i225"),
            _host("switch-core", "10.1.5.1", driver="switch"),
        ]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_nagios(inv)

        assert "desktop" not in output
        assert "switch-core" in output

    def test_skips_hosts_without_driver(self):
        hosts = [_host("unknown", "10.1.10.1")]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_nagios(inv)

        assert output == ""

    def test_driver_first_word_used(self):
        """'switch, managed' → 'switch' for hardware detection."""
        hosts = [_host("switch-core", "10.1.5.1", driver="switch, managed")]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_nagios(inv)

        assert "switch-core" in output
