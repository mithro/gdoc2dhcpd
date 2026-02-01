"""Tests for host data models."""

from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, NetworkInventory, SNMPData
from gdoc2netcfg.models.network import Site


def _make_interface(name=None, mac='aa:bb:cc:dd:ee:ff', ip='10.1.10.1', dhcp_name='test'):
    return NetworkInterface(
        name=name,
        mac=MACAddress.parse(mac),
        ipv4=IPv4Address(ip),
        dhcp_name=dhcp_name,
    )


class TestNetworkInterface:
    def test_basic_construction(self):
        iface = _make_interface(name='eth0', ip='10.1.10.1')
        assert iface.name == 'eth0'
        assert str(iface.ipv4) == '10.1.10.1'
        assert str(iface.mac) == 'aa:bb:cc:dd:ee:ff'
        assert iface.ipv6_addresses == []
        assert iface.vlan_id is None

    def test_none_name_for_default(self):
        iface = _make_interface(name=None)
        assert iface.name is None


class TestHost:
    def test_basic_construction(self):
        host = Host(machine_name='desktop', hostname='desktop')
        assert host.machine_name == 'desktop'
        assert host.hostname == 'desktop'
        assert host.interfaces == []
        assert host.default_ipv4 is None

    def test_with_interface(self):
        iface = _make_interface(name='eth0', ip='10.1.10.1')
        host = Host(
            machine_name='desktop',
            hostname='desktop',
            interfaces=[iface],
        )
        assert len(host.interfaces) == 1
        assert host.all_ipv4 == {'eth0': iface.ipv4}

    def test_interface_by_name(self):
        eth0 = _make_interface(name='eth0', mac='aa:bb:cc:dd:ee:01', ip='10.1.10.1')
        bmc = _make_interface(name='bmc', mac='aa:bb:cc:dd:ee:02', ip='10.1.5.1')
        host = Host(
            machine_name='server',
            hostname='server',
            interfaces=[eth0, bmc],
        )
        assert host.interface_by_name['eth0'] == eth0
        assert host.interface_by_name['bmc'] == bmc

    def test_all_macs(self):
        eth0 = _make_interface(name='eth0', mac='aa:bb:cc:dd:ee:01')
        eth1 = _make_interface(name='eth1', mac='aa:bb:cc:dd:ee:02')
        host = Host(
            machine_name='server',
            hostname='server',
            interfaces=[eth0, eth1],
        )
        macs = host.all_macs
        assert len(macs) == 2
        assert MACAddress.parse('aa:bb:cc:dd:ee:01') in macs

    def test_is_bmc(self):
        bmc_iface = _make_interface(name='bmc', ip='10.1.5.1')
        host = Host(
            machine_name='server',
            hostname='server',
            interfaces=[bmc_iface],
        )
        assert host.is_bmc()

    def test_is_not_bmc(self):
        eth_iface = _make_interface(name='eth0')
        host = Host(
            machine_name='server',
            hostname='server',
            interfaces=[eth_iface],
        )
        assert not host.is_bmc()

    def test_is_multi_interface(self):
        eth0 = _make_interface(name='eth0', mac='aa:bb:cc:dd:ee:01')
        eth1 = _make_interface(name='eth1', mac='aa:bb:cc:dd:ee:02')
        host = Host(
            machine_name='server',
            hostname='server',
            interfaces=[eth0, eth1],
        )
        assert host.is_multi_interface()

    def test_single_interface(self):
        host = Host(
            machine_name='thing',
            hostname='thing.iot',
            interfaces=[_make_interface()],
        )
        assert not host.is_multi_interface()

    def test_extra_fields(self):
        host = Host(
            machine_name='switch',
            hostname='switch',
            extra={'Driver': 'switch', 'Parent': 'router'},
        )
        assert host.extra['Driver'] == 'switch'


class TestNetworkInventory:
    def _make_inventory(self):
        site = Site(name='welland', domain='welland.mithis.com')
        host_a = Host(machine_name='alpha', hostname='alpha')
        host_b = Host(machine_name='beta', hostname='beta.iot')
        return NetworkInventory(site=site, hosts=[host_a, host_b])

    def test_basic_construction(self):
        inv = self._make_inventory()
        assert inv.site.name == 'welland'
        assert len(inv.hosts) == 2

    def test_hosts_sorted(self):
        inv = self._make_inventory()
        sorted_hosts = inv.hosts_sorted()
        assert sorted_hosts[0].hostname == 'alpha'
        assert sorted_hosts[1].hostname == 'beta.iot'

    def test_host_by_hostname(self):
        inv = self._make_inventory()
        assert inv.host_by_hostname('alpha') is not None
        assert inv.host_by_hostname('alpha').machine_name == 'alpha'
        assert inv.host_by_hostname('nonexistent') is None


class TestSNMPData:
    def test_basic_construction(self):
        data = SNMPData(
            snmp_version="v2c",
            system_info=(("sysDescr", "Linux server"), ("sysName", "myhost")),
            interfaces=(
                (("ifIndex", "1"), ("ifDescr", "eth0")),
            ),
            ip_addresses=(
                (("ipAdEntAddr", "10.1.10.1"), ("ipAdEntIfIndex", "1")),
            ),
            raw=(("1.3.6.1.2.1.1.1.0", "Linux server"),),
        )
        assert data.snmp_version == "v2c"
        assert data.system_info == (("sysDescr", "Linux server"), ("sysName", "myhost"))
        assert len(data.interfaces) == 1
        assert len(data.ip_addresses) == 1
        assert data.raw == (("1.3.6.1.2.1.1.1.0", "Linux server"),)

    def test_defaults(self):
        data = SNMPData(snmp_version="v1")
        assert data.system_info == ()
        assert data.interfaces == ()
        assert data.ip_addresses == ()
        assert data.raw == ()

    def test_frozen(self):
        data = SNMPData(snmp_version="v2c")
        try:
            data.snmp_version = "v3"
            assert False, "Should have raised FrozenInstanceError"
        except AttributeError:
            pass

    def test_host_snmp_data_default_none(self):
        host = Host(machine_name="server", hostname="server")
        assert host.snmp_data is None

    def test_host_with_snmp_data(self):
        data = SNMPData(
            snmp_version="v2c",
            system_info=(("sysName", "switch-1"),),
        )
        host = Host(machine_name="switch", hostname="switch", snmp_data=data)
        assert host.snmp_data is not None
        assert host.snmp_data.snmp_version == "v2c"
        assert host.snmp_data.system_info == (("sysName", "switch-1"),)
