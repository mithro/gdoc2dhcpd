"""Tests for BridgeData model."""

from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import BridgeData, Host, NetworkInterface


class TestBridgeData:
    def test_frozen(self):
        data = BridgeData(
            mac_table=(("AA:BB:CC:DD:EE:FF", 5, 3, "1/g3"),),
            vlan_names=((1, "Default"), (5, "net")),
            port_pvids=((1, 31), (2, 31)),
        )
        try:
            data.mac_table = ()
            assert False, "Should have raised FrozenInstanceError"
        except AttributeError:
            pass

    def test_empty_defaults(self):
        data = BridgeData()
        assert data.mac_table == ()
        assert data.vlan_names == ()
        assert data.port_pvids == ()
        assert data.port_names == ()
        assert data.port_status == ()
        assert data.lldp_neighbors == ()

    def test_host_bridge_data_default_none(self):
        host = Host(
            machine_name="sw",
            hostname="sw",
            interfaces=[
                NetworkInterface(
                    name=None,
                    mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                    ip_addresses=(IPv4Address("10.1.5.10"),),
                ),
            ],
        )
        assert host.bridge_data is None
