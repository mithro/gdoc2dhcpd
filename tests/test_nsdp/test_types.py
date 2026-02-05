"""Tests for NSDP data types."""

from nsdp.types import (
    LinkSpeed,
    NSDPDevice,
    PortPVID,
    PortStatistics,
    PortStatus,
    VLANEngine,
    VLANMembership,
)


class TestLinkSpeed:
    def test_down(self):
        assert LinkSpeed.DOWN.speed_mbps == 0

    def test_1g(self):
        assert LinkSpeed.GIGABIT.speed_mbps == 1000

    def test_from_byte_down(self):
        assert LinkSpeed.from_byte(0x00) is LinkSpeed.DOWN

    def test_from_byte_100m_full(self):
        assert LinkSpeed.from_byte(0x04) is LinkSpeed.FULL_100M

    def test_from_byte_unknown(self):
        speed = LinkSpeed.from_byte(0xFF)
        assert speed is LinkSpeed.UNKNOWN


class TestVLANEngine:
    def test_disabled(self):
        assert VLANEngine.DISABLED.value == 0

    def test_advanced_802_1q(self):
        assert VLANEngine.ADVANCED_802_1Q.value == 4


class TestPortStatus:
    def test_creation(self):
        ps = PortStatus(port_id=1, speed=LinkSpeed.GIGABIT)
        assert ps.port_id == 1
        assert ps.speed is LinkSpeed.GIGABIT

    def test_frozen(self):
        ps = PortStatus(port_id=1, speed=LinkSpeed.DOWN)
        try:
            ps.port_id = 2
            assert False, "Should be frozen"
        except AttributeError:
            pass


class TestPortStatistics:
    def test_creation(self):
        ps = PortStatistics(
            port_id=1,
            bytes_received=1000,
            bytes_sent=500,
            crc_errors=0,
        )
        assert ps.bytes_received == 1000
        assert ps.bytes_sent == 500


class TestVLANMembership:
    def test_creation(self):
        vm = VLANMembership(
            vlan_id=100,
            member_ports=frozenset({1, 2, 3}),
            tagged_ports=frozenset({3}),
        )
        assert vm.vlan_id == 100
        assert 2 in vm.member_ports
        assert 1 not in vm.tagged_ports

    def test_untagged_ports(self):
        vm = VLANMembership(
            vlan_id=1,
            member_ports=frozenset({1, 2, 3}),
            tagged_ports=frozenset({3}),
        )
        assert vm.untagged_ports == frozenset({1, 2})


class TestPortPVID:
    def test_creation(self):
        pp = PortPVID(port_id=5, vlan_id=100)
        assert pp.port_id == 5
        assert pp.vlan_id == 100


class TestNSDPDevice:
    def test_creation_minimal(self):
        dev = NSDPDevice(
            model="GS110EMX",
            mac="00:09:5b:aa:bb:cc",
        )
        assert dev.model == "GS110EMX"
        assert dev.hostname is None

    def test_creation_full(self):
        dev = NSDPDevice(
            model="GS110EMX",
            mac="00:09:5b:aa:bb:cc",
            hostname="switch-1",
            ip="10.1.20.1",
            netmask="255.255.255.0",
            gateway="10.1.20.254",
            firmware_version="V2.06.24GR",
            dhcp_enabled=True,
            port_count=10,
            serial_number="ABC123",
            port_status=(
                PortStatus(port_id=1, speed=LinkSpeed.GIGABIT),
            ),
            vlan_engine=VLANEngine.ADVANCED_802_1Q,
        )
        assert dev.hostname == "switch-1"
        assert dev.port_count == 10
        assert dev.port_status[0].speed is LinkSpeed.GIGABIT
