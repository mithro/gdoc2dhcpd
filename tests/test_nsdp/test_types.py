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

    def test_from_byte_10g(self):
        speed = LinkSpeed.from_byte(0xFF)
        assert speed is LinkSpeed.TEN_GIGABIT

    def test_from_byte_unknown_returns_down(self):
        # Unknown speed codes return DOWN
        speed = LinkSpeed.from_byte(0xFE)
        assert speed is LinkSpeed.DOWN


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


# Tests for new types from Task 3


class TestPortQoS:
    """Tests for PortQoS dataclass (NSDP tag 0x3800)."""

    def test_creation(self):
        from nsdp.types import PortQoS

        qos = PortQoS(port_id=1, priority=8)
        assert qos.port_id == 1
        assert qos.priority == 8

    def test_low_priority(self):
        from nsdp.types import PortQoS

        qos = PortQoS(port_id=5, priority=1)
        assert qos.port_id == 5
        assert qos.priority == 1

    def test_frozen(self):
        from nsdp.types import PortQoS

        qos = PortQoS(port_id=1, priority=4)
        try:
            qos.port_id = 2
            assert False, "Should be frozen"
        except AttributeError:
            pass


class TestPortMirroring:
    """Tests for PortMirroring dataclass (NSDP tag 0x5C00)."""

    def test_disabled(self):
        from nsdp.types import PortMirroring

        pm = PortMirroring(destination_port=0)
        assert pm.destination_port == 0
        assert pm.source_ports == frozenset()

    def test_enabled(self):
        from nsdp.types import PortMirroring

        pm = PortMirroring(destination_port=10, source_ports=frozenset({1, 2}))
        assert pm.destination_port == 10
        assert 1 in pm.source_ports
        assert 2 in pm.source_ports

    def test_multiple_source_ports(self):
        from nsdp.types import PortMirroring

        pm = PortMirroring(
            destination_port=8,
            source_ports=frozenset({1, 2, 3, 4, 5}),
        )
        assert pm.destination_port == 8
        assert len(pm.source_ports) == 5

    def test_frozen(self):
        from nsdp.types import PortMirroring

        pm = PortMirroring(destination_port=5, source_ports=frozenset({1}))
        try:
            pm.destination_port = 6
            assert False, "Should be frozen"
        except AttributeError:
            pass


class TestIGMPSnooping:
    """Tests for IGMPSnooping dataclass (NSDP tag 0x6800)."""

    def test_disabled(self):
        from nsdp.types import IGMPSnooping

        igmp = IGMPSnooping(enabled=False)
        assert igmp.enabled is False
        assert igmp.vlan_id is None

    def test_enabled_without_vlan(self):
        from nsdp.types import IGMPSnooping

        igmp = IGMPSnooping(enabled=True)
        assert igmp.enabled is True
        assert igmp.vlan_id is None

    def test_enabled_with_vlan(self):
        from nsdp.types import IGMPSnooping

        igmp = IGMPSnooping(enabled=True, vlan_id=10)
        assert igmp.enabled is True
        assert igmp.vlan_id == 10

    def test_frozen(self):
        from nsdp.types import IGMPSnooping

        igmp = IGMPSnooping(enabled=True, vlan_id=100)
        try:
            igmp.enabled = False
            assert False, "Should be frozen"
        except AttributeError:
            pass


class TestNSDPDeviceNewFields:
    """Tests for NSDPDevice with new fields from Task 3."""

    def test_port_qos_field(self):
        from nsdp.types import PortQoS

        dev = NSDPDevice(
            model="GS110EMX",
            mac="00:09:5b:aa:bb:cc",
            port_qos=(
                PortQoS(port_id=1, priority=8),
                PortQoS(port_id=2, priority=4),
            ),
        )
        assert len(dev.port_qos) == 2
        assert dev.port_qos[0].port_id == 1
        assert dev.port_qos[0].priority == 8

    def test_qos_engine_field(self):
        dev = NSDPDevice(
            model="GS110EMX",
            mac="00:09:5b:aa:bb:cc",
            qos_engine=2,  # 802.1p mode
        )
        assert dev.qos_engine == 2

    def test_port_mirroring_field(self):
        from nsdp.types import PortMirroring

        dev = NSDPDevice(
            model="GS110EMX",
            mac="00:09:5b:aa:bb:cc",
            port_mirroring=PortMirroring(
                destination_port=10,
                source_ports=frozenset({1, 2, 3}),
            ),
        )
        assert dev.port_mirroring is not None
        assert dev.port_mirroring.destination_port == 10
        assert 2 in dev.port_mirroring.source_ports

    def test_igmp_snooping_field(self):
        from nsdp.types import IGMPSnooping

        dev = NSDPDevice(
            model="GS110EMX",
            mac="00:09:5b:aa:bb:cc",
            igmp_snooping=IGMPSnooping(enabled=True, vlan_id=1),
        )
        assert dev.igmp_snooping is not None
        assert dev.igmp_snooping.enabled is True
        assert dev.igmp_snooping.vlan_id == 1

    def test_broadcast_filtering_field(self):
        dev = NSDPDevice(
            model="GS110EMX",
            mac="00:09:5b:aa:bb:cc",
            broadcast_filtering=True,
        )
        assert dev.broadcast_filtering is True

    def test_loop_detection_field(self):
        dev = NSDPDevice(
            model="GS110EMX",
            mac="00:09:5b:aa:bb:cc",
            loop_detection=False,
        )
        assert dev.loop_detection is False

    def test_all_new_fields_default_none_or_empty(self):
        """Verify new fields default to None or empty tuple."""
        dev = NSDPDevice(
            model="GS110EMX",
            mac="00:09:5b:aa:bb:cc",
        )
        assert dev.port_qos == ()
        assert dev.qos_engine is None
        assert dev.port_mirroring is None
        assert dev.igmp_snooping is None
        assert dev.broadcast_filtering is None
        assert dev.loop_detection is None

    def test_creation_with_all_new_fields(self):
        """Test creating a device with all new fields populated."""
        from nsdp.types import IGMPSnooping, PortMirroring, PortQoS

        dev = NSDPDevice(
            model="GS110EMX",
            mac="00:09:5b:aa:bb:cc",
            hostname="switch-1",
            port_qos=(
                PortQoS(port_id=1, priority=8),
                PortQoS(port_id=2, priority=4),
            ),
            qos_engine=2,
            port_mirroring=PortMirroring(
                destination_port=10,
                source_ports=frozenset({1, 2}),
            ),
            igmp_snooping=IGMPSnooping(enabled=True, vlan_id=1),
            broadcast_filtering=True,
            loop_detection=True,
        )
        assert dev.hostname == "switch-1"
        assert len(dev.port_qos) == 2
        assert dev.qos_engine == 2
        assert dev.port_mirroring.destination_port == 10
        assert dev.igmp_snooping.enabled is True
        assert dev.broadcast_filtering is True
        assert dev.loop_detection is True
