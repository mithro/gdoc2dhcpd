"""Tests for unified SwitchData model."""

from gdoc2netcfg.models.switch_data import (
    PortLinkStatus,
    PortTrafficStats,
    SwitchData,
    SwitchDataSource,
    VLANInfo,
)


class TestSwitchDataSource:
    """Tests for the SwitchDataSource enum."""

    def test_snmp_value(self):
        assert SwitchDataSource.SNMP.value == "snmp"

    def test_nsdp_value(self):
        assert SwitchDataSource.NSDP.value == "nsdp"


class TestPortLinkStatus:
    """Tests for the PortLinkStatus dataclass."""

    def test_port_up(self):
        status = PortLinkStatus(port_id=1, is_up=True, speed_mbps=1000)
        assert status.port_id == 1
        assert status.is_up is True
        assert status.speed_mbps == 1000

    def test_port_down(self):
        status = PortLinkStatus(port_id=2, is_up=False, speed_mbps=0)
        assert status.port_id == 2
        assert status.is_up is False
        assert status.speed_mbps == 0

    def test_with_port_name(self):
        status = PortLinkStatus(
            port_id=1, is_up=True, speed_mbps=1000, port_name="ge-0/0/1"
        )
        assert status.port_name == "ge-0/0/1"

    def test_port_name_defaults_none(self):
        status = PortLinkStatus(port_id=1, is_up=True, speed_mbps=1000)
        assert status.port_name is None

    def test_frozen(self):
        status = PortLinkStatus(port_id=1, is_up=True, speed_mbps=1000)
        try:
            status.port_id = 2
            assert False, "Should be frozen"
        except AttributeError:
            pass

    def test_10g_speed(self):
        status = PortLinkStatus(port_id=9, is_up=True, speed_mbps=10000)
        assert status.speed_mbps == 10000


class TestPortTrafficStats:
    """Tests for the PortTrafficStats dataclass."""

    def test_creation(self):
        stats = PortTrafficStats(port_id=1, bytes_rx=1000, bytes_tx=500, errors=0)
        assert stats.port_id == 1
        assert stats.bytes_rx == 1000
        assert stats.bytes_tx == 500
        assert stats.errors == 0

    def test_with_errors(self):
        stats = PortTrafficStats(port_id=3, bytes_rx=5000, bytes_tx=3000, errors=15)
        assert stats.errors == 15

    def test_frozen(self):
        stats = PortTrafficStats(port_id=1, bytes_rx=1000, bytes_tx=500, errors=0)
        try:
            stats.bytes_rx = 2000
            assert False, "Should be frozen"
        except AttributeError:
            pass

    def test_large_counters(self):
        # Test with large byte counters (64-bit values)
        stats = PortTrafficStats(
            port_id=1,
            bytes_rx=18446744073709551615,  # Max uint64
            bytes_tx=18446744073709551615,
            errors=0,
        )
        assert stats.bytes_rx == 18446744073709551615


class TestVLANInfo:
    """Tests for the VLANInfo dataclass."""

    def test_untagged_ports(self):
        vlan = VLANInfo(
            vlan_id=10,
            name="mgmt",
            member_ports=frozenset({1, 2, 3}),
            tagged_ports=frozenset({3}),
        )
        assert vlan.untagged_ports == frozenset({1, 2})

    def test_all_untagged(self):
        vlan = VLANInfo(
            vlan_id=1,
            name="default",
            member_ports=frozenset({1, 2, 3, 4}),
            tagged_ports=frozenset(),
        )
        assert vlan.untagged_ports == frozenset({1, 2, 3, 4})

    def test_all_tagged(self):
        vlan = VLANInfo(
            vlan_id=100,
            name="trunk",
            member_ports=frozenset({1, 2}),
            tagged_ports=frozenset({1, 2}),
        )
        assert vlan.untagged_ports == frozenset()

    def test_no_name(self):
        vlan = VLANInfo(
            vlan_id=20,
            name=None,
            member_ports=frozenset({1}),
        )
        assert vlan.name is None

    def test_tagged_ports_defaults_empty(self):
        vlan = VLANInfo(
            vlan_id=30,
            name="test",
            member_ports=frozenset({1, 2}),
        )
        assert vlan.tagged_ports == frozenset()
        assert vlan.untagged_ports == frozenset({1, 2})

    def test_frozen(self):
        vlan = VLANInfo(
            vlan_id=10,
            name="test",
            member_ports=frozenset({1}),
        )
        try:
            vlan.vlan_id = 20
            assert False, "Should be frozen"
        except AttributeError:
            pass


class TestSwitchData:
    """Tests for the SwitchData dataclass."""

    def test_nsdp_source(self):
        data = SwitchData(
            source=SwitchDataSource.NSDP,
            model="GS110EMX",
            port_count=10,
            serial_number="ABC123",
        )
        assert data.source == SwitchDataSource.NSDP
        assert data.model == "GS110EMX"
        assert data.port_count == 10
        assert data.serial_number == "ABC123"
        # SNMP-only fields should be None
        assert data.mac_table is None

    def test_snmp_source(self):
        data = SwitchData(
            source=SwitchDataSource.SNMP,
            model="GS724T",
            mac_table=(("aa:bb:cc:dd:ee:ff", 1, 5, "port5"),),
        )
        assert data.source == SwitchDataSource.SNMP
        assert data.model == "GS724T"
        assert data.mac_table is not None
        assert len(data.mac_table) == 1
        # NSDP-only fields should be None
        assert data.serial_number is None

    def test_common_fields_port_status(self):
        data = SwitchData(
            source=SwitchDataSource.NSDP,
            port_status=(
                PortLinkStatus(port_id=1, is_up=True, speed_mbps=1000),
                PortLinkStatus(port_id=2, is_up=False, speed_mbps=0),
            ),
        )
        assert len(data.port_status) == 2
        assert data.port_status[0].is_up is True
        assert data.port_status[1].is_up is False

    def test_common_fields_port_pvids(self):
        data = SwitchData(
            source=SwitchDataSource.SNMP,
            port_pvids=((1, 10), (2, 20), (3, 10)),
        )
        assert len(data.port_pvids) == 3
        assert data.port_pvids[0] == (1, 10)
        assert data.port_pvids[1] == (2, 20)

    def test_common_fields_port_stats(self):
        data = SwitchData(
            source=SwitchDataSource.NSDP,
            port_stats=(
                PortTrafficStats(port_id=1, bytes_rx=1000, bytes_tx=500, errors=0),
                PortTrafficStats(port_id=2, bytes_rx=2000, bytes_tx=1000, errors=5),
            ),
        )
        assert len(data.port_stats) == 2
        assert data.port_stats[0].bytes_rx == 1000
        assert data.port_stats[1].errors == 5

    def test_common_fields_vlans(self):
        data = SwitchData(
            source=SwitchDataSource.SNMP,
            vlans=(
                VLANInfo(
                    vlan_id=1,
                    name="default",
                    member_ports=frozenset({1, 2, 3, 4}),
                ),
                VLANInfo(
                    vlan_id=10,
                    name="mgmt",
                    member_ports=frozenset({1, 2}),
                    tagged_ports=frozenset({1, 2}),
                ),
            ),
        )
        assert len(data.vlans) == 2
        assert data.vlans[0].vlan_id == 1
        assert data.vlans[1].name == "mgmt"

    def test_snmp_mac_table(self):
        data = SwitchData(
            source=SwitchDataSource.SNMP,
            mac_table=(
                ("aa:bb:cc:dd:ee:ff", 1, 5, "port5"),
                ("11:22:33:44:55:66", 10, 3, "port3"),
            ),
        )
        assert data.mac_table[0][0] == "aa:bb:cc:dd:ee:ff"
        assert data.mac_table[0][1] == 1  # vlan_id
        assert data.mac_table[0][2] == 5  # port_id
        assert data.mac_table[0][3] == "port5"

    def test_snmp_lldp_neighbors(self):
        data = SwitchData(
            source=SwitchDataSource.SNMP,
            lldp_neighbors=(
                (1, "switch-a", "ge-0/0/24", "aa:bb:cc:dd:ee:ff"),
            ),
        )
        assert data.lldp_neighbors is not None
        assert data.lldp_neighbors[0][1] == "switch-a"

    def test_snmp_poe_status(self):
        data = SwitchData(
            source=SwitchDataSource.SNMP,
            poe_status=((1, 1, 3), (2, 1, 2)),  # (port_id, admin_status, detection_status)
        )
        assert data.poe_status is not None
        assert len(data.poe_status) == 2

    def test_nsdp_qos_engine(self):
        data = SwitchData(
            source=SwitchDataSource.NSDP,
            qos_engine=2,  # 802.1p mode
        )
        assert data.qos_engine == 2

    def test_nsdp_port_mirroring(self):
        data = SwitchData(
            source=SwitchDataSource.NSDP,
            port_mirroring_dest=10,
        )
        assert data.port_mirroring_dest == 10

    def test_nsdp_igmp_snooping(self):
        data = SwitchData(
            source=SwitchDataSource.NSDP,
            igmp_snooping_enabled=True,
        )
        assert data.igmp_snooping_enabled is True

    def test_defaults_empty_tuples(self):
        data = SwitchData(source=SwitchDataSource.NSDP)
        assert data.port_status == ()
        assert data.port_pvids == ()
        assert data.port_stats == ()
        assert data.vlans == ()

    def test_defaults_none_fields(self):
        data = SwitchData(source=SwitchDataSource.NSDP)
        assert data.model is None
        assert data.firmware_version is None
        assert data.port_count is None

    def test_frozen(self):
        data = SwitchData(source=SwitchDataSource.NSDP, model="GS110EMX")
        try:
            data.model = "other"
            assert False, "Should be frozen"
        except AttributeError:
            pass

    def test_complete_nsdp_example(self):
        """Test a complete NSDP switch data example."""
        data = SwitchData(
            source=SwitchDataSource.NSDP,
            model="GS110EMX",
            firmware_version="V2.06.24GR",
            port_count=10,
            port_status=(
                PortLinkStatus(port_id=1, is_up=True, speed_mbps=1000),
                PortLinkStatus(port_id=2, is_up=True, speed_mbps=100),
                PortLinkStatus(port_id=9, is_up=True, speed_mbps=10000),
                PortLinkStatus(port_id=10, is_up=False, speed_mbps=0),
            ),
            port_pvids=((1, 10), (2, 10), (9, 1), (10, 1)),
            port_stats=(
                PortTrafficStats(port_id=1, bytes_rx=1000000, bytes_tx=500000, errors=0),
                PortTrafficStats(port_id=2, bytes_rx=2000000, bytes_tx=1000000, errors=0),
            ),
            vlans=(
                VLANInfo(vlan_id=1, name=None, member_ports=frozenset({1, 2, 9, 10})),
                VLANInfo(
                    vlan_id=10,
                    name=None,
                    member_ports=frozenset({1, 2}),
                    tagged_ports=frozenset(),
                ),
            ),
            serial_number="12345ABC",
            qos_engine=0,
            port_mirroring_dest=0,
            igmp_snooping_enabled=False,
        )
        assert data.source == SwitchDataSource.NSDP
        assert data.port_count == 10
        assert len(data.port_status) == 4
        assert data.port_status[2].speed_mbps == 10000  # 10G port
        assert len(data.vlans) == 2

    def test_complete_snmp_example(self):
        """Test a complete SNMP switch data example."""
        data = SwitchData(
            source=SwitchDataSource.SNMP,
            model="GS724Tv4",
            firmware_version="6.6.1.6",
            port_count=24,
            port_status=(
                PortLinkStatus(
                    port_id=1, is_up=True, speed_mbps=1000, port_name="ge-0/0/1"
                ),
                PortLinkStatus(
                    port_id=2, is_up=False, speed_mbps=0, port_name="ge-0/0/2"
                ),
            ),
            port_pvids=((1, 1), (2, 10)),
            vlans=(
                VLANInfo(
                    vlan_id=1, name="default", member_ports=frozenset({1, 2, 3, 4})
                ),
                VLANInfo(
                    vlan_id=10,
                    name="management",
                    member_ports=frozenset({1, 2}),
                    tagged_ports=frozenset({1}),
                ),
            ),
            mac_table=(
                ("aa:bb:cc:dd:ee:ff", 1, 1, "ge-0/0/1"),
                ("11:22:33:44:55:66", 10, 2, "ge-0/0/2"),
            ),
            lldp_neighbors=(
                (1, "upstream-switch", "port24", "aa:aa:aa:aa:aa:aa"),
            ),
            poe_status=((1, 1, 3), (2, 2, 1)),
        )
        assert data.source == SwitchDataSource.SNMP
        assert data.port_status[0].port_name == "ge-0/0/1"
        assert data.mac_table is not None
        assert data.lldp_neighbors is not None
        assert data.poe_status is not None
