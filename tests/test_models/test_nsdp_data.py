"""Tests for the NSDPData model on Host."""

from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, NSDPData


def test_nsdp_data_creation():
    data = NSDPData(
        model="GS110EMX",
        mac="00:09:5b:aa:bb:cc",
        firmware_version="V2.06.24GR",
    )
    assert data.model == "GS110EMX"
    assert data.firmware_version == "V2.06.24GR"
    assert data.port_status == ()


def test_nsdp_data_frozen():
    data = NSDPData(model="GS110EMX", mac="00:09:5b:aa:bb:cc")
    try:
        data.model = "other"
        assert False, "Should be frozen"
    except AttributeError:
        pass


def test_host_nsdp_data_default_none():
    host = Host(
        machine_name="switch",
        hostname="switch",
        interfaces=[
            NetworkInterface(
                name=None,
                mac=MACAddress.parse("00:09:5b:aa:bb:cc"),
                ipv4=IPv4Address("10.1.20.1"),
                dhcp_name="switch",
            ),
        ],
    )
    assert host.nsdp_data is None


def test_host_nsdp_data_set():
    host = Host(
        machine_name="switch",
        hostname="switch",
        interfaces=[
            NetworkInterface(
                name=None,
                mac=MACAddress.parse("00:09:5b:aa:bb:cc"),
                ipv4=IPv4Address("10.1.20.1"),
                dhcp_name="switch",
            ),
        ],
    )
    host.nsdp_data = NSDPData(
        model="GS110EMX",
        mac="00:09:5b:aa:bb:cc",
    )
    assert host.nsdp_data is not None
    assert host.nsdp_data.model == "GS110EMX"


def test_nsdp_data_vlan_engine():
    """Test vlan_engine field on NSDPData."""
    data = NSDPData(model="GS110EMX", mac="aa:bb:cc:dd:ee:ff", vlan_engine=4)
    assert data.vlan_engine == 4


def test_nsdp_data_vlan_engine_defaults_none():
    """Test vlan_engine defaults to None."""
    data = NSDPData(model="GS110EMX", mac="aa:bb:cc:dd:ee:ff")
    assert data.vlan_engine is None


def test_nsdp_data_vlan_members():
    """Test vlan_members field on NSDPData."""
    data = NSDPData(
        model="GS110EMX",
        mac="aa:bb:cc:dd:ee:ff",
        vlan_members=(
            (1, frozenset({1, 2, 3}), frozenset({3})),
            (10, frozenset({1, 2}), frozenset({1, 2})),
        ),
    )
    assert len(data.vlan_members) == 2
    assert data.vlan_members[0][0] == 1  # vlan_id
    assert 2 in data.vlan_members[0][1]  # member_ports
    assert 3 in data.vlan_members[0][2]  # tagged_ports


def test_nsdp_data_vlan_members_defaults_empty():
    """Test vlan_members defaults to empty tuple."""
    data = NSDPData(model="GS110EMX", mac="aa:bb:cc:dd:ee:ff")
    assert data.vlan_members == ()


def test_nsdp_data_port_statistics():
    """Test port_statistics field on NSDPData."""
    data = NSDPData(
        model="GS110EMX",
        mac="aa:bb:cc:dd:ee:ff",
        port_statistics=((1, 1000, 500, 0), (2, 2000, 1000, 5)),
    )
    assert len(data.port_statistics) == 2
    assert data.port_statistics[0] == (1, 1000, 500, 0)
    # Verify tuple contents: (port_id, bytes_rx, bytes_tx, crc_errors)
    assert data.port_statistics[1][0] == 2  # port_id
    assert data.port_statistics[1][1] == 2000  # bytes_rx
    assert data.port_statistics[1][2] == 1000  # bytes_tx
    assert data.port_statistics[1][3] == 5  # crc_errors


def test_nsdp_data_port_statistics_defaults_empty():
    """Test port_statistics defaults to empty tuple."""
    data = NSDPData(model="GS110EMX", mac="aa:bb:cc:dd:ee:ff")
    assert data.port_statistics == ()
