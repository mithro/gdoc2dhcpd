"""Tests for the NSDPData model on Host."""

from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NSDPData, NetworkInterface


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
