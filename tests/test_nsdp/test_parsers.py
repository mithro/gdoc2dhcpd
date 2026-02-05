"""Tests for NSDP TLV value parsers."""

import struct

from nsdp.parsers import (
    parse_discovery_response,
    parse_ipv4,
    parse_mac,
    parse_port_pvid,
    parse_port_statistics,
    parse_port_status,
    parse_vlan_members,
)
from nsdp.protocol import NSDPPacket, Op, Tag
from nsdp.types import LinkSpeed


class TestParseIPv4:
    def test_loopback(self):
        assert parse_ipv4(b"\x7f\x00\x00\x01") == "127.0.0.1"

    def test_private(self):
        assert parse_ipv4(b"\x0a\x01\x14\x01") == "10.1.20.1"

    def test_wrong_length(self):
        assert parse_ipv4(b"\x0a\x01") is None


class TestParseMAC:
    def test_normal(self):
        assert parse_mac(b"\x00\x09\x5b\xaa\xbb\xcc") == "00:09:5b:aa:bb:cc"

    def test_wrong_length(self):
        assert parse_mac(b"\x00\x09") is None


class TestParsePortStatus:
    def test_gigabit(self):
        ps = parse_port_status(b"\x01\x05\x01")
        assert ps is not None
        assert ps.port_id == 1
        assert ps.speed is LinkSpeed.GIGABIT

    def test_down(self):
        ps = parse_port_status(b"\x03\x00\x01")
        assert ps is not None
        assert ps.port_id == 3
        assert ps.speed is LinkSpeed.DOWN

    def test_wrong_length(self):
        assert parse_port_status(b"\x01\x05") is None


class TestParsePortStatistics:
    def test_basic(self):
        data = b"\x01"  # port_id=1
        data += struct.pack(">Q", 1000)  # bytes_received
        data += struct.pack(">Q", 500)   # bytes_sent
        data += struct.pack(">Q", 0)     # crc_errors
        data += b"\x00" * 24             # 6 unknown uint64 fields
        ps = parse_port_statistics(data)
        assert ps is not None
        assert ps.port_id == 1
        assert ps.bytes_received == 1000
        assert ps.bytes_sent == 500
        assert ps.crc_errors == 0

    def test_wrong_length(self):
        assert parse_port_statistics(b"\x01\x02") is None


class TestParsePortPVID:
    def test_basic(self):
        pp = parse_port_pvid(b"\x05\x00\x64")  # port=5, vlan=100
        assert pp is not None
        assert pp.port_id == 5
        assert pp.vlan_id == 100

    def test_wrong_length(self):
        assert parse_port_pvid(b"\x05") is None


class TestParseVLANMembers:
    def test_basic_8_port(self):
        """8-port switch: 1-byte member bitmap, 1-byte tagged bitmap."""
        data = struct.pack(">H", 100)  # vlan_id=100
        data += bytes([0b11110000])    # ports 1-4 are members
        data += bytes([0b00010000])    # port 4 is tagged
        vm = parse_vlan_members(data, port_count=8)
        assert vm is not None
        assert vm.vlan_id == 100
        assert vm.member_ports == frozenset({1, 2, 3, 4})
        assert vm.tagged_ports == frozenset({4})

    def test_wrong_length(self):
        assert parse_vlan_members(b"\x00", port_count=8) is None


class TestParseDiscoveryResponse:
    def test_full_response(self):
        """Build a synthetic NSDP read response and parse it."""
        pkt = NSDPPacket(
            op=Op.READ_RESPONSE,
            client_mac=b"\x00" * 6,
            server_mac=b"\x00\x09\x5b\xaa\xbb\xcc",
        )
        pkt.add_tlv(Tag.MODEL, b"GS110EMX")
        pkt.add_tlv(Tag.HOSTNAME, b"switch-1")
        pkt.add_tlv(Tag.MAC, b"\x00\x09\x5b\xaa\xbb\xcc")
        pkt.add_tlv(Tag.IP_ADDRESS, b"\x0a\x01\x14\x01")
        pkt.add_tlv(Tag.NETMASK, b"\xff\xff\xff\x00")
        pkt.add_tlv(Tag.GATEWAY, b"\x0a\x01\x14\xfe")
        pkt.add_tlv(Tag.FIRMWARE_VER_1, b"V2.06.24GR")
        pkt.add_tlv(Tag.DHCP_MODE, b"\x01")
        pkt.add_tlv(Tag.PORT_COUNT, b"\x0a")
        pkt.add_tlv(Tag.PORT_STATUS, b"\x01\x05\x01")  # port 1, 1G
        pkt.add_tlv(Tag.PORT_STATUS, b"\x02\x00\x01")  # port 2, down

        device = parse_discovery_response(pkt)
        assert device.model == "GS110EMX"
        assert device.hostname == "switch-1"
        assert device.mac == "00:09:5b:aa:bb:cc"
        assert device.ip == "10.1.20.1"
        assert device.netmask == "255.255.255.0"
        assert device.gateway == "10.1.20.254"
        assert device.firmware_version == "V2.06.24GR"
        assert device.dhcp_enabled is True
        assert device.port_count == 10
        assert len(device.port_status) == 2
        assert device.port_status[0].speed is LinkSpeed.GIGABIT
        assert device.port_status[1].speed is LinkSpeed.DOWN
