"""Tests for the NSDP UDP client.

Uses mocked sockets since real NSDP requires broadcast and root privileges.
"""

from unittest.mock import patch

from nsdp.client import (
    DISCOVERY_TAGS,
    NSDPClient,
    get_interface_mac,
)
from nsdp.protocol import Op, Tag


class TestGetInterfaceMAC:
    @patch("nsdp.client.Path.read_text")
    def test_returns_6_bytes(self, mock_read_text):
        """get_interface_mac should return 6 bytes."""
        # The function reads from /sys/class/net/{iface}/address
        mock_read_text.return_value = "aa:bb:cc:dd:ee:ff\n"
        mac = get_interface_mac("eth0")
        assert len(mac) == 6
        assert mac == b"\xaa\xbb\xcc\xdd\xee\xff"


class TestNSDPClient:
    def test_discovery_tags(self):
        """DISCOVERY_TAGS should include core identity tags."""
        assert Tag.MODEL in DISCOVERY_TAGS
        assert Tag.HOSTNAME in DISCOVERY_TAGS
        assert Tag.MAC in DISCOVERY_TAGS
        assert Tag.IP_ADDRESS in DISCOVERY_TAGS
        assert Tag.FIRMWARE_VER_1 in DISCOVERY_TAGS
        assert Tag.PORT_COUNT in DISCOVERY_TAGS
        assert Tag.PORT_STATUS in DISCOVERY_TAGS

    def test_build_discovery_packet(self):
        """Build a discovery packet and verify it has correct structure."""
        client = NSDPClient.__new__(NSDPClient)
        client._client_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
        client._sequence = 0

        pkt = client._build_read_request(DISCOVERY_TAGS)
        assert pkt.op == Op.READ_REQUEST
        assert pkt.client_mac == b"\xaa\xbb\xcc\xdd\xee\xff"
        assert pkt.server_mac == b"\x00" * 6
        assert len(pkt.tlvs) == len(DISCOVERY_TAGS)

    def test_build_targeted_request(self):
        """Targeted request should have specific server MAC."""
        client = NSDPClient.__new__(NSDPClient)
        client._client_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
        client._sequence = 0

        target_mac = b"\x00\x09\x5b\x11\x22\x33"
        pkt = client._build_read_request(
            [Tag.MODEL],
            target_mac=target_mac,
        )
        assert pkt.server_mac == target_mac

    def test_unicast_request_has_broadcast_server_mac(self):
        """query_ip sends to IP but with broadcast server MAC in header."""
        client = NSDPClient.__new__(NSDPClient)
        client._client_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
        client._sequence = 0

        # When querying by IP, we don't know the switch MAC yet,
        # so we send with zeros (broadcast) in the server MAC field
        pkt = client._build_read_request([Tag.MODEL])
        assert pkt.server_mac == b"\x00" * 6
