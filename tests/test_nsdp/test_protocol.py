"""Tests for NSDP protocol encoding and decoding."""

import struct

from nsdp.protocol import (
    NSDPPacket,
    Op,
    Tag,
    TLVEntry,
)


class TestTag:
    def test_model_value(self):
        assert Tag.MODEL == 0x0001

    def test_end_marker_value(self):
        assert Tag.END_OF_MARK == 0xFFFF

    def test_port_status_value(self):
        assert Tag.PORT_STATUS == 0x0C00


class TestOp:
    def test_read_request(self):
        assert Op.READ_REQUEST == 0x01

    def test_read_response(self):
        assert Op.READ_RESPONSE == 0x02


class TestTLVEntry:
    def test_encode_empty_value(self):
        """Read-request TLV: tag + length=0, no value."""
        tlv = TLVEntry(tag=Tag.MODEL, value=b"")
        encoded = tlv.encode()
        assert encoded == struct.pack(">HH", 0x0001, 0)

    def test_encode_with_value(self):
        tlv = TLVEntry(tag=Tag.MODEL, value=b"GS110EMX")
        encoded = tlv.encode()
        assert encoded == struct.pack(">HH", 0x0001, 8) + b"GS110EMX"

    def test_decode_single(self):
        data = struct.pack(">HH", 0x0001, 8) + b"GS110EMX"
        tlv, consumed = TLVEntry.decode(data)
        assert tlv.tag == Tag.MODEL
        assert tlv.value == b"GS110EMX"
        assert consumed == 12

    def test_decode_empty_value(self):
        data = struct.pack(">HH", 0x0001, 0)
        tlv, consumed = TLVEntry.decode(data)
        assert tlv.tag == Tag.MODEL
        assert tlv.value == b""
        assert consumed == 4

    def test_end_marker(self):
        data = struct.pack(">HH", 0xFFFF, 0)
        tlv, consumed = TLVEntry.decode(data)
        assert tlv.tag == Tag.END_OF_MARK
        assert consumed == 4


class TestNSDPPacket:
    def test_header_size(self):
        assert NSDPPacket.HEADER_SIZE == 32

    def test_encode_read_request(self):
        """Encode a discovery read request and verify header structure."""
        pkt = NSDPPacket(
            op=Op.READ_REQUEST,
            client_mac=b"\x01\x02\x03\x04\x05\x06",
        )
        pkt.add_tlv(Tag.MODEL)
        pkt.add_tlv(Tag.HOSTNAME)
        encoded = pkt.encode()

        # Header is 32 bytes
        assert len(encoded) >= 32

        # Check signature at offset 0x18
        assert encoded[0x18:0x1C] == b"NSDP"

        # Check version and op
        assert encoded[0] == 0x01  # version
        assert encoded[1] == 0x01  # READ_REQUEST

        # Ends with EOM marker
        assert encoded[-4:] == b"\xFF\xFF\x00\x00"

    def test_roundtrip(self):
        """Encode then decode a packet -- should preserve all fields."""
        pkt = NSDPPacket(
            op=Op.READ_RESPONSE,
            client_mac=b"\x01\x02\x03\x04\x05\x06",
            server_mac=b"\xAA\xBB\xCC\xDD\xEE\xFF",
            sequence=42,
        )
        pkt.add_tlv(Tag.MODEL, b"GS110EMX")
        pkt.add_tlv(Tag.PORT_COUNT, b"\x0A")

        encoded = pkt.encode()
        decoded = NSDPPacket.decode(encoded)

        assert decoded.op == Op.READ_RESPONSE
        assert decoded.client_mac == b"\x01\x02\x03\x04\x05\x06"
        assert decoded.server_mac == b"\xAA\xBB\xCC\xDD\xEE\xFF"
        assert decoded.sequence == 42
        assert len(decoded.tlvs) == 2
        assert decoded.tlvs[0].tag == Tag.MODEL
        assert decoded.tlvs[0].value == b"GS110EMX"
        assert decoded.tlvs[1].tag == Tag.PORT_COUNT
        assert decoded.tlvs[1].value == b"\x0A"

    def test_broadcast_server_mac(self):
        """Default server_mac should be all zeros (broadcast)."""
        pkt = NSDPPacket(
            op=Op.READ_REQUEST,
            client_mac=b"\x00" * 6,
        )
        assert pkt.server_mac == b"\x00" * 6

    def test_decode_ignores_trailing_data(self):
        """Decoding stops at EOM marker even if extra bytes follow."""
        pkt = NSDPPacket(
            op=Op.READ_REQUEST,
            client_mac=b"\x00" * 6,
        )
        pkt.add_tlv(Tag.MODEL)
        encoded = pkt.encode() + b"\xDE\xAD"
        decoded = NSDPPacket.decode(encoded)
        assert len(decoded.tlvs) == 1
