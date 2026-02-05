"""NSDP packet encoding and decoding.

Implements the binary wire format for Netgear Switch Discovery Protocol
packets. The format is: 32-byte header + TLV entries + end marker.

All multi-byte integers are big-endian (network byte order).

See docs/nsdp-protocol.md for the full protocol specification.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum


NSDP_SIGNATURE = b"NSDP"

# Port assignments
CLIENT_PORT_V2 = 63321
SERVER_PORT_V2 = 63322
CLIENT_PORT_V1 = 63323
SERVER_PORT_V1 = 63324


class Op(IntEnum):
    """NSDP operation codes (header byte 1).

    READ_REQUEST/RESPONSE are used for discovery and property queries.
    WRITE_REQUEST/RESPONSE are used to modify switch configuration
    (requires authentication via Tag.PASSWORD or Tag.AUTH_V2_PASSWORD).
    """

    READ_REQUEST = 0x01
    READ_RESPONSE = 0x02
    WRITE_REQUEST = 0x03
    WRITE_RESPONSE = 0x04


class Tag(IntEnum):
    """NSDP TLV tag identifiers.

    Each tag represents a switch property. Tags are 16-bit unsigned
    integers encoded big-endian in the packet.

    See docs/nsdp-protocol.md § TLV Tag Registry for byte-level
    encoding details of each tag's value field.
    """

    # Packet markers
    START_OF_MARK = 0x0000
    END_OF_MARK = 0xFFFF

    # Device identity
    MODEL = 0x0001
    HOSTNAME = 0x0003
    MAC = 0x0004
    LOCATION = 0x0005
    IP_ADDRESS = 0x0006
    NETMASK = 0x0007
    GATEWAY = 0x0008
    DHCP_MODE = 0x000B
    FIRMWARE_VER_1 = 0x000D
    FIRMWARE_VER_2 = 0x000E
    PORT_COUNT = 0x6000
    SERIAL_NUMBER = 0x7800

    # Authentication
    PASSWORD = 0x000A
    AUTH_V2_SALT = 0x0017
    AUTH_V2_PASSWORD = 0x001A

    # Port information
    PORT_STATUS = 0x0C00
    PORT_STATISTICS = 0x1000

    # VLAN
    VLAN_ENGINE = 0x2000
    VLAN_MEMBERS = 0x2800
    PORT_PVID = 0x3000

    # Actions (write-only)
    REBOOT = 0x0013
    FACTORY_RESET = 0x0400


@dataclass(frozen=True)
class TLVEntry:
    """A single Type-Length-Value entry in an NSDP packet.

    Attributes:
        tag: Property identifier from the Tag enum.
        value: Raw bytes of the property value (empty for read requests).
    """

    tag: Tag | int
    value: bytes = b""

    def encode(self) -> bytes:
        """Encode this TLV entry to wire format.

        Returns:
            4-byte header (tag + length) followed by value bytes.
        """
        return struct.pack(">HH", int(self.tag), len(self.value)) + self.value

    @classmethod
    def decode(cls, data: bytes) -> tuple[TLVEntry, int]:
        """Decode one TLV entry from the start of a byte buffer.

        Args:
            data: Buffer starting at a TLV header.

        Returns:
            (TLVEntry, bytes_consumed) tuple.

        Raises:
            struct.error: If data is too short for the TLV header.
            ValueError: If data is too short for the declared value length.
        """
        tag_raw, length = struct.unpack_from(">HH", data, 0)
        if len(data) < 4 + length:
            msg = f"TLV tag 0x{tag_raw:04X} declares {length} bytes but only {len(data) - 4} available"
            raise ValueError(msg)
        value = data[4:4 + length]
        try:
            tag = Tag(tag_raw)
        except ValueError:
            tag = tag_raw
        return cls(tag=tag, value=value), 4 + length


@dataclass
class NSDPPacket:
    """An NSDP protocol packet (header + TLV body + end marker).

    The packet structure is:
      - 32-byte fixed header (version, op, MACs, sequence, "NSDP" signature)
      - Variable-length TLV entries
      - 4-byte end marker (tag=0xFFFF, length=0)

    Attributes:
        op: Operation code (read/write request/response).
        client_mac: 6-byte sender MAC address.
        server_mac: 6-byte target MAC (all zeros = broadcast).
        sequence: Packet sequence number (incremented per request).
        result: Result code (0=success in responses).
        tlvs: List of TLV entries in this packet.
    """

    HEADER_SIZE = 32
    HEADER_FORMAT = ">BB H 4s 6s 6s HH 4s 4s"

    op: Op
    client_mac: bytes
    server_mac: bytes = b"\x00" * 6
    sequence: int = 0
    result: int = 0
    tlvs: list[TLVEntry] = field(default_factory=list)

    def add_tlv(self, tag: Tag | int, value: bytes = b"") -> None:
        """Append a TLV entry to this packet.

        For read requests, call with just the tag (value defaults to empty).
        For write requests and responses, provide the value bytes.
        """
        self.tlvs.append(TLVEntry(tag=tag, value=value))

    def encode(self) -> bytes:
        """Encode the full packet to wire format.

        Returns:
            Complete NSDP packet bytes (header + TLVs + end marker).
        """
        header = struct.pack(
            self.HEADER_FORMAT,
            0x01,                   # version
            int(self.op),
            self.result,
            b"\x00" * 4,           # reserved_1
            self.client_mac,
            self.server_mac,
            0,                     # reserved_2
            self.sequence,
            NSDP_SIGNATURE,
            b"\x00" * 4,           # reserved_3
        )
        body = b"".join(tlv.encode() for tlv in self.tlvs)
        end_marker = struct.pack(">HH", 0xFFFF, 0)
        return header + body + end_marker

    @classmethod
    def decode(cls, data: bytes) -> NSDPPacket:
        """Decode an NSDP packet from raw bytes.

        Args:
            data: Raw packet bytes (at least 32 bytes for header).

        Returns:
            Decoded NSDPPacket with all TLV entries parsed.

        Raises:
            ValueError: If packet is too short, has wrong signature, or
                contains malformed TLV entries.
        """
        if len(data) < cls.HEADER_SIZE:
            msg = f"Packet too short: {len(data)} bytes (need at least {cls.HEADER_SIZE})"
            raise ValueError(msg)

        (
            _version, op_raw, result,
            _reserved_1, client_mac, server_mac,
            _reserved_2, sequence,
            signature, _reserved_3,
        ) = struct.unpack_from(cls.HEADER_FORMAT, data, 0)

        if signature != NSDP_SIGNATURE:
            msg = f"Invalid signature: {signature!r} (expected {NSDP_SIGNATURE!r})"
            raise ValueError(msg)

        pkt = cls(
            op=Op(op_raw),
            client_mac=client_mac,
            server_mac=server_mac,
            sequence=sequence,
            result=result,
        )

        # Parse TLV body
        offset = cls.HEADER_SIZE
        while offset < len(data):
            tlv, consumed = TLVEntry.decode(data[offset:])
            if tlv.tag == Tag.END_OF_MARK:
                break
            pkt.tlvs.append(tlv)
            offset += consumed

        return pkt
