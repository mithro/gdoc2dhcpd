# NSDP Discovery Protocol Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a standalone NSDP (Netgear Switch Discovery Protocol) package and gdoc2netcfg supplement to discover unmanaged Netgear switches (GS110EMX / `netgear-switch-plus`) that lack SNMP support.

**Architecture:** Pure Python implementation of the NSDP UDP broadcast protocol using only stdlib (`struct`, `socket`). The `src/nsdp/` package is fully independent — no dependency on gdoc2netcfg. A thin supplement bridge layer in `src/gdoc2netcfg/supplements/nsdp.py` follows the existing scan/cache/enrich pattern. Full protocol documentation in `docs/nsdp-protocol.md`.

**Tech Stack:** Python 3.11+ stdlib only (`struct`, `socket`, `enum`, `dataclasses`). No external dependencies for the protocol package.

---

### Task 1: Create NSDP protocol documentation

**Files:**
- Create: `docs/nsdp-protocol.md`

**Step 1: Write protocol documentation**

Create `docs/nsdp-protocol.md` with the full NSDP protocol specification:

```markdown
# NSDP (Netgear Switch Discovery Protocol) Specification

## Overview

NSDP is a proprietary UDP broadcast protocol used by Netgear for discovering and
managing ProSAFE and Plus series switches. It uses a simple Type-Length-Value (TLV)
message format.

## Transport

| Parameter       | Value              |
|-----------------|--------------------|
| Protocol        | UDP (stateless)    |
| Client port     | 63321 (v2), 63323 (v1) |
| Server port     | 63322 (v2), 63324 (v1) |
| Discovery       | Broadcast to 255.255.255.255 |
| Byte order      | Big-endian (network byte order) |

## Packet Structure

### Header (32 bytes)

| Offset | Size | Field            | Description |
|--------|------|------------------|-------------|
| 0x00   | 1    | version          | Always 0x01 |
| 0x01   | 1    | operation        | See Operation Codes |
| 0x02   | 2    | result           | 0x0000=success, 0x0700=bad password |
| 0x04   | 4    | reserved_1       | Zeroed |
| 0x08   | 6    | client_mac       | Sender (manager) MAC address |
| 0x0E   | 6    | server_mac       | Target device MAC (00:00:00:00:00:00 = broadcast) |
| 0x14   | 2    | reserved_2       | Zeroed |
| 0x16   | 2    | sequence         | Incrementing per request |
| 0x18   | 4    | signature        | ASCII "NSDP" (0x4E534450) |
| 0x1C   | 4    | reserved_3       | Zeroed |

### Operation Codes

| Value | Name           |
|-------|----------------|
| 0x01  | Read Request   |
| 0x02  | Read Response  |
| 0x03  | Write Request  |
| 0x04  | Write Response |

### TLV Entry (4-byte header + variable data)

| Offset | Size | Field  | Description |
|--------|------|--------|-------------|
| 0x00   | 2    | tag    | Property identifier (big-endian uint16) |
| 0x02   | 2    | length | Length of value in bytes (big-endian uint16) |
| 0x04   | N    | value  | Property data (N = length bytes) |

For **read requests**, TLV entries have length=0 (request the property).
For **read responses** and **write requests**, TLV entries include data.

### End Marker

Every packet ends with tag=0xFFFF, length=0x0000 (4 bytes: FF FF 00 00).

## TLV Tag Registry

### Device Identity

| Tag      | Name             | Type    | R/W | Description |
|----------|------------------|---------|-----|-------------|
| 0x0001   | model            | string  | R   | Device model (e.g. "GS110EMX") |
| 0x0003   | hostname         | string  | R/W | Device name / hostname |
| 0x0004   | mac              | 6 bytes | R   | Device MAC address |
| 0x0005   | location         | string  | R/W | System location |
| 0x0006   | ip_address       | 4 bytes | R/W | Management IPv4 address |
| 0x0007   | netmask          | 4 bytes | R/W | IPv4 subnet mask |
| 0x0008   | gateway          | 4 bytes | R/W | Default gateway IPv4 |
| 0x000B   | dhcp_mode        | 1 byte  | R/W | 0=disabled, 1=enabled |
| 0x000D   | firmware_ver_1   | string  | R   | Firmware version (slot 1) |
| 0x000E   | firmware_ver_2   | string  | R   | Firmware version (slot 2) |
| 0x6000   | port_count       | 1 byte  | R   | Number of ports |
| 0x7800   | serial_number    | string  | R   | Device serial number |

### Port Information

| Tag      | Name             | Type    | R/W | Description |
|----------|------------------|---------|-----|-------------|
| 0x0C00   | port_status      | 3 bytes | R   | Per-port link status (repeated per port) |
| 0x1000   | port_statistics  | 49 bytes| R   | Per-port traffic stats (repeated per port) |

#### Port Status Encoding (3 bytes)

| Byte | Field       | Values |
|------|-------------|--------|
| 0    | port_id     | 1-based port number |
| 1    | link_speed  | 0x00=down, 0x01=10M-half, 0x02=10M-full, 0x03=100M-half, 0x04=100M-full, 0x05=1G |
| 2    | unknown     | Usually 0x01 |

**Note:** Speed values for 2.5G, 5G, and 10G are undocumented. The GS110EMX has
10G ports — actual values need to be discovered via packet capture on real hardware.

#### Port Statistics Encoding (49 bytes)

| Offset | Size | Field           |
|--------|------|-----------------|
| 0      | 1    | port_id         |
| 1-8    | 8    | bytes_received  |
| 9-16   | 8    | bytes_sent      |
| 17-24  | 8    | crc_errors      |
| 25-48  | 24   | unknown (6x uint64) |

### VLAN Configuration

| Tag      | Name             | Type    | R/W | Description |
|----------|------------------|---------|-----|-------------|
| 0x2000   | vlan_engine      | 1 byte  | R/W | 0=off, 1=basic-port, 2=adv-port, 3=basic-802.1Q, 4=adv-802.1Q |
| 0x2800   | vlan_members     | 4+ bytes| R   | VLAN membership (vlanId(2) + member bitfield + tagged bitfield) |
| 0x3000   | port_pvid        | 3 bytes | R   | Port PVID (portId(1) + vlanId(2)) |

### Authentication

| Tag      | Name             | Type    | Description |
|----------|------------------|---------|-------------|
| 0x000A   | password         | variable| XOR-encoded with key "NtgrSmartSwitchRock" |
| 0x0017   | auth_v2_salt     | variable| Auth v2 password salt (newer firmware) |
| 0x001A   | auth_v2_password | variable| Auth v2 password (newer firmware) |

### Other

| Tag      | Name               | Type    | R/W | Description |
|----------|--------------------|---------|-----|-------------|
| 0x0013   | reboot             | empty   | W   | Trigger device reboot |
| 0x0400   | factory_reset      | empty   | W   | Factory reset |
| 0x0000   | start_of_mark      | empty   | -   | Packet start marker |
| 0xFFFF   | end_of_mark        | empty   | -   | Packet end marker |

## Password Encoding

Passwords are XOR-encoded with the repeating key `NtgrSmartSwitchRock` (19 bytes).

## References

- [CursedHardware/go-nsdp protocol-design.md](https://github.com/CursedHardware/go-nsdp/blob/master/docs/protocol-design.md)
- [kamiraux/wireshark-nsdp NSDP_info](https://github.com/kamiraux/wireshark-nsdp/blob/master/NSDP_info)
- [AlbanBedel/libnsdp](https://github.com/AlbanBedel/libnsdp)
- [hdecarne-github/go-nsdp](https://github.com/hdecarne-github/go-nsdp)
```

**Step 2: Commit**

```bash
git add docs/nsdp-protocol.md
git commit -m "docs: add NSDP protocol specification"
```

---

### Task 2: Create NSDP protocol types module

**Files:**
- Create: `src/nsdp/__init__.py`
- Create: `src/nsdp/types.py`
- Create: `tests/test_nsdp/__init__.py`
- Create: `tests/test_nsdp/test_types.py`

**Step 1: Write failing tests for NSDP data types**

Create `tests/test_nsdp/__init__.py` (empty) and `tests/test_nsdp/test_types.py`:

```python
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
```

**Step 2: Run tests to verify they fail**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/feature-nsdp && uv run pytest tests/test_nsdp/test_types.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'nsdp'`

**Step 3: Implement NSDP types**

Create `src/nsdp/__init__.py`:

```python
"""NSDP (Netgear Switch Discovery Protocol) — pure-Python implementation.

A standalone protocol library for discovering and querying Netgear switches
via the proprietary NSDP UDP broadcast protocol. See docs/nsdp-protocol.md
for the full protocol specification.

This package has no external dependencies beyond the Python standard library.
"""
```

Create `src/nsdp/types.py`:

```python
"""NSDP data types for device discovery results.

These frozen dataclasses represent the information returned by Netgear
switches in response to NSDP discovery and read requests. All types are
immutable to match the conventions used in the gdoc2netcfg project.

See docs/nsdp-protocol.md for the protocol specification and TLV tag
registry that these types correspond to.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class LinkSpeed(IntEnum):
    """Port link speed/status as reported in NSDP tag 0x0C00 byte 1.

    Values 0x00–0x05 are documented. Values for 2.5G, 5G, and 10G
    are present on newer hardware (e.g. GS110EMX) but not yet documented
    in any public specification — they need to be discovered via packet
    capture on real hardware.
    """

    DOWN = 0x00
    HALF_10M = 0x01
    FULL_10M = 0x02
    HALF_100M = 0x03
    FULL_100M = 0x04
    GIGABIT = 0x05
    UNKNOWN = 0xFF  # Placeholder for undiscovered speed values

    @classmethod
    def from_byte(cls, value: int) -> LinkSpeed:
        """Parse a speed byte, returning UNKNOWN for unrecognised values."""
        try:
            return cls(value)
        except ValueError:
            return cls.UNKNOWN

    @property
    def speed_mbps(self) -> int:
        """Approximate speed in Mbps (0 for down/unknown)."""
        return {
            LinkSpeed.DOWN: 0,
            LinkSpeed.HALF_10M: 10,
            LinkSpeed.FULL_10M: 10,
            LinkSpeed.HALF_100M: 100,
            LinkSpeed.FULL_100M: 100,
            LinkSpeed.GIGABIT: 1000,
            LinkSpeed.UNKNOWN: 0,
        }.get(self, 0)


class VLANEngine(IntEnum):
    """VLAN engine mode as reported in NSDP tag 0x2000.

    Controls how the switch handles VLAN assignment.
    """

    DISABLED = 0
    BASIC_PORT = 1       # Port-based, port in 1 VLAN only
    ADVANCED_PORT = 2    # Port-based, port in multiple VLANs
    BASIC_802_1Q = 3     # 802.1Q, port in 1 VLAN only
    ADVANCED_802_1Q = 4  # 802.1Q, tagged/untagged, multiple VLANs


@dataclass(frozen=True)
class PortStatus:
    """Link status for a single switch port (NSDP tag 0x0C00).

    Attributes:
        port_id: 1-based port number.
        speed: Detected link speed/duplex.
    """

    port_id: int
    speed: LinkSpeed


@dataclass(frozen=True)
class PortStatistics:
    """Traffic statistics for a single switch port (NSDP tag 0x1000).

    Attributes:
        port_id: 1-based port number.
        bytes_received: Total bytes received on this port.
        bytes_sent: Total bytes sent from this port.
        crc_errors: CRC error count.
    """

    port_id: int
    bytes_received: int
    bytes_sent: int
    crc_errors: int


@dataclass(frozen=True)
class VLANMembership:
    """VLAN port membership (NSDP tag 0x2800).

    Attributes:
        vlan_id: 802.1Q VLAN ID.
        member_ports: Set of port IDs that are members of this VLAN.
        tagged_ports: Subset of member_ports that are tagged (802.1Q trunk).
    """

    vlan_id: int
    member_ports: frozenset[int]
    tagged_ports: frozenset[int] = field(default_factory=frozenset)

    @property
    def untagged_ports(self) -> frozenset[int]:
        """Ports that are untagged members (access ports)."""
        return self.member_ports - self.tagged_ports


@dataclass(frozen=True)
class PortPVID:
    """Port native/default VLAN ID (NSDP tag 0x3000).

    Attributes:
        port_id: 1-based port number.
        vlan_id: Default VLAN for untagged frames on this port.
    """

    port_id: int
    vlan_id: int


@dataclass(frozen=True)
class NSDPDevice:
    """Complete device information discovered via NSDP.

    Populated by combining responses from multiple NSDP TLV tags.
    Fields are optional because not all switches report all properties.

    Attributes:
        model: Device model string (tag 0x0001), e.g. "GS110EMX".
        mac: Device MAC address as colon-separated hex string (tag 0x0004).
        hostname: Device name (tag 0x0003).
        ip: Management IPv4 address as dotted-quad string (tag 0x0006).
        netmask: IPv4 subnet mask (tag 0x0007).
        gateway: Default gateway IPv4 (tag 0x0008).
        firmware_version: Firmware version string (tag 0x000D).
        dhcp_enabled: Whether DHCP is enabled (tag 0x000B).
        port_count: Number of ports (tag 0x6000).
        serial_number: Device serial number (tag 0x7800).
        port_status: Per-port link status (tag 0x0C00, repeated).
        port_statistics: Per-port traffic stats (tag 0x1000, repeated).
        vlan_engine: VLAN engine mode (tag 0x2000).
        vlan_members: VLAN membership table (tag 0x2800, repeated).
        port_pvids: Port native VLAN IDs (tag 0x3000, repeated).
    """

    model: str
    mac: str
    hostname: str | None = None
    ip: str | None = None
    netmask: str | None = None
    gateway: str | None = None
    firmware_version: str | None = None
    dhcp_enabled: bool | None = None
    port_count: int | None = None
    serial_number: str | None = None
    port_status: tuple[PortStatus, ...] = ()
    port_statistics: tuple[PortStatistics, ...] = ()
    vlan_engine: VLANEngine | None = None
    vlan_members: tuple[VLANMembership, ...] = ()
    port_pvids: tuple[PortPVID, ...] = ()
```

**Step 4: Add `src/nsdp` to pyproject.toml**

In `pyproject.toml`, under `[tool.hatch.build.targets.wheel]`, change:
```toml
packages = ["src/gdoc2netcfg"]
```
to:
```toml
packages = ["src/gdoc2netcfg", "src/nsdp"]
```

Also add `"src"` to `[tool.pytest.ini_options]` pythonpath if not already there (it is).

**Step 5: Run tests to verify they pass**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/feature-nsdp && uv run pytest tests/test_nsdp/test_types.py -v`
Expected: All tests PASS.

**Step 6: Commit**

```bash
git add src/nsdp/__init__.py src/nsdp/types.py tests/test_nsdp/__init__.py tests/test_nsdp/test_types.py pyproject.toml
git commit -m "feat(nsdp): add data type models for NSDP protocol"
```

---

### Task 3: Create NSDP TLV tag registry and packet codec

**Files:**
- Create: `src/nsdp/protocol.py`
- Create: `tests/test_nsdp/test_protocol.py`

**Step 1: Write failing tests for TLV encoding/decoding**

Create `tests/test_nsdp/test_protocol.py`:

```python
"""Tests for NSDP protocol encoding and decoding."""

import struct

from nsdp.protocol import (
    NSDP_SIGNATURE,
    Op,
    Tag,
    TLVEntry,
    NSDPPacket,
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
        """Encode then decode a packet — should preserve all fields."""
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
```

**Step 2: Run tests to verify they fail**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/feature-nsdp && uv run pytest tests/test_nsdp/test_protocol.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'nsdp.protocol'`

**Step 3: Implement protocol module**

Create `src/nsdp/protocol.py`:

```python
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
```

**Step 4: Run tests to verify they pass**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/feature-nsdp && uv run pytest tests/test_nsdp/test_protocol.py -v`
Expected: All tests PASS.

**Step 5: Run all tests to check for regressions**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/feature-nsdp && uv run pytest -q`
Expected: 771 + new tests all PASS.

**Step 6: Commit**

```bash
git add src/nsdp/protocol.py tests/test_nsdp/test_protocol.py
git commit -m "feat(nsdp): add TLV tag registry and packet codec"
```

---

### Task 4: Create NSDP TLV value parsers

**Files:**
- Create: `src/nsdp/parsers.py`
- Create: `tests/test_nsdp/test_parsers.py`

**Step 1: Write failing tests for TLV value parsing**

Create `tests/test_nsdp/test_parsers.py`:

```python
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
from nsdp.protocol import NSDPPacket, Op, Tag, TLVEntry
from nsdp.types import LinkSpeed, VLANEngine


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
```

**Step 2: Run tests to verify they fail**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/feature-nsdp && uv run pytest tests/test_nsdp/test_parsers.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'nsdp.parsers'`

**Step 3: Implement parsers**

Create `src/nsdp/parsers.py`:

```python
"""NSDP TLV value parsers.

Each function parses the raw bytes from a specific TLV tag into a typed
Python object. Returns None for malformed or truncated data.

The parse_discovery_response() function combines all parsers to convert
a complete NSDP read response into an NSDPDevice.

See docs/nsdp-protocol.md § TLV Tag Registry for byte-level encoding.
"""

from __future__ import annotations

import socket
import struct

from nsdp.protocol import NSDPPacket, Tag
from nsdp.types import (
    LinkSpeed,
    NSDPDevice,
    PortPVID,
    PortStatistics,
    PortStatus,
    VLANEngine,
    VLANMembership,
)


def parse_ipv4(data: bytes) -> str | None:
    """Parse a 4-byte IPv4 address into dotted-quad notation.

    Returns None if data is not exactly 4 bytes.
    """
    if len(data) != 4:
        return None
    return socket.inet_ntoa(data)


def parse_mac(data: bytes) -> str | None:
    """Parse a 6-byte MAC address into colon-separated hex notation.

    Returns None if data is not exactly 6 bytes.
    """
    if len(data) != 6:
        return None
    return ":".join(f"{b:02x}" for b in data)


def parse_port_status(data: bytes) -> PortStatus | None:
    """Parse NSDP tag 0x0C00 (3 bytes: port_id, speed, unknown).

    Returns None if data is not exactly 3 bytes.
    """
    if len(data) != 3:
        return None
    port_id = data[0]
    speed = LinkSpeed.from_byte(data[1])
    return PortStatus(port_id=port_id, speed=speed)


def parse_port_statistics(data: bytes) -> PortStatistics | None:
    """Parse NSDP tag 0x1000 (49 bytes: port_id + 6x uint64).

    Returns None if data is not exactly 49 bytes.
    """
    if len(data) != 49:
        return None
    port_id = data[0]
    bytes_received, bytes_sent, crc_errors = struct.unpack_from(">QQQ", data, 1)
    return PortStatistics(
        port_id=port_id,
        bytes_received=bytes_received,
        bytes_sent=bytes_sent,
        crc_errors=crc_errors,
    )


def parse_port_pvid(data: bytes) -> PortPVID | None:
    """Parse NSDP tag 0x3000 (3 bytes: port_id(1) + vlan_id(2)).

    Returns None if data is not exactly 3 bytes.
    """
    if len(data) != 3:
        return None
    port_id = data[0]
    vlan_id = struct.unpack_from(">H", data, 1)[0]
    return PortPVID(port_id=port_id, vlan_id=vlan_id)


def _bitmap_to_ports(bitmap: bytes) -> frozenset[int]:
    """Convert a port bitmap (MSB-first) to a set of 1-based port IDs.

    Each byte represents 8 ports. Bit 7 of byte 0 = port 1,
    bit 6 = port 2, ..., bit 0 = port 8.
    """
    ports = set()
    for byte_idx, byte_val in enumerate(bitmap):
        for bit in range(8):
            if byte_val & (0x80 >> bit):
                ports.add(byte_idx * 8 + bit + 1)
    return frozenset(ports)


def parse_vlan_members(data: bytes, port_count: int = 8) -> VLANMembership | None:
    """Parse NSDP tag 0x2800 (vlan_id(2) + member bitmap + tagged bitmap).

    The bitmap size depends on port_count (ceil(port_count/8) bytes each).
    Returns None if data is too short.
    """
    bitmap_bytes = (port_count + 7) // 8
    expected_len = 2 + bitmap_bytes * 2
    if len(data) < expected_len:
        return None
    vlan_id = struct.unpack_from(">H", data, 0)[0]
    member_bitmap = data[2:2 + bitmap_bytes]
    tagged_bitmap = data[2 + bitmap_bytes:2 + bitmap_bytes * 2]
    return VLANMembership(
        vlan_id=vlan_id,
        member_ports=_bitmap_to_ports(member_bitmap),
        tagged_ports=_bitmap_to_ports(tagged_bitmap),
    )


def parse_discovery_response(packet: NSDPPacket) -> NSDPDevice:
    """Parse a complete NSDP read response into an NSDPDevice.

    Iterates all TLV entries in the packet and extracts known properties.
    Unknown tags are silently skipped to handle newer firmware gracefully.

    Args:
        packet: Decoded NSDPPacket (should be Op.READ_RESPONSE).

    Returns:
        NSDPDevice with all parsed fields populated.

    Raises:
        ValueError: If no model tag is found in the response.
    """
    model: str | None = None
    mac: str | None = None
    hostname: str | None = None
    ip: str | None = None
    netmask: str | None = None
    gateway: str | None = None
    firmware_version: str | None = None
    dhcp_enabled: bool | None = None
    port_count: int | None = None
    serial_number: str | None = None
    vlan_engine: VLANEngine | None = None
    port_statuses: list[PortStatus] = []
    port_stats: list[PortStatistics] = []
    vlan_members_list: list[VLANMembership] = []
    port_pvids: list[PortPVID] = []

    for tlv in packet.tlvs:
        tag = tlv.tag
        val = tlv.value

        if tag == Tag.MODEL:
            model = val.decode("ascii", errors="replace").rstrip("\x00")
        elif tag == Tag.HOSTNAME:
            hostname = val.decode("ascii", errors="replace").rstrip("\x00")
        elif tag == Tag.MAC:
            mac = parse_mac(val)
        elif tag == Tag.IP_ADDRESS:
            ip = parse_ipv4(val)
        elif tag == Tag.NETMASK:
            netmask = parse_ipv4(val)
        elif tag == Tag.GATEWAY:
            gateway = parse_ipv4(val)
        elif tag == Tag.FIRMWARE_VER_1:
            firmware_version = val.decode("ascii", errors="replace").rstrip("\x00")
        elif tag == Tag.DHCP_MODE:
            dhcp_enabled = bool(val[0]) if val else None
        elif tag == Tag.PORT_COUNT:
            port_count = val[0] if val else None
        elif tag == Tag.SERIAL_NUMBER:
            serial_number = val.decode("ascii", errors="replace").rstrip("\x00")
        elif tag == Tag.PORT_STATUS:
            ps = parse_port_status(val)
            if ps is not None:
                port_statuses.append(ps)
        elif tag == Tag.PORT_STATISTICS:
            ps = parse_port_statistics(val)
            if ps is not None:
                port_stats.append(ps)
        elif tag == Tag.VLAN_ENGINE:
            if val:
                try:
                    vlan_engine = VLANEngine(val[0])
                except ValueError:
                    pass
        elif tag == Tag.VLAN_MEMBERS:
            pc = port_count or 8
            vm = parse_vlan_members(val, port_count=pc)
            if vm is not None:
                vlan_members_list.append(vm)
        elif tag == Tag.PORT_PVID:
            pp = parse_port_pvid(val)
            if pp is not None:
                port_pvids.append(pp)

    if model is None:
        msg = "No model tag in NSDP response"
        raise ValueError(msg)
    if mac is None:
        mac = parse_mac(packet.server_mac) or "00:00:00:00:00:00"

    return NSDPDevice(
        model=model,
        mac=mac,
        hostname=hostname,
        ip=ip,
        netmask=netmask,
        gateway=gateway,
        firmware_version=firmware_version,
        dhcp_enabled=dhcp_enabled,
        port_count=port_count,
        serial_number=serial_number,
        port_status=tuple(port_statuses),
        port_statistics=tuple(port_stats),
        vlan_engine=vlan_engine,
        vlan_members=tuple(vlan_members_list),
        port_pvids=tuple(port_pvids),
    )
```

**Step 4: Run tests to verify they pass**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/feature-nsdp && uv run pytest tests/test_nsdp/test_parsers.py -v`
Expected: All tests PASS.

**Step 5: Run all tests**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/feature-nsdp && uv run pytest -q`
Expected: All tests PASS.

**Step 6: Commit**

```bash
git add src/nsdp/parsers.py tests/test_nsdp/test_parsers.py
git commit -m "feat(nsdp): add TLV value parsers for device properties"
```

---

### Task 5: Create NSDP UDP client

**Files:**
- Create: `src/nsdp/client.py`
- Create: `tests/test_nsdp/test_client.py`

**Step 1: Write failing tests for the client**

Create `tests/test_nsdp/test_client.py`:

```python
"""Tests for the NSDP UDP client.

Uses mocked sockets since real NSDP requires broadcast and root privileges.
"""

import socket
from unittest.mock import MagicMock, patch

from nsdp.client import (
    DISCOVERY_TAGS,
    NSDPClient,
    get_interface_mac,
)
from nsdp.protocol import NSDPPacket, Op, Tag


class TestGetInterfaceMAC:
    @patch("nsdp.client.socket.socket")
    def test_returns_6_bytes(self, mock_socket_cls):
        """get_interface_mac should return 6 bytes."""
        # Mock getsockname to return a MAC-like address
        mock_sock = MagicMock()
        mock_socket_cls.return_value.__enter__ = MagicMock(return_value=mock_sock)
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)

        # The function reads from /sys/class/net/{iface}/address
        with patch("builtins.open", create=True) as mock_open:
            mock_open.return_value.__enter__ = MagicMock(
                return_value=MagicMock(read=MagicMock(return_value="aa:bb:cc:dd:ee:ff\n"))
            )
            mock_open.return_value.__exit__ = MagicMock(return_value=False)
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
```

**Step 2: Run tests to verify they fail**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/feature-nsdp && uv run pytest tests/test_nsdp/test_client.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'nsdp.client'`

**Step 3: Implement client**

Create `src/nsdp/client.py`:

```python
"""NSDP UDP client for switch discovery and property queries.

Sends NSDP broadcast or targeted UDP packets and collects responses.
Requires binding to UDP port 63321 which may need elevated privileges
(root/sudo or CAP_NET_RAW capability) on Linux.

Usage:
    client = NSDPClient("eth0")
    devices = client.discover(timeout=2.0)
    for device in devices:
        print(f"{device.model} at {device.ip} ({device.mac})")

See docs/nsdp-protocol.md for protocol details.
"""

from __future__ import annotations

import socket
import struct
from pathlib import Path

from nsdp.parsers import parse_discovery_response
from nsdp.protocol import (
    CLIENT_PORT_V2,
    SERVER_PORT_V2,
    NSDPPacket,
    Op,
    Tag,
)
from nsdp.types import NSDPDevice


# Tags requested during broadcast discovery — covers device identity,
# port status, and VLAN configuration.
DISCOVERY_TAGS: list[Tag] = [
    Tag.MODEL,
    Tag.HOSTNAME,
    Tag.MAC,
    Tag.IP_ADDRESS,
    Tag.NETMASK,
    Tag.GATEWAY,
    Tag.FIRMWARE_VER_1,
    Tag.DHCP_MODE,
    Tag.PORT_COUNT,
    Tag.SERIAL_NUMBER,
    Tag.PORT_STATUS,
    Tag.PORT_STATISTICS,
    Tag.VLAN_ENGINE,
    Tag.VLAN_MEMBERS,
    Tag.PORT_PVID,
]


def get_interface_mac(interface: str) -> bytes:
    """Read the MAC address of a network interface from sysfs.

    Args:
        interface: Network interface name (e.g. "eth0", "enp0s31f6").

    Returns:
        6-byte MAC address.

    Raises:
        FileNotFoundError: If the interface does not exist.
        ValueError: If the MAC address cannot be parsed.
    """
    mac_path = Path(f"/sys/class/net/{interface}/address")
    mac_str = mac_path.read_text().strip()
    octets = bytes.fromhex(mac_str.replace(":", ""))
    if len(octets) != 6:
        msg = f"Invalid MAC from {mac_path}: {mac_str!r}"
        raise ValueError(msg)
    return octets


class NSDPClient:
    """UDP client for NSDP switch discovery and property queries.

    Creates a UDP socket bound to the NSDP client port (63321) on the
    specified network interface. The socket has SO_BROADCAST enabled
    for discovery requests.

    Args:
        interface: Network interface to bind to (e.g. "eth0").
            Used to determine the client MAC address and to bind
            the socket via SO_BINDTODEVICE.

    Raises:
        PermissionError: If binding to port 63321 requires elevated
            privileges. Run with sudo or grant CAP_NET_RAW:
            ``sudo setcap cap_net_raw+ep $(which python3)``
        FileNotFoundError: If the interface does not exist.
    """

    def __init__(self, interface: str) -> None:
        self._interface = interface
        self._client_mac = get_interface_mac(interface)
        self._sequence = 0
        self._sock: socket.socket | None = None

    def _get_socket(self) -> socket.socket:
        """Create or return the cached UDP socket."""
        if self._sock is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Bind to specific interface (Linux only)
            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_BINDTODEVICE,
                self._interface.encode() + b"\0",
            )
            sock.bind(("", CLIENT_PORT_V2))
            self._sock = sock
        return self._sock

    def _next_sequence(self) -> int:
        """Return the next sequence number (wraps at 65535)."""
        seq = self._sequence
        self._sequence = (self._sequence + 1) & 0xFFFF
        return seq

    def _build_read_request(
        self,
        tags: list[Tag],
        target_mac: bytes | None = None,
    ) -> NSDPPacket:
        """Build an NSDP read request packet.

        Args:
            tags: List of property tags to request.
            target_mac: Specific device MAC to query (None = broadcast).

        Returns:
            Encoded NSDPPacket ready to send.
        """
        pkt = NSDPPacket(
            op=Op.READ_REQUEST,
            client_mac=self._client_mac,
            server_mac=target_mac or b"\x00" * 6,
            sequence=self._next_sequence(),
        )
        for tag in tags:
            pkt.add_tlv(tag)
        return pkt

    def discover(
        self,
        timeout: float = 2.0,
        tags: list[Tag] | None = None,
    ) -> list[NSDPDevice]:
        """Broadcast an NSDP discovery request and collect responses.

        Sends a single UDP broadcast packet requesting the specified tags
        (defaults to DISCOVERY_TAGS) and waits for responses until the
        timeout expires.

        Args:
            timeout: Seconds to wait for responses after sending.
            tags: Tags to request (default: DISCOVERY_TAGS).

        Returns:
            List of NSDPDevice objects, one per responding switch.
        """
        sock = self._get_socket()
        sock.settimeout(timeout)

        request_tags = tags or DISCOVERY_TAGS
        pkt = self._build_read_request(request_tags)
        sock.sendto(pkt.encode(), ("255.255.255.255", SERVER_PORT_V2))

        devices: list[NSDPDevice] = []
        seen_macs: set[str] = set()

        while True:
            try:
                data, _addr = sock.recvfrom(4096)
            except socket.timeout:
                break

            try:
                response = NSDPPacket.decode(data)
            except (ValueError, struct.error):
                continue

            if response.op != Op.READ_RESPONSE:
                continue

            try:
                device = parse_discovery_response(response)
            except ValueError:
                continue

            # Deduplicate by MAC address
            if device.mac not in seen_macs:
                seen_macs.add(device.mac)
                devices.append(device)

        return devices

    def read_device(
        self,
        target_mac: bytes,
        tags: list[Tag] | None = None,
        timeout: float = 2.0,
    ) -> NSDPDevice | None:
        """Send a targeted read request to a specific switch.

        Args:
            target_mac: 6-byte MAC of the target device.
            tags: Tags to request (default: DISCOVERY_TAGS).
            timeout: Seconds to wait for the response.

        Returns:
            NSDPDevice if the switch responds, None otherwise.
        """
        sock = self._get_socket()
        sock.settimeout(timeout)

        request_tags = tags or DISCOVERY_TAGS
        pkt = self._build_read_request(request_tags, target_mac=target_mac)
        sock.sendto(pkt.encode(), ("255.255.255.255", SERVER_PORT_V2))

        while True:
            try:
                data, _addr = sock.recvfrom(4096)
            except socket.timeout:
                return None

            try:
                response = NSDPPacket.decode(data)
            except (ValueError, struct.error):
                continue

            if response.op != Op.READ_RESPONSE:
                continue

            try:
                return parse_discovery_response(response)
            except ValueError:
                continue

    def close(self) -> None:
        """Close the UDP socket."""
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def __enter__(self) -> NSDPClient:
        return self

    def __exit__(self, *_exc) -> None:
        self.close()
```

**Step 4: Run tests to verify they pass**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/feature-nsdp && uv run pytest tests/test_nsdp/test_client.py -v`
Expected: All tests PASS.

**Step 5: Commit**

```bash
git add src/nsdp/client.py tests/test_nsdp/test_client.py
git commit -m "feat(nsdp): add UDP client for switch discovery"
```

---

### Task 6: Update `src/nsdp/__init__.py` public API exports

**Files:**
- Modify: `src/nsdp/__init__.py`

**Step 1: Update exports**

Update `src/nsdp/__init__.py` to export the public API:

```python
"""NSDP (Netgear Switch Discovery Protocol) — pure-Python implementation.

A standalone protocol library for discovering and querying Netgear switches
via the proprietary NSDP UDP broadcast protocol. See docs/nsdp-protocol.md
for the full protocol specification.

This package has no external dependencies beyond the Python standard library.

Quick start:
    from nsdp import NSDPClient

    with NSDPClient("eth0") as client:
        devices = client.discover(timeout=2.0)
        for device in devices:
            print(f"{device.model} at {device.ip}")
"""

from nsdp.client import DISCOVERY_TAGS, NSDPClient, get_interface_mac
from nsdp.parsers import parse_discovery_response
from nsdp.protocol import NSDP_SIGNATURE, NSDPPacket, Op, Tag, TLVEntry
from nsdp.types import (
    LinkSpeed,
    NSDPDevice,
    PortPVID,
    PortStatistics,
    PortStatus,
    VLANEngine,
    VLANMembership,
)

__all__ = [
    "DISCOVERY_TAGS",
    "LinkSpeed",
    "NSDP_SIGNATURE",
    "NSDPClient",
    "NSDPDevice",
    "NSDPPacket",
    "Op",
    "PortPVID",
    "PortStatistics",
    "PortStatus",
    "Tag",
    "TLVEntry",
    "VLANEngine",
    "VLANMembership",
    "get_interface_mac",
    "parse_discovery_response",
]
```

**Step 2: Run all tests**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/feature-nsdp && uv run pytest -q`
Expected: All tests PASS.

**Step 3: Lint**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/feature-nsdp && uv run ruff check src/nsdp/ tests/test_nsdp/`
Expected: No issues.

**Step 4: Commit**

```bash
git add src/nsdp/__init__.py
git commit -m "feat(nsdp): update package exports with full public API"
```

---

### Task 7: Add NSDPData model to gdoc2netcfg

**Files:**
- Modify: `src/gdoc2netcfg/models/host.py:134-197` (add NSDPData, add field to Host)
- Create: `tests/test_models/test_nsdp_data.py`

**Step 1: Write failing test**

Create `tests/test_models/test_nsdp_data.py`:

```python
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
```

**Step 2: Run test to verify it fails**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/feature-nsdp && uv run pytest tests/test_models/test_nsdp_data.py -v`
Expected: FAIL with `ImportError: cannot import name 'NSDPData' from 'gdoc2netcfg.models.host'`

**Step 3: Add NSDPData to host.py**

In `src/gdoc2netcfg/models/host.py`, add a new frozen dataclass **before** the `Host` class (after `BridgeData`, around line 164):

```python
@dataclass(frozen=True)
class NSDPData:
    """NSDP discovery data for a Netgear switch.

    Populated by the nsdp supplement after broadcast discovery.
    Contains device identity, port status, and VLAN configuration
    as reported by the Netgear Switch Discovery Protocol.

    Attributes:
        model: Device model string (e.g. "GS110EMX").
        mac: Device MAC address as colon-separated hex string.
        hostname: Device name.
        ip: Management IPv4 address.
        netmask: IPv4 subnet mask.
        gateway: Default gateway IPv4.
        firmware_version: Firmware version string.
        dhcp_enabled: Whether DHCP is enabled.
        port_count: Number of ports.
        serial_number: Device serial number.
        port_status: Per-port link status as (port_id, speed_byte) tuples.
        port_pvids: Per-port native VLAN as (port_id, vlan_id) tuples.
    """

    model: str
    mac: str
    hostname: str | None = None
    ip: str | None = None
    netmask: str | None = None
    gateway: str | None = None
    firmware_version: str | None = None
    dhcp_enabled: bool | None = None
    port_count: int | None = None
    serial_number: str | None = None
    port_status: tuple[tuple[int, int], ...] = ()
    port_pvids: tuple[tuple[int, int], ...] = ()
```

Add `nsdp_data: NSDPData | None = None` to the `Host` dataclass (after `bridge_data`).

**Step 4: Run test to verify it passes**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/feature-nsdp && uv run pytest tests/test_models/test_nsdp_data.py -v`
Expected: PASS.

**Step 5: Run all tests to check for regressions**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/feature-nsdp && uv run pytest -q`
Expected: All tests PASS.

**Step 6: Commit**

```bash
git add src/gdoc2netcfg/models/host.py tests/test_models/test_nsdp_data.py
git commit -m "feat: add NSDPData model and nsdp_data field on Host"
```

---

### Task 8: Create gdoc2netcfg NSDP supplement

**Files:**
- Create: `src/gdoc2netcfg/supplements/nsdp.py`
- Create: `tests/test_supplements/test_nsdp.py`

**Step 1: Write failing tests**

Create `tests/test_supplements/test_nsdp.py`:

```python
"""Tests for the NSDP supplement."""

import json
from unittest.mock import patch, MagicMock

from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NSDPData, NetworkInterface
from gdoc2netcfg.supplements.nsdp import (
    enrich_hosts_with_nsdp,
    load_nsdp_cache,
    save_nsdp_cache,
)


def _make_host(hostname="gs110emx", ip="10.1.20.1", hardware_type="netgear-switch-plus"):
    return Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=[
            NetworkInterface(
                name=None,
                mac=MACAddress.parse("00:09:5b:aa:bb:cc"),
                ipv4=IPv4Address(ip),
                dhcp_name=hostname,
            ),
        ],
        default_ipv4=IPv4Address(ip),
        hardware_type=hardware_type,
    )


class TestNSDPCache:
    def test_load_missing_returns_empty(self, tmp_path):
        result = load_nsdp_cache(tmp_path / "nonexistent.json")
        assert result == {}

    def test_save_and_load_roundtrip(self, tmp_path):
        cache_path = tmp_path / "nsdp.json"
        data = {
            "gs110emx": {
                "model": "GS110EMX",
                "mac": "00:09:5b:aa:bb:cc",
                "firmware_version": "V2.06.24GR",
            }
        }
        save_nsdp_cache(cache_path, data)
        loaded = load_nsdp_cache(cache_path)
        assert loaded == data

    def test_save_creates_parent_directory(self, tmp_path):
        cache_path = tmp_path / "subdir" / "nsdp.json"
        save_nsdp_cache(cache_path, {"host": {"model": "GS110EMX", "mac": "aa:bb:cc:dd:ee:ff"}})
        assert cache_path.exists()


class TestEnrichHostsWithNSDP:
    def test_enrich_from_cache(self):
        host = _make_host()
        cache = {
            "gs110emx": {
                "model": "GS110EMX",
                "mac": "00:09:5b:aa:bb:cc",
                "firmware_version": "V2.06.24GR",
                "port_count": 10,
                "port_status": [(1, 5), (2, 0)],
            }
        }
        enrich_hosts_with_nsdp([host], cache)
        assert host.nsdp_data is not None
        assert host.nsdp_data.model == "GS110EMX"
        assert host.nsdp_data.firmware_version == "V2.06.24GR"
        assert host.nsdp_data.port_count == 10
        assert len(host.nsdp_data.port_status) == 2

    def test_no_cache_entry(self):
        host = _make_host()
        enrich_hosts_with_nsdp([host], {})
        assert host.nsdp_data is None

    def test_skip_non_netgear(self):
        host = _make_host(hardware_type=None)
        cache = {
            "gs110emx": {
                "model": "GS110EMX",
                "mac": "00:09:5b:aa:bb:cc",
            }
        }
        enrich_hosts_with_nsdp([host], cache)
        # Still enriches — cache is hostname-keyed, not hardware-type filtered
        assert host.nsdp_data is not None
```

**Step 2: Run tests to verify they fail**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/feature-nsdp && uv run pytest tests/test_supplements/test_nsdp.py -v`
Expected: FAIL with `ModuleNotFoundError`

**Step 3: Implement supplement**

Create `src/gdoc2netcfg/supplements/nsdp.py`:

```python
"""Supplement: NSDP discovery data collection.

Scans Netgear switches via the NSDP broadcast protocol to retrieve
device identity, firmware version, port status, and VLAN configuration.
Results are cached in nsdp.json.

This is primarily useful for unmanaged switches (hardware_type =
"netgear-switch-plus") that lack SNMP support. NSDP provides the only
programmatic way to query these devices.

The NSDP protocol client lives in the standalone `nsdp` package.
This module is the bridge between that package and gdoc2netcfg's
supplement pipeline.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

from gdoc2netcfg.derivations.hardware import (
    HARDWARE_NETGEAR_SWITCH,
    HARDWARE_NETGEAR_SWITCH_PLUS,
)
from gdoc2netcfg.models.host import NSDPData

if TYPE_CHECKING:
    from gdoc2netcfg.models.host import Host
    from gdoc2netcfg.supplements.reachability import HostReachability

NSDP_HARDWARE_TYPES = frozenset({HARDWARE_NETGEAR_SWITCH, HARDWARE_NETGEAR_SWITCH_PLUS})


def load_nsdp_cache(cache_path: Path) -> dict[str, dict]:
    """Load cached NSDP data from disk."""
    if not cache_path.exists():
        return {}
    with open(cache_path) as f:
        return json.load(f)


def save_nsdp_cache(cache_path: Path, data: dict[str, dict]) -> None:
    """Save NSDP data to disk cache."""
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    with open(cache_path, "w") as f:
        json.dump(data, f, indent="  ", sort_keys=True)


def scan_nsdp(
    hosts: list[Host],
    cache_path: Path,
    force: bool = False,
    max_age: float = 300,
    verbose: bool = False,
    reachability: dict[str, HostReachability] | None = None,
    interface: str | None = None,
) -> dict[str, dict]:
    """Scan Netgear switches via NSDP broadcast discovery.

    Sends a single NSDP broadcast and matches responses to known hosts
    by MAC address.

    Args:
        hosts: Host objects to match against NSDP responses.
        cache_path: Path to nsdp.json cache file.
        force: Force re-scan even if cache is fresh.
        max_age: Maximum cache age in seconds (default 5 minutes).
        verbose: Print progress to stderr.
        reachability: Pre-computed reachability data (not used for
            filtering — NSDP is broadcast-based, so all switches on
            the broadcast domain respond regardless).
        interface: Network interface for NSDP broadcast (e.g. "eth0").
            Required for actual scanning; if None, returns cached data
            only.

    Returns:
        Mapping of hostname to NSDP data dict.
    """
    nsdp_data = load_nsdp_cache(cache_path)

    # Check if cache is fresh enough
    if not force and cache_path.exists():
        age = time.time() - cache_path.stat().st_mtime
        if age < max_age:
            if verbose:
                print(f"nsdp.json last updated {age:.0f}s ago, using cache.", file=sys.stderr)
            return nsdp_data

    if interface is None:
        if verbose:
            print("No interface specified for NSDP scan, using cache only.", file=sys.stderr)
        return nsdp_data

    # Build MAC → hostname index for matching NSDP responses to hosts
    mac_to_hostname: dict[str, str] = {}
    for host in hosts:
        if host.hardware_type not in NSDP_HARDWARE_TYPES:
            continue
        for iface in host.interfaces:
            mac_to_hostname[str(iface.mac).lower()] = host.hostname

    if not mac_to_hostname:
        if verbose:
            print("No Netgear switches to scan.", file=sys.stderr)
        return nsdp_data

    if verbose:
        print(f"Scanning {len(mac_to_hostname)} Netgear switch(es) via NSDP...", file=sys.stderr)

    try:
        from nsdp import NSDPClient

        with NSDPClient(interface) as client:
            devices = client.discover(timeout=3.0)

        for device in devices:
            hostname = mac_to_hostname.get(device.mac.lower())
            if hostname is None:
                if verbose:
                    print(
                        f"  NSDP: unknown device {device.model} "
                        f"({device.mac}) at {device.ip}",
                        file=sys.stderr,
                    )
                continue

            entry: dict = {
                "model": device.model,
                "mac": device.mac,
            }
            if device.hostname is not None:
                entry["hostname"] = device.hostname
            if device.ip is not None:
                entry["ip"] = device.ip
            if device.netmask is not None:
                entry["netmask"] = device.netmask
            if device.gateway is not None:
                entry["gateway"] = device.gateway
            if device.firmware_version is not None:
                entry["firmware_version"] = device.firmware_version
            if device.dhcp_enabled is not None:
                entry["dhcp_enabled"] = device.dhcp_enabled
            if device.port_count is not None:
                entry["port_count"] = device.port_count
            if device.serial_number is not None:
                entry["serial_number"] = device.serial_number
            if device.port_status:
                entry["port_status"] = [
                    (ps.port_id, ps.speed.value) for ps in device.port_status
                ]
            if device.port_pvids:
                entry["port_pvids"] = [
                    (pp.port_id, pp.vlan_id) for pp in device.port_pvids
                ]

            nsdp_data[hostname] = entry
            if verbose:
                fw = device.firmware_version or "?"
                print(f"  {hostname}: {device.model} fw={fw}", file=sys.stderr)

    except PermissionError:
        print(
            "Error: NSDP scan requires elevated privileges.\n"
            "  Run with: sudo uv run gdoc2netcfg nsdp --interface <iface>\n"
            "  Or grant capability: sudo setcap cap_net_raw+ep $(which python3)",
            file=sys.stderr,
        )
    except Exception as e:
        print(f"Error during NSDP scan: {e}", file=sys.stderr)

    save_nsdp_cache(cache_path, nsdp_data)
    return nsdp_data


def enrich_hosts_with_nsdp(
    hosts: list[Host],
    nsdp_cache: dict[str, dict],
) -> None:
    """Attach cached NSDP data to Host objects.

    Modifies hosts in-place by setting host.nsdp_data.
    """
    for host in hosts:
        info = nsdp_cache.get(host.hostname)
        if info is not None:
            host.nsdp_data = NSDPData(
                model=info["model"],
                mac=info["mac"],
                hostname=info.get("hostname"),
                ip=info.get("ip"),
                netmask=info.get("netmask"),
                gateway=info.get("gateway"),
                firmware_version=info.get("firmware_version"),
                dhcp_enabled=info.get("dhcp_enabled"),
                port_count=info.get("port_count"),
                serial_number=info.get("serial_number"),
                port_status=tuple(
                    (ps[0], ps[1]) for ps in info.get("port_status", [])
                ),
                port_pvids=tuple(
                    (pp[0], pp[1]) for pp in info.get("port_pvids", [])
                ),
            )
```

**Step 4: Run tests to verify they pass**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/feature-nsdp && uv run pytest tests/test_supplements/test_nsdp.py -v`
Expected: All tests PASS.

**Step 5: Commit**

```bash
git add src/gdoc2netcfg/supplements/nsdp.py tests/test_supplements/test_nsdp.py
git commit -m "feat: add NSDP supplement (scan/cache/enrich)"
```

---

### Task 9: Wire NSDP into CLI and pipeline

**Files:**
- Modify: `src/gdoc2netcfg/cli/main.py` (add nsdp command, add to _build_pipeline)

**Step 1: Write failing test for CLI command**

Add to `tests/test_supplements/test_nsdp.py` (or create `tests/test_cli/test_nsdp_command.py` if preferred):

```python
"""Test that the 'nsdp' CLI subcommand is registered."""

from gdoc2netcfg.cli.main import main


class TestNSDPCLIRegistration:
    def test_nsdp_subcommand_in_help(self, capsys):
        """The nsdp subcommand should be registered in argparse."""
        try:
            main(["nsdp", "--help"])
        except SystemExit:
            pass
        captured = capsys.readouterr()
        assert "nsdp" in captured.out.lower() or "nsdp" in captured.err.lower()
```

**Step 2: Run test to verify it fails**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/feature-nsdp && uv run pytest tests/test_supplements/test_nsdp.py::TestNSDPCLIRegistration -v`
Expected: FAIL (no `nsdp` subcommand)

**Step 3: Add to CLI**

In `src/gdoc2netcfg/cli/main.py`:

1. Add `cmd_nsdp()` function (following the pattern of `cmd_snmp`).
2. Add the `nsdp` subparser to `main()`.
3. Add `"nsdp": cmd_nsdp` to the commands dict.
4. Add NSDP cache loading to `_build_pipeline()`.

**cmd_nsdp function** (add after `cmd_bridge`):

```python
def cmd_nsdp(args: argparse.Namespace) -> int:
    """Scan Netgear switches via NSDP broadcast discovery."""
    config = _load_config(args)

    from gdoc2netcfg.derivations.host_builder import build_hosts
    from gdoc2netcfg.sources.parser import parse_csv
    from gdoc2netcfg.supplements.nsdp import (
        enrich_hosts_with_nsdp,
        scan_nsdp,
    )

    # Minimal pipeline to get hosts with IPs
    csv_data = _fetch_or_load_csvs(config, use_cache=True)
    _enrich_site_from_vlan_sheet(config, csv_data)
    all_records = []
    for name, csv_text in csv_data:
        if name == "vlan_allocations":
            continue
        records = parse_csv(csv_text, name)
        all_records.extend(records)

    hosts = build_hosts(all_records, config.site)

    reachability = _load_or_run_reachability(config, hosts, force=args.force)
    _print_reachability_summary(reachability, hosts)

    cache_path = Path(config.cache.directory) / "nsdp.json"
    print("\nScanning via NSDP...", file=sys.stderr)
    nsdp_data = scan_nsdp(
        hosts,
        cache_path=cache_path,
        force=args.force,
        verbose=True,
        reachability=reachability,
        interface=args.interface,
    )

    enrich_hosts_with_nsdp(hosts, nsdp_data)

    # Report
    hosts_with_nsdp = sum(1 for h in hosts if h.nsdp_data is not None)
    print(f"\nNSDP data for {hosts_with_nsdp}/{len(hosts)} hosts.")

    return 0
```

**Subparser** (add in `main()` after the `bridge` parser):

```python
# nsdp
nsdp_parser = subparsers.add_parser("nsdp", help="Scan Netgear switches via NSDP discovery")
nsdp_parser.add_argument(
    "--force", action="store_true",
    help="Force re-scan even if cache is fresh",
)
nsdp_parser.add_argument(
    "--interface",
    help="Network interface for NSDP broadcast (e.g. eth0)",
)
```

**Commands dict** — add `"nsdp": cmd_nsdp`.

**_build_pipeline** — add NSDP cache loading (after bridge loading, around line 168):

```python
# Load NSDP cache and enrich (don't scan — that's a separate subcommand)
from gdoc2netcfg.supplements.nsdp import enrich_hosts_with_nsdp, load_nsdp_cache

nsdp_cache_path = Path(config.cache.directory) / "nsdp.json"
nsdp_cache = load_nsdp_cache(nsdp_cache_path)
enrich_hosts_with_nsdp(hosts, nsdp_cache)
```

**Step 4: Run test to verify it passes**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/feature-nsdp && uv run pytest tests/test_supplements/test_nsdp.py -v`
Expected: All tests PASS.

**Step 5: Run all tests to check for regressions**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/feature-nsdp && uv run pytest -q`
Expected: All tests PASS.

**Step 6: Lint**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/feature-nsdp && uv run ruff check src/ tests/`
Expected: No issues.

**Step 7: Commit**

```bash
git add src/gdoc2netcfg/cli/main.py
git commit -m "feat: wire NSDP supplement into CLI and pipeline"
```

---

### Task 10: Validate against real hardware

**Files:** None (exploratory testing)

**Step 1: Test on welland**

SSH to welland and run the NSDP scan against real GS110EMX hardware:

```bash
ssh -A ten64.welland.mithis.com
cd /opt/gdoc2netcfg
# Pull the feature branch
sudo -E git fetch origin feature/nsdp
sudo -E git checkout feature/nsdp

# Run NSDP discovery on the management VLAN interface
sudo uv run gdoc2netcfg nsdp --interface br0 --force
```

**Step 2: Verify output**

Check that:
- GS110EMX switches are discovered
- Model, MAC, IP, firmware version are populated
- Port status shows correct link speeds (especially for 10G ports — note the speed byte values)
- Compare NSDP-reported IP/MAC against the spreadsheet

**Step 3: If 10G speed values discovered**

Update `src/nsdp/types.py` LinkSpeed enum with newly discovered speed byte values for 2.5G/5G/10G. Add corresponding tests.

**Step 4: Document findings**

Update `docs/nsdp-protocol.md` with any newly discovered TLV values or speed bytes.

**Step 5: Commit any fixes**

```bash
git add -A
git commit -m "fix(nsdp): update protocol data from real hardware testing"
```

---

### Task 11: Final cleanup and PR preparation

**Files:**
- Modify: `CLAUDE.md` (add NSDP scan command to Build and Test Commands section)

**Step 1: Update CLAUDE.md**

Add to the Build and Test Commands section:

```bash
uv run gdoc2netcfg nsdp --interface eth0    # Scan Netgear switches via NSDP
```

**Step 2: Run full test suite and lint**

```bash
cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/feature-nsdp
uv run pytest -q
uv run ruff check src/ tests/
```

Expected: All tests PASS, no lint issues.

**Step 3: Commit and prepare for merge**

```bash
git add CLAUDE.md
git commit -m "docs: add NSDP scan command to CLAUDE.md"
```
