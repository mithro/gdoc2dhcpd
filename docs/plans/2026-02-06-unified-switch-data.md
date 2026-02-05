# Unified Switch Data Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Create a unified `SwitchData` structure that both SNMP and NSDP supplements populate, so consumers don't need to care about the data source.

**Architecture:** Define a `SwitchData` dataclass with common fields (port status, port PVIDs, VLAN membership, port statistics) plus optional source-specific fields. Both the NSDP and bridge supplements will populate this unified structure on `Host.switch_data`. First fix NSDP to cache all collected data, then add new NSDP tags, then create the unified structure, then wire both supplements to populate it.

**Tech Stack:** Python 3.11+, frozen dataclasses, pytest

---

## Task 1: Cache VLAN and Statistics Data in NSDP Supplement

The NSDP client already collects `vlan_engine`, `vlan_members`, and `port_statistics` but the supplement doesn't cache them to `nsdp.json`.

**Files:**
- Modify: `src/gdoc2netcfg/supplements/nsdp.py:116-148`
- Modify: `src/gdoc2netcfg/models/host.py:166-200` (NSDPData class)
- Test: `tests/test_supplements/test_nsdp.py`
- Test: `tests/test_models/test_nsdp_data.py`

**Step 1: Add fields to NSDPData model**

In `src/gdoc2netcfg/models/host.py`, add after line 200:

```python
    vlan_engine: int | None = None  # 0=disabled, 4=advanced 802.1Q
    vlan_members: tuple[tuple[int, frozenset[int], frozenset[int]], ...] = ()
    # Each tuple: (vlan_id, member_ports, tagged_ports)
    port_statistics: tuple[tuple[int, int, int, int], ...] = ()
    # Each tuple: (port_id, bytes_rx, bytes_tx, crc_errors)
```

**Step 2: Update supplement to cache new fields**

In `src/gdoc2netcfg/supplements/nsdp.py`, after line 143 (after port_pvids), add:

```python
                if device.vlan_engine is not None:
                    entry["vlan_engine"] = device.vlan_engine.value
                if device.vlan_members:
                    entry["vlan_members"] = [
                        (vm.vlan_id, sorted(vm.member_ports), sorted(vm.tagged_ports))
                        for vm in device.vlan_members
                    ]
                if device.port_statistics:
                    entry["port_statistics"] = [
                        (ps.port_id, ps.bytes_received, ps.bytes_sent, ps.crc_errors)
                        for ps in device.port_statistics
                    ]
```

**Step 3: Update enrich_hosts_with_nsdp to load new fields**

In `src/gdoc2netcfg/supplements/nsdp.py`, update the NSDPData construction (around line 175-192) to include:

```python
                vlan_engine=info.get("vlan_engine"),
                vlan_members=tuple(
                    (vm[0], frozenset(vm[1]), frozenset(vm[2]))
                    for vm in info.get("vlan_members", [])
                ),
                port_statistics=tuple(
                    (ps[0], ps[1], ps[2], ps[3])
                    for ps in info.get("port_statistics", [])
                ),
```

**Step 4: Add tests for new fields**

In `tests/test_models/test_nsdp_data.py`, add:

```python
def test_nsdp_data_vlan_engine():
    data = NSDPData(model="GS110EMX", mac="aa:bb:cc:dd:ee:ff", vlan_engine=4)
    assert data.vlan_engine == 4


def test_nsdp_data_vlan_members():
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


def test_nsdp_data_port_statistics():
    data = NSDPData(
        model="GS110EMX",
        mac="aa:bb:cc:dd:ee:ff",
        port_statistics=((1, 1000, 500, 0), (2, 2000, 1000, 5)),
    )
    assert data.port_statistics[0] == (1, 1000, 500, 0)
```

**Step 5: Run tests**

```bash
uv run pytest tests/test_models/test_nsdp_data.py tests/test_supplements/test_nsdp.py -v
```

**Step 6: Commit**

```bash
git add src/gdoc2netcfg/models/host.py src/gdoc2netcfg/supplements/nsdp.py tests/
git commit -m "Cache VLAN engine, members, and port statistics in NSDP supplement"
```

---

## Task 2: Add New NSDP Tags to Protocol

Add the additional TLV tags discovered during hardware probing.

**Files:**
- Modify: `src/nsdp/protocol.py:40-84` (Tag enum)
- Test: `tests/test_nsdp/test_protocol.py`

**Step 1: Add new tags to Tag enum**

In `src/nsdp/protocol.py`, add after line 80 (after PORT_PVID):

```python
    # QoS
    QOS_ENGINE = 0x3400
    PORT_QOS_PRIORITY = 0x3800

    # Traffic control
    INGRESS_RATE_LIMIT = 0x4C00
    EGRESS_RATE_LIMIT = 0x5000
    BROADCAST_FILTERING = 0x5400
    BROADCAST_BANDWIDTH = 0x5800
    PORT_MIRRORING = 0x5C00

    # IGMP
    IGMP_SNOOPING = 0x6800
    BLOCK_UNKNOWN_MULTICAST = 0x6C00
    IGMPV3_HEADER_VALIDATION = 0x7000
    IGMP_STATIC_ROUTER_PORTS = 0x8000

    # Other
    LOOP_DETECTION = 0x9000
    ACTIVE_FIRMWARE = 0x000C
```

**Step 2: Add test for new tags**

In `tests/test_nsdp/test_protocol.py`, add:

```python
def test_new_tags_exist():
    from nsdp.protocol import Tag
    assert Tag.QOS_ENGINE == 0x3400
    assert Tag.PORT_MIRRORING == 0x5C00
    assert Tag.IGMP_SNOOPING == 0x6800
    assert Tag.ACTIVE_FIRMWARE == 0x000C
```

**Step 3: Run tests**

```bash
uv run pytest tests/test_nsdp/test_protocol.py -v
```

**Step 4: Commit**

```bash
git add src/nsdp/protocol.py tests/test_nsdp/test_protocol.py
git commit -m "Add QoS, IGMP, mirroring, and other NSDP tags"
```

---

## Task 3: Add NSDP Types for New Data

Create data types for the new NSDP fields.

**Files:**
- Modify: `src/nsdp/types.py`
- Test: `tests/test_nsdp/test_types.py`

**Step 1: Add PortQoS dataclass**

In `src/nsdp/types.py`, add after PortPVID class (around line 130):

```python
@dataclass(frozen=True)
class PortQoS:
    """Port QoS priority setting (NSDP tag 0x3800).

    Attributes:
        port_id: 1-based port number.
        priority: QoS priority (typically 1-8, higher = more priority).
    """

    port_id: int
    priority: int
```

**Step 2: Add PortMirroring dataclass**

```python
@dataclass(frozen=True)
class PortMirroring:
    """Port mirroring configuration (NSDP tag 0x5C00).

    Attributes:
        destination_port: Port receiving mirrored traffic (0 = disabled).
        source_ports: Ports being mirrored.
    """

    destination_port: int
    source_ports: frozenset[int] = field(default_factory=frozenset)
```

**Step 3: Add IGMPSnooping dataclass**

```python
@dataclass(frozen=True)
class IGMPSnooping:
    """IGMP snooping configuration (NSDP tag 0x6800).

    Attributes:
        enabled: Whether IGMP snooping is enabled.
        vlan_id: VLAN for IGMP snooping (if applicable).
    """

    enabled: bool
    vlan_id: int | None = None
```

**Step 4: Update NSDPDevice to include new fields**

Add to NSDPDevice class attributes (after port_pvids):

```python
    port_qos: tuple[PortQoS, ...] = ()
    qos_engine: int | None = None  # 0=disabled, 1=port-based, 2=802.1p
    port_mirroring: PortMirroring | None = None
    igmp_snooping: IGMPSnooping | None = None
    broadcast_filtering: bool | None = None
    loop_detection: bool | None = None
```

**Step 5: Add tests**

In `tests/test_nsdp/test_types.py`:

```python
from nsdp.types import PortQoS, PortMirroring, IGMPSnooping


class TestPortQoS:
    def test_creation(self):
        qos = PortQoS(port_id=1, priority=8)
        assert qos.port_id == 1
        assert qos.priority == 8


class TestPortMirroring:
    def test_disabled(self):
        pm = PortMirroring(destination_port=0)
        assert pm.destination_port == 0
        assert pm.source_ports == frozenset()

    def test_enabled(self):
        pm = PortMirroring(destination_port=10, source_ports=frozenset({1, 2}))
        assert pm.destination_port == 10
        assert 1 in pm.source_ports


class TestIGMPSnooping:
    def test_disabled(self):
        igmp = IGMPSnooping(enabled=False)
        assert igmp.enabled is False

    def test_enabled_with_vlan(self):
        igmp = IGMPSnooping(enabled=True, vlan_id=10)
        assert igmp.enabled is True
        assert igmp.vlan_id == 10
```

**Step 6: Run tests**

```bash
uv run pytest tests/test_nsdp/test_types.py -v
```

**Step 7: Commit**

```bash
git add src/nsdp/types.py tests/test_nsdp/test_types.py
git commit -m "Add PortQoS, PortMirroring, IGMPSnooping types"
```

---

## Task 4: Add Parsers for New NSDP Tags

Parse the new TLV tags in the NSDP response.

**Files:**
- Modify: `src/nsdp/parsers.py`
- Test: `tests/test_nsdp/test_parsers.py`

**Step 1: Add parse_port_qos function**

In `src/nsdp/parsers.py`, add after parse_port_pvid:

```python
def parse_port_qos(data: bytes) -> PortQoS | None:
    """Parse NSDP tag 0x3800 (2 bytes: port_id, priority).

    Returns None if data is not exactly 2 bytes.
    """
    if len(data) != 2:
        return None
    return PortQoS(port_id=data[0], priority=data[1])
```

**Step 2: Add parse_port_mirroring function**

```python
def parse_port_mirroring(data: bytes) -> PortMirroring | None:
    """Parse NSDP tag 0x5C00 (4 bytes: dest_port, source_bitmap).

    Returns None if data is not exactly 4 bytes.
    """
    if len(data) != 4:
        return None
    dest_port = data[0]
    # Bytes 1-3 are source port bitmap (MSB first)
    source_ports = _bitmap_to_ports(data[1:4])
    return PortMirroring(destination_port=dest_port, source_ports=source_ports)
```

**Step 3: Add parse_igmp_snooping function**

```python
def parse_igmp_snooping(data: bytes) -> IGMPSnooping | None:
    """Parse NSDP tag 0x6800 (4 bytes: unknown, enabled, unknown, vlan?).

    Returns None if data is too short.
    """
    if len(data) < 2:
        return None
    enabled = bool(data[1])
    vlan_id = None
    if len(data) >= 4:
        vlan_id = data[3] if data[3] != 0 else None
    return IGMPSnooping(enabled=enabled, vlan_id=vlan_id)
```

**Step 4: Update imports in parsers.py**

Add to the imports from nsdp.types:

```python
from nsdp.types import (
    IGMPSnooping,
    LinkSpeed,
    NSDPDevice,
    PortMirroring,
    PortPVID,
    PortQoS,
    PortStatistics,
    PortStatus,
    VLANEngine,
    VLANMembership,
)
```

**Step 5: Update parse_discovery_response to handle new tags**

In parse_discovery_response, add variables after vlan_engine declaration:

```python
    port_qos_list: list[PortQoS] = []
    qos_engine: int | None = None
    port_mirroring_obj: PortMirroring | None = None
    igmp_snooping_obj: IGMPSnooping | None = None
    broadcast_filtering: bool | None = None
    loop_detection: bool | None = None
```

Add handling in the for loop after PORT_PVID:

```python
        elif tag == Tag.PORT_QOS_PRIORITY:
            pq = parse_port_qos(val)
            if pq is not None:
                port_qos_list.append(pq)
        elif tag == Tag.QOS_ENGINE:
            qos_engine = val[0] if val else None
        elif tag == Tag.PORT_MIRRORING:
            port_mirroring_obj = parse_port_mirroring(val)
        elif tag == Tag.IGMP_SNOOPING:
            igmp_snooping_obj = parse_igmp_snooping(val)
        elif tag == Tag.BROADCAST_FILTERING:
            broadcast_filtering = bool(val[0]) if val else None
        elif tag == Tag.LOOP_DETECTION:
            loop_detection = bool(val[0]) if val else None
```

Update the NSDPDevice return to include new fields:

```python
        port_qos=tuple(port_qos_list),
        qos_engine=qos_engine,
        port_mirroring=port_mirroring_obj,
        igmp_snooping=igmp_snooping_obj,
        broadcast_filtering=broadcast_filtering,
        loop_detection=loop_detection,
```

**Step 6: Add tests for new parsers**

In `tests/test_nsdp/test_parsers.py`:

```python
from nsdp.parsers import parse_port_qos, parse_port_mirroring, parse_igmp_snooping


class TestParsePortQoS:
    def test_valid(self):
        result = parse_port_qos(b"\x01\x08")
        assert result is not None
        assert result.port_id == 1
        assert result.priority == 8

    def test_invalid_length(self):
        assert parse_port_qos(b"\x01") is None
        assert parse_port_qos(b"\x01\x02\x03") is None


class TestParsePortMirroring:
    def test_disabled(self):
        result = parse_port_mirroring(b"\x00\x00\x00\x00")
        assert result is not None
        assert result.destination_port == 0
        assert result.source_ports == frozenset()

    def test_enabled(self):
        # Dest port 10, source ports 1,2 (bitmap 0xC0 = 11000000)
        result = parse_port_mirroring(b"\x0a\xc0\x00\x00")
        assert result is not None
        assert result.destination_port == 10
        assert result.source_ports == frozenset({1, 2})


class TestParseIGMPSnooping:
    def test_enabled(self):
        result = parse_igmp_snooping(b"\x00\x01\x00\x01")
        assert result is not None
        assert result.enabled is True

    def test_disabled(self):
        result = parse_igmp_snooping(b"\x00\x00\x00\x00")
        assert result is not None
        assert result.enabled is False
```

**Step 7: Run tests**

```bash
uv run pytest tests/test_nsdp/test_parsers.py -v
```

**Step 8: Commit**

```bash
git add src/nsdp/parsers.py tests/test_nsdp/test_parsers.py
git commit -m "Add parsers for QoS, mirroring, and IGMP NSDP tags"
```

---

## Task 5: Request New Tags in NSDP Client

Update the discovery tag list to request the new tags.

**Files:**
- Modify: `src/nsdp/client.py:34-50`

**Step 1: Add new tags to DISCOVERY_TAGS**

In `src/nsdp/client.py`, update DISCOVERY_TAGS to include:

```python
DISCOVERY_TAGS: list[Tag] = [
    # Device identity
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
    Tag.ACTIVE_FIRMWARE,
    # Port information
    Tag.PORT_STATUS,
    Tag.PORT_STATISTICS,
    # VLAN
    Tag.VLAN_ENGINE,
    Tag.VLAN_MEMBERS,
    Tag.PORT_PVID,
    # QoS
    Tag.QOS_ENGINE,
    Tag.PORT_QOS_PRIORITY,
    # Traffic control
    Tag.BROADCAST_FILTERING,
    Tag.PORT_MIRRORING,
    # IGMP
    Tag.IGMP_SNOOPING,
    Tag.BLOCK_UNKNOWN_MULTICAST,
    # Loop detection
    Tag.LOOP_DETECTION,
]
```

**Step 2: Run existing tests**

```bash
uv run pytest tests/test_nsdp/ -v
```

**Step 3: Commit**

```bash
git add src/nsdp/client.py
git commit -m "Request QoS, mirroring, IGMP, and loop detection tags"
```

---

## Task 6: Create Unified SwitchData Structure

Create the unified dataclass that normalizes data from both SNMP and NSDP.

**Files:**
- Create: `src/gdoc2netcfg/models/switch_data.py`
- Test: `tests/test_models/test_switch_data.py`

**Step 1: Create switch_data.py**

```python
"""Unified switch data model for SNMP and NSDP sources.

This module provides a common representation of switch data that can be
populated from either SNMP (managed switches) or NSDP (Netgear Plus switches).
Consumers should use these types rather than the source-specific BridgeData
or NSDPData classes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class SwitchDataSource(Enum):
    """Source of switch data."""

    SNMP = "snmp"
    NSDP = "nsdp"


@dataclass(frozen=True)
class PortLinkStatus:
    """Link status for a single switch port.

    Attributes:
        port_id: 1-based port number.
        is_up: Whether the port has link.
        speed_mbps: Link speed in Mbps (0 if down).
        port_name: Human-readable port name (SNMP only, None for NSDP).
    """

    port_id: int
    is_up: bool
    speed_mbps: int
    port_name: str | None = None


@dataclass(frozen=True)
class PortTrafficStats:
    """Traffic statistics for a single port.

    Attributes:
        port_id: 1-based port number.
        bytes_rx: Total bytes received.
        bytes_tx: Total bytes transmitted.
        errors: Error count (CRC errors for NSDP, ifInErrors for SNMP).
    """

    port_id: int
    bytes_rx: int
    bytes_tx: int
    errors: int


@dataclass(frozen=True)
class VLANInfo:
    """VLAN configuration.

    Attributes:
        vlan_id: 802.1Q VLAN ID.
        name: VLAN name (SNMP only, None for NSDP).
        member_ports: Set of port IDs that are members.
        tagged_ports: Subset of member_ports that are tagged (trunk).
    """

    vlan_id: int
    name: str | None
    member_ports: frozenset[int]
    tagged_ports: frozenset[int] = field(default_factory=frozenset)

    @property
    def untagged_ports(self) -> frozenset[int]:
        """Ports that are untagged members (access ports)."""
        return self.member_ports - self.tagged_ports


@dataclass(frozen=True)
class SwitchData:
    """Unified switch data from SNMP or NSDP.

    This is the primary interface for consuming switch data. It provides
    a consistent view regardless of whether data came from SNMP or NSDP.

    Attributes:
        source: Where this data came from (SNMP or NSDP).
        model: Switch model string.
        firmware_version: Firmware version string.
        port_count: Total number of ports.
        port_status: Per-port link status.
        port_pvids: Per-port native VLAN as (port_id, vlan_id) tuples.
        port_stats: Per-port traffic statistics (if available).
        vlans: VLAN configuration (if available).

        # SNMP-only fields (None for NSDP)
        mac_table: MAC forwarding table entries.
        lldp_neighbors: LLDP neighbor information.
        poe_status: PoE port status.

        # NSDP-only fields (None for SNMP)
        serial_number: Device serial number.
        qos_engine: QoS mode (0=off, 1=port-based, 2=802.1p).
        port_mirroring_dest: Destination port for mirroring (0=disabled).
        igmp_snooping_enabled: Whether IGMP snooping is on.
    """

    source: SwitchDataSource
    model: str | None = None
    firmware_version: str | None = None
    port_count: int | None = None

    # Common fields
    port_status: tuple[PortLinkStatus, ...] = ()
    port_pvids: tuple[tuple[int, int], ...] = ()  # (port_id, vlan_id)
    port_stats: tuple[PortTrafficStats, ...] = ()
    vlans: tuple[VLANInfo, ...] = ()

    # SNMP-only (None for NSDP)
    mac_table: tuple[tuple[str, int, int, str], ...] | None = None
    # (mac, vlan_id, port_id, port_name)
    lldp_neighbors: tuple[tuple[int, str, str, str], ...] | None = None
    # (port_id, remote_name, remote_port, remote_mac)
    poe_status: tuple[tuple[int, int, int], ...] | None = None
    # (port_id, admin_status, detection_status)

    # NSDP-only (None for SNMP)
    serial_number: str | None = None
    qos_engine: int | None = None
    port_mirroring_dest: int | None = None
    igmp_snooping_enabled: bool | None = None
```

**Step 2: Create tests**

In `tests/test_models/test_switch_data.py`:

```python
"""Tests for unified SwitchData model."""

from gdoc2netcfg.models.switch_data import (
    PortLinkStatus,
    PortTrafficStats,
    SwitchData,
    SwitchDataSource,
    VLANInfo,
)


class TestPortLinkStatus:
    def test_up(self):
        status = PortLinkStatus(port_id=1, is_up=True, speed_mbps=1000)
        assert status.port_id == 1
        assert status.is_up is True
        assert status.speed_mbps == 1000

    def test_down(self):
        status = PortLinkStatus(port_id=2, is_up=False, speed_mbps=0)
        assert status.is_up is False

    def test_with_name(self):
        status = PortLinkStatus(
            port_id=1, is_up=True, speed_mbps=1000, port_name="ge-0/0/1"
        )
        assert status.port_name == "ge-0/0/1"


class TestPortTrafficStats:
    def test_creation(self):
        stats = PortTrafficStats(port_id=1, bytes_rx=1000, bytes_tx=500, errors=0)
        assert stats.bytes_rx == 1000
        assert stats.errors == 0


class TestVLANInfo:
    def test_untagged_ports(self):
        vlan = VLANInfo(
            vlan_id=10,
            name="mgmt",
            member_ports=frozenset({1, 2, 3}),
            tagged_ports=frozenset({3}),
        )
        assert vlan.untagged_ports == frozenset({1, 2})

    def test_no_name(self):
        vlan = VLANInfo(
            vlan_id=20,
            name=None,
            member_ports=frozenset({1}),
        )
        assert vlan.name is None


class TestSwitchData:
    def test_nsdp_source(self):
        data = SwitchData(
            source=SwitchDataSource.NSDP,
            model="GS110EMX",
            port_count=10,
            serial_number="ABC123",
        )
        assert data.source == SwitchDataSource.NSDP
        assert data.serial_number == "ABC123"
        assert data.mac_table is None  # SNMP-only

    def test_snmp_source(self):
        data = SwitchData(
            source=SwitchDataSource.SNMP,
            model="GS724T",
            mac_table=(("aa:bb:cc:dd:ee:ff", 1, 5, "port5"),),
        )
        assert data.source == SwitchDataSource.SNMP
        assert data.mac_table is not None
        assert data.serial_number is None  # NSDP-only

    def test_common_fields(self):
        data = SwitchData(
            source=SwitchDataSource.NSDP,
            port_status=(
                PortLinkStatus(port_id=1, is_up=True, speed_mbps=1000),
                PortLinkStatus(port_id=2, is_up=False, speed_mbps=0),
            ),
            port_pvids=((1, 10), (2, 20)),
        )
        assert len(data.port_status) == 2
        assert data.port_pvids[0] == (1, 10)
```

**Step 3: Run tests**

```bash
uv run pytest tests/test_models/test_switch_data.py -v
```

**Step 4: Commit**

```bash
git add src/gdoc2netcfg/models/switch_data.py tests/test_models/test_switch_data.py
git commit -m "Add unified SwitchData model"
```

---

## Task 7: Add SwitchData to Host Model

Wire the unified SwitchData into the Host class.

**Files:**
- Modify: `src/gdoc2netcfg/models/host.py`
- Modify: `src/gdoc2netcfg/models/__init__.py`

**Step 1: Import SwitchData in host.py**

Add import at top of `src/gdoc2netcfg/models/host.py`:

```python
from gdoc2netcfg.models.switch_data import SwitchData
```

**Step 2: Add switch_data field to Host**

In the Host class (around line 235), add after `nsdp_data`:

```python
    switch_data: SwitchData | None = None
```

**Step 3: Export from models/__init__.py**

In `src/gdoc2netcfg/models/__init__.py`, add:

```python
from gdoc2netcfg.models.switch_data import (
    PortLinkStatus,
    PortTrafficStats,
    SwitchData,
    SwitchDataSource,
    VLANInfo,
)
```

**Step 4: Run all model tests**

```bash
uv run pytest tests/test_models/ -v
```

**Step 5: Commit**

```bash
git add src/gdoc2netcfg/models/
git commit -m "Add switch_data field to Host model"
```

---

## Task 8: Create NSDP to SwitchData Converter

Convert NSDPData to the unified SwitchData format.

**Files:**
- Modify: `src/gdoc2netcfg/supplements/nsdp.py`
- Test: `tests/test_supplements/test_nsdp.py`

**Step 1: Add conversion function**

In `src/gdoc2netcfg/supplements/nsdp.py`, add after imports:

```python
from gdoc2netcfg.models.switch_data import (
    PortLinkStatus,
    PortTrafficStats,
    SwitchData,
    SwitchDataSource,
    VLANInfo,
)
from nsdp.types import LinkSpeed
```

Add the converter function:

```python
def nsdp_to_switch_data(nsdp: NSDPData) -> SwitchData:
    """Convert NSDPData to unified SwitchData format."""
    # Convert port status
    port_status = tuple(
        PortLinkStatus(
            port_id=ps[0],
            is_up=ps[1] != LinkSpeed.DOWN.value,
            speed_mbps=LinkSpeed.from_byte(ps[1]).speed_mbps,
        )
        for ps in nsdp.port_status
    )

    # Convert port statistics
    port_stats = tuple(
        PortTrafficStats(
            port_id=ps[0],
            bytes_rx=ps[1],
            bytes_tx=ps[2],
            errors=ps[3],
        )
        for ps in nsdp.port_statistics
    )

    # Convert VLAN membership
    vlans = tuple(
        VLANInfo(
            vlan_id=vm[0],
            name=None,  # NSDP doesn't have VLAN names
            member_ports=vm[1],
            tagged_ports=vm[2],
        )
        for vm in nsdp.vlan_members
    )

    return SwitchData(
        source=SwitchDataSource.NSDP,
        model=nsdp.model,
        firmware_version=nsdp.firmware_version,
        port_count=nsdp.port_count,
        port_status=port_status,
        port_pvids=nsdp.port_pvids,
        port_stats=port_stats,
        vlans=vlans,
        serial_number=nsdp.serial_number,
        qos_engine=nsdp.vlan_engine,  # Note: vlan_engine stored here for now
    )
```

**Step 2: Update enrich_hosts_with_nsdp to also set switch_data**

In the enrich function, after setting `host.nsdp_data`, add:

```python
            host.switch_data = nsdp_to_switch_data(host.nsdp_data)
```

**Step 3: Add tests**

In `tests/test_supplements/test_nsdp.py`:

```python
from gdoc2netcfg.supplements.nsdp import nsdp_to_switch_data
from gdoc2netcfg.models.host import NSDPData
from gdoc2netcfg.models.switch_data import SwitchDataSource


def test_nsdp_to_switch_data_basic():
    nsdp = NSDPData(
        model="GS110EMX",
        mac="aa:bb:cc:dd:ee:ff",
        firmware_version="1.0.1.4",
        port_count=10,
        serial_number="ABC123",
        port_status=((1, 5), (2, 0)),  # port 1 = gigabit, port 2 = down
        port_pvids=((1, 10), (2, 20)),
    )
    result = nsdp_to_switch_data(nsdp)

    assert result.source == SwitchDataSource.NSDP
    assert result.model == "GS110EMX"
    assert result.serial_number == "ABC123"
    assert len(result.port_status) == 2
    assert result.port_status[0].is_up is True
    assert result.port_status[0].speed_mbps == 1000
    assert result.port_status[1].is_up is False


def test_nsdp_to_switch_data_vlans():
    nsdp = NSDPData(
        model="GS110EMX",
        mac="aa:bb:cc:dd:ee:ff",
        vlan_members=(
            (1, frozenset({1, 2, 3}), frozenset({3})),
            (10, frozenset({1, 2}), frozenset({1, 2})),
        ),
    )
    result = nsdp_to_switch_data(nsdp)

    assert len(result.vlans) == 2
    assert result.vlans[0].vlan_id == 1
    assert result.vlans[0].name is None  # NSDP has no names
    assert result.vlans[0].untagged_ports == frozenset({1, 2})
```

**Step 4: Run tests**

```bash
uv run pytest tests/test_supplements/test_nsdp.py -v
```

**Step 5: Commit**

```bash
git add src/gdoc2netcfg/supplements/nsdp.py tests/test_supplements/test_nsdp.py
git commit -m "Convert NSDP data to unified SwitchData format"
```

---

## Task 9: Create SNMP Bridge to SwitchData Converter

Convert BridgeData to the unified SwitchData format.

**Files:**
- Modify: `src/gdoc2netcfg/supplements/bridge.py`
- Test: `tests/test_supplements/test_bridge.py`

**Step 1: Add imports to bridge.py**

```python
from gdoc2netcfg.models.switch_data import (
    PortLinkStatus,
    PortTrafficStats,
    SwitchData,
    SwitchDataSource,
    VLANInfo,
)
```

**Step 2: Add conversion function**

```python
def bridge_to_switch_data(bridge: BridgeData, model: str | None = None) -> SwitchData:
    """Convert BridgeData to unified SwitchData format."""
    # Build port_id to port_name mapping
    port_names = {ifidx: name for ifidx, name in bridge.port_names}

    # Convert port status (ifIndex, oper_status, speed_mbps) -> PortLinkStatus
    # Need to map ifIndex to port_id (1-based port number)
    # For now, use ifIndex as port_id (may need refinement)
    port_status = tuple(
        PortLinkStatus(
            port_id=ifidx,
            is_up=oper == 1,  # 1 = up, 2 = down
            speed_mbps=speed,
            port_name=port_names.get(ifidx),
        )
        for ifidx, oper, speed in bridge.port_status
    )

    # Convert VLANs from bitmap format
    # Need vlan_names + vlan_egress_ports + vlan_untagged_ports
    vlan_name_map = {vid: name for vid, name in bridge.vlan_names}

    def bitmap_to_ports(hex_bitmap: str) -> frozenset[int]:
        """Convert hex bitmap string to port set."""
        if not hex_bitmap:
            return frozenset()
        try:
            bitmap_bytes = bytes.fromhex(hex_bitmap)
        except ValueError:
            return frozenset()
        ports = set()
        for byte_idx, byte_val in enumerate(bitmap_bytes):
            for bit in range(8):
                if byte_val & (0x80 >> bit):
                    ports.add(byte_idx * 8 + bit + 1)
        return frozenset(ports)

    vlans = []
    egress_map = {vid: bitmap for vid, bitmap in bridge.vlan_egress_ports}
    untagged_map = {vid: bitmap for vid, bitmap in bridge.vlan_untagged_ports}

    for vid, name in bridge.vlan_names:
        member_ports = bitmap_to_ports(egress_map.get(vid, ""))
        untagged = bitmap_to_ports(untagged_map.get(vid, ""))
        tagged = member_ports - untagged
        vlans.append(VLANInfo(
            vlan_id=vid,
            name=name,
            member_ports=member_ports,
            tagged_ports=tagged,
        ))

    return SwitchData(
        source=SwitchDataSource.SNMP,
        model=model,
        port_status=port_status,
        port_pvids=bridge.port_pvids,
        vlans=tuple(vlans),
        mac_table=bridge.mac_table,
        lldp_neighbors=bridge.lldp_neighbors,
        poe_status=bridge.poe_status if bridge.poe_status else None,
    )
```

**Step 3: Update enrich_hosts_with_bridge to also set switch_data**

Find where `host.bridge_data` is set and add:

```python
            host.switch_data = bridge_to_switch_data(host.bridge_data, model=host.hostname)
```

**Step 4: Add tests**

In `tests/test_supplements/test_bridge.py`:

```python
from gdoc2netcfg.supplements.bridge import bridge_to_switch_data
from gdoc2netcfg.models.host import BridgeData
from gdoc2netcfg.models.switch_data import SwitchDataSource


def test_bridge_to_switch_data_basic():
    bridge = BridgeData(
        port_status=((1, 1, 1000), (2, 2, 0)),  # port 1 up, port 2 down
        port_names=((1, "ge-0/0/1"), (2, "ge-0/0/2")),
        port_pvids=((1, 10), (2, 20)),
    )
    result = bridge_to_switch_data(bridge, model="GS724T")

    assert result.source == SwitchDataSource.SNMP
    assert result.model == "GS724T"
    assert len(result.port_status) == 2
    assert result.port_status[0].is_up is True
    assert result.port_status[0].port_name == "ge-0/0/1"
    assert result.port_status[1].is_up is False


def test_bridge_to_switch_data_vlans():
    bridge = BridgeData(
        vlan_names=((1, "default"), (10, "mgmt")),
        vlan_egress_ports=((1, "ff"), (10, "c0")),  # VLAN 1: all 8 ports, VLAN 10: ports 1,2
        vlan_untagged_ports=((1, "3f"), (10, "c0")),  # VLAN 1: ports 3-8 untagged
    )
    result = bridge_to_switch_data(bridge)

    assert len(result.vlans) == 2
    vlan1 = next(v for v in result.vlans if v.vlan_id == 1)
    assert vlan1.name == "default"
    assert vlan1.member_ports == frozenset({1, 2, 3, 4, 5, 6, 7, 8})


def test_bridge_to_switch_data_mac_table():
    bridge = BridgeData(
        mac_table=(("aa:bb:cc:dd:ee:ff", 1, 5, "port5"),),
    )
    result = bridge_to_switch_data(bridge)

    assert result.mac_table is not None
    assert result.mac_table[0][0] == "aa:bb:cc:dd:ee:ff"
```

**Step 5: Run tests**

```bash
uv run pytest tests/test_supplements/test_bridge.py -v
```

**Step 6: Commit**

```bash
git add src/gdoc2netcfg/supplements/bridge.py tests/test_supplements/test_bridge.py
git commit -m "Convert SNMP bridge data to unified SwitchData format"
```

---

## Task 10: Add Port Statistics to SNMP Bridge Supplement

The SNMP bridge supplement doesn't currently collect port traffic statistics. Add this capability.

**Files:**
- Modify: `src/gdoc2netcfg/supplements/bridge.py`
- Test: `tests/test_supplements/test_bridge.py`

**Step 1: Add OID constants**

In `src/gdoc2netcfg/supplements/bridge.py`, add to the OID constants section:

```python
# Interface statistics (IF-MIB)
_IF_HC_IN_OCTETS = "1.3.6.1.2.1.31.1.1.1.6"
_IF_HC_OUT_OCTETS = "1.3.6.1.2.1.31.1.1.1.10"
_IF_IN_ERRORS = "1.3.6.1.2.1.2.2.1.14"
```

**Step 2: Add to _BRIDGE_TABLE_OIDS**

```python
_BRIDGE_TABLE_OIDS: dict[str, str] = {
    # ... existing entries ...
    "ifHCInOctets": _IF_HC_IN_OCTETS,
    "ifHCOutOctets": _IF_HC_OUT_OCTETS,
    "ifInErrors": _IF_IN_ERRORS,
}
```

**Step 3: Add parser function**

```python
def _parse_port_statistics(
    raw: dict[str, str],
) -> tuple[tuple[int, int, int, int], ...]:
    """Parse interface statistics from SNMP data.

    Returns tuple of (ifIndex, bytes_rx, bytes_tx, errors) tuples.
    """
    in_octets: dict[int, int] = {}
    out_octets: dict[int, int] = {}
    in_errors: dict[int, int] = {}

    for oid, value in raw.items():
        if oid.startswith(_IF_HC_IN_OCTETS + "."):
            suffix = oid[len(_IF_HC_IN_OCTETS) + 1:]
            ifidx = int(suffix)
            in_octets[ifidx] = int(value)
        elif oid.startswith(_IF_HC_OUT_OCTETS + "."):
            suffix = oid[len(_IF_HC_OUT_OCTETS) + 1:]
            ifidx = int(suffix)
            out_octets[ifidx] = int(value)
        elif oid.startswith(_IF_IN_ERRORS + "."):
            suffix = oid[len(_IF_IN_ERRORS) + 1:]
            ifidx = int(suffix)
            in_errors[ifidx] = int(value)

    # Combine into tuples for all interfaces that have data
    all_ifidx = set(in_octets.keys()) | set(out_octets.keys())
    result = []
    for ifidx in sorted(all_ifidx):
        result.append((
            ifidx,
            in_octets.get(ifidx, 0),
            out_octets.get(ifidx, 0),
            in_errors.get(ifidx, 0),
        ))
    return tuple(result)
```

**Step 4: Add port_statistics to BridgeData**

In `src/gdoc2netcfg/models/host.py`, add to BridgeData class:

```python
    port_statistics: tuple[tuple[int, int, int, int], ...] = ()
    # (ifIndex, bytes_rx, bytes_tx, errors)
```

**Step 5: Wire into collect_bridge_data**

In the function that creates BridgeData, add:

```python
    port_statistics=_parse_port_statistics(raw),
```

**Step 6: Update bridge_to_switch_data to include stats**

```python
    # Convert port statistics
    port_stats = tuple(
        PortTrafficStats(
            port_id=ifidx,
            bytes_rx=rx,
            bytes_tx=tx,
            errors=err,
        )
        for ifidx, rx, tx, err in bridge.port_statistics
    )
```

And add to the SwitchData return:

```python
        port_stats=port_stats,
```

**Step 7: Add tests**

```python
def test_parse_port_statistics():
    from gdoc2netcfg.supplements.bridge import _parse_port_statistics

    raw = {
        "1.3.6.1.2.1.31.1.1.1.6.1": "1000",
        "1.3.6.1.2.1.31.1.1.1.6.2": "2000",
        "1.3.6.1.2.1.31.1.1.1.10.1": "500",
        "1.3.6.1.2.1.31.1.1.1.10.2": "1000",
        "1.3.6.1.2.1.2.2.1.14.1": "5",
        "1.3.6.1.2.1.2.2.1.14.2": "0",
    }
    result = _parse_port_statistics(raw)

    assert len(result) == 2
    assert result[0] == (1, 1000, 500, 5)
    assert result[1] == (2, 2000, 1000, 0)
```

**Step 8: Run tests**

```bash
uv run pytest tests/test_supplements/test_bridge.py -v
```

**Step 9: Commit**

```bash
git add src/gdoc2netcfg/models/host.py src/gdoc2netcfg/supplements/bridge.py tests/
git commit -m "Add port statistics collection to SNMP bridge supplement"
```

---

## Task 11: Update CLI nsdp show Command

Update the CLI to display the new NSDP data fields.

**Files:**
- Modify: `src/gdoc2netcfg/cli/main.py`

**Step 1: Update cmd_nsdp_show to display new fields**

In the nsdp show command, after printing port PVIDs, add sections for:

```python
        # VLAN memberships
        if info.get("vlan_members"):
            print("\nVLAN Memberships:")
            for vlan_id, members, tagged in info["vlan_members"]:
                untagged = set(members) - set(tagged)
                print(f"  VLAN {vlan_id:3d}: members={sorted(members)}")
                if tagged:
                    print(f"            tagged={sorted(tagged)}")
                if untagged:
                    print(f"            untagged={sorted(untagged)}")

        # Port statistics
        if info.get("port_statistics"):
            print("\nPort Statistics:")
            for port_id, rx, tx, errors in info["port_statistics"]:
                print(f"  Port {port_id:2d}: RX={rx:,} TX={tx:,} Errors={errors}")
```

**Step 2: Run manual test**

```bash
uv run gdoc2netcfg nsdp scan --force
uv run gdoc2netcfg nsdp show
```

**Step 3: Commit**

```bash
git add src/gdoc2netcfg/cli/main.py
git commit -m "Display VLAN memberships and port statistics in nsdp show"
```

---

## Task 12: Run Full Test Suite and Final Cleanup

Verify everything works together.

**Step 1: Run full test suite**

```bash
uv run pytest -v
```

**Step 2: Run linter**

```bash
uv run ruff check src/ tests/
```

**Step 3: Fix any issues found**

**Step 4: Final commit if needed**

```bash
git add -A
git commit -m "Fix lint issues and cleanup"
```

---

## Summary

After completing all tasks:

1. **NSDP now caches** vlan_engine, vlan_members, port_statistics
2. **New NSDP tags** for QoS, IGMP, mirroring, loop detection
3. **Unified SwitchData** model that both sources populate
4. **SNMP now collects** port statistics (ifHCInOctets, etc.)
5. **Host.switch_data** provides consistent access regardless of source
6. **CLI shows** all collected data

Consumers can now use `host.switch_data` and not care whether the data came from SNMP or NSDP.
