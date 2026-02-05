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


def parse_port_qos(data: bytes) -> PortQoS | None:
    """Parse NSDP tag 0x3800 (2 bytes: port_id, priority).

    Returns None if data is not exactly 2 bytes.
    """
    if len(data) != 2:
        return None
    return PortQoS(port_id=data[0], priority=data[1])


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
    port_qos_list: list[PortQoS] = []
    qos_engine: int | None = None
    port_mirroring_obj: PortMirroring | None = None
    igmp_snooping_obj: IGMPSnooping | None = None
    broadcast_filtering: bool | None = None
    loop_detection: bool | None = None

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
        port_qos=tuple(port_qos_list),
        qos_engine=qos_engine,
        port_mirroring=port_mirroring_obj,
        igmp_snooping=igmp_snooping_obj,
        broadcast_filtering=broadcast_filtering,
        loop_detection=loop_detection,
    )
