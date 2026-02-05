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

    Values 0x00–0x05 are documented for older switches. Value 0xFF is
    used by newer hardware (e.g. GS110EMX) for 10G links. Values for
    2.5G and 5G are not yet known.
    """

    DOWN = 0x00
    HALF_10M = 0x01
    FULL_10M = 0x02
    HALF_100M = 0x03
    FULL_100M = 0x04
    GIGABIT = 0x05
    TEN_GIGABIT = 0xFF  # 10G link (observed on GS110EMX ports 9-10)

    @classmethod
    def from_byte(cls, value: int) -> LinkSpeed:
        """Parse a speed byte, returning DOWN for unrecognised values."""
        try:
            return cls(value)
        except ValueError:
            # Unknown speed code - treat as down/unknown
            return cls.DOWN

    @property
    def speed_mbps(self) -> int:
        """Approximate speed in Mbps (0 for down)."""
        return {
            LinkSpeed.DOWN: 0,
            LinkSpeed.HALF_10M: 10,
            LinkSpeed.FULL_10M: 10,
            LinkSpeed.HALF_100M: 100,
            LinkSpeed.FULL_100M: 100,
            LinkSpeed.GIGABIT: 1000,
            LinkSpeed.TEN_GIGABIT: 10000,
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
