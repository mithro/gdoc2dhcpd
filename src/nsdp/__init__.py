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
