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

    def query_ip(
        self,
        ip: str,
        tags: list[Tag] | None = None,
        timeout: float = 2.0,
    ) -> NSDPDevice | None:
        """Query a switch by IP address (unicast).

        Sends a unicast NSDP read request to the specified IP address.
        This is more reliable than broadcast on networks with VLANs or
        where broadcast doesn't reach all switches.

        Args:
            ip: Switch IP address (e.g. "10.1.5.25").
            tags: Tags to request (default: DISCOVERY_TAGS).
            timeout: Seconds to wait for the response.

        Returns:
            NSDPDevice if the switch responds, None otherwise.
        """
        sock = self._get_socket()
        sock.settimeout(timeout)

        request_tags = tags or DISCOVERY_TAGS
        pkt = self._build_read_request(request_tags)
        sock.sendto(pkt.encode(), (ip, SERVER_PORT_V2))

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
