"""Shared network reachability checks.

Provides ping and port-check utilities used by multiple supplements
(SSHFP scanning, SSL certificate scanning, etc.).
"""

from __future__ import annotations

import socket
import subprocess
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gdoc2netcfg.models.host import Host


def check_reachable(ip: str, packets: int = 5) -> bool:
    """Check if a host responds to ICMP ping.

    Args:
        ip: IPv4 address string to ping.
        packets: Number of ping packets to send.

    Returns:
        True if all packets were received.
    """
    try:
        result = subprocess.run(
            ["ping", "-n", "-A", "-c", str(packets), "-w", "1", ip],
            capture_output=True,
            text=True,
        )
        return f"{packets} packets transmitted, {packets} received" in result.stdout
    except FileNotFoundError:
        return False


def check_port_open(ip: str, port: int, timeout: float = 0.5) -> bool:
    """Check if a TCP port is open on the host.

    Args:
        ip: IPv4 address string.
        port: TCP port number to check.
        timeout: Connection timeout in seconds.

    Returns:
        True if the port is open and accepting connections.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((ip, port)) == 0
    finally:
        sock.close()


@dataclass(frozen=True)
class HostReachability:
    """Pre-computed reachability state for a single host.

    Stores which IPs responded to ping so multiple supplements can
    skip redundant per-host ping loops.
    """

    hostname: str
    active_ips: tuple[str, ...] = ()

    @property
    def is_up(self) -> bool:
        """True if any IP responded to ping."""
        return len(self.active_ips) > 0


def check_all_hosts_reachability(
    hosts: list[Host],
    verbose: bool = False,
) -> dict[str, HostReachability]:
    """Ping all IPs for each host and return reachability state.

    Iterates hosts sorted by reversed hostname (matching existing
    supplement sort order). For each host, pings every interface IP
    and records which responded.

    Args:
        hosts: Host objects with IPs to check.
        verbose: Print progress to stderr.

    Returns:
        Mapping of hostname to HostReachability.
    """
    import sys

    result: dict[str, HostReachability] = {}

    for host in sorted(hosts, key=lambda h: h.hostname.split(".")[::-1]):
        if verbose:
            print(f"  {host.hostname:>20s} ", end="", flush=True, file=sys.stderr)

        active_ips = []
        for iface in host.interfaces:
            ip_str = str(iface.ipv4)
            if check_reachable(ip_str):
                active_ips.append(ip_str)

        result[host.hostname] = HostReachability(
            hostname=host.hostname,
            active_ips=tuple(active_ips),
        )

        if verbose:
            if result[host.hostname].is_up:
                print(f"up({','.join(active_ips)})", file=sys.stderr)
            else:
                print("down", file=sys.stderr)

    return result
