"""Shared network reachability checks.

Provides ping and port-check utilities used by multiple supplements
(SSHFP scanning, SSL certificate scanning, etc.).
"""

from __future__ import annotations

import re
import socket
import subprocess
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gdoc2netcfg.models.host import Host


@dataclass(frozen=True)
class PingResult:
    """Result of pinging a single IP address.

    Truthy when at least one packet was received, so existing
    ``if check_reachable(ip):`` callers keep working.
    """

    transmitted: int
    received: int
    rtt_avg_ms: float | None = None

    def __bool__(self) -> bool:
        return self.received >= 1


def check_reachable(ip: str, packets: int = 5) -> PingResult:
    """Check if a host responds to ICMP ping.

    Args:
        ip: IPv4 address string to ping.
        packets: Number of ping packets to send.

    Returns:
        PingResult with packet counts and latency.
    """
    try:
        result = subprocess.run(
            ["ping", "-n", "-A", "-c", str(packets), "-w", "1", ip],
            capture_output=True,
            text=True,
        )
        match = re.search(
            r"(\d+) packets transmitted, (\d+) received", result.stdout
        )
        if match is None:
            return PingResult(packets, 0)
        transmitted = int(match.group(1))
        received = int(match.group(2))
        rtt_avg = None
        if received > 0:
            rtt_match = re.search(
                r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", result.stdout
            )
            if rtt_match:
                rtt_avg = float(rtt_match.group(1))
        return PingResult(transmitted, received, rtt_avg)
    except FileNotFoundError:
        return PingResult(0, 0)


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
    sorted_hosts = sorted(hosts, key=lambda h: h.hostname.split(".")[::-1])
    name_width = max((len(h.hostname) for h in sorted_hosts), default=0)

    for host in sorted_hosts:
        active_ips = []
        ip_results: list[tuple[str, PingResult]] = []
        for iface in host.interfaces:
            ip_str = str(iface.ipv4)
            ping = check_reachable(ip_str)
            ip_results.append((ip_str, ping))
            if ping:
                active_ips.append(ip_str)

        result[host.hostname] = HostReachability(
            hostname=host.hostname,
            active_ips=tuple(active_ips),
        )

        if verbose:
            parts = []
            for ip_str, ping in ip_results:
                part = f"{ip_str} {ping.received}/{ping.transmitted}"
                if ping.rtt_avg_ms is not None:
                    part += f" {ping.rtt_avg_ms:.1f}ms"
                parts.append(part)
            detail = ", ".join(parts)
            label = "up" if result[host.hostname].is_up else "down"
            print(
                f"  {host.hostname:>{name_width}s} {label}({detail})",
                file=sys.stderr,
            )

    return result
