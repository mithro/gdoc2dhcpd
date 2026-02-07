"""Shared network reachability checks.

Provides ping and port-check utilities used by multiple supplements
(SSHFP scanning, SSL certificate scanning, etc.).
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
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


def check_reachable(ip: str, packets: int = 10) -> PingResult:
    """Check if a host responds to ICMP ping.

    Args:
        ip: IPv4 or IPv6 address string to ping.
        packets: Number of ping packets to send.

    Returns:
        PingResult with packet counts and latency.
    """
    try:
        result = subprocess.run(
            ["ping", "-n", "-A", "-c", str(packets), "-W", "1", ip],
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


def _detect_ip_version(ip: str) -> int:
    """Return 4 or 6 based on the IP string format."""
    return ipaddress.ip_address(ip).version


def check_port_open(ip: str, port: int, timeout: float = 0.5) -> bool:
    """Check if a TCP port is open on the host.

    Args:
        ip: IPv4 or IPv6 address string.
        port: TCP port number to check.
        timeout: Connection timeout in seconds.

    Returns:
        True if the port is open and accepting connections.
    """
    family = socket.AF_INET6 if _detect_ip_version(ip) == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((ip, port)) == 0
    finally:
        sock.close()


@dataclass(frozen=True)
class InterfaceReachability:
    """Reachability state for a single VirtualInterface."""

    pings: tuple[tuple[str, PingResult], ...] = ()

    @property
    def active_ips(self) -> tuple[str, ...]:
        """IPs that responded to ping."""
        return tuple(addr for addr, pr in self.pings if pr)

    @property
    def active_ipv4(self) -> tuple[str, ...]:
        """Reachable IPv4 addresses."""
        return tuple(addr for addr in self.active_ips if _detect_ip_version(addr) == 4)

    @property
    def active_ipv6(self) -> tuple[str, ...]:
        """Reachable IPv6 addresses."""
        return tuple(addr for addr in self.active_ips if _detect_ip_version(addr) == 6)

    @property
    def has_ipv4(self) -> bool:
        """True if any IPv4 address is reachable."""
        return len(self.active_ipv4) > 0

    @property
    def has_ipv6(self) -> bool:
        """True if any IPv6 address is reachable."""
        return len(self.active_ipv6) > 0

    @property
    def reachability_mode(self) -> str:
        """'unreachable', 'ipv4-only', 'ipv6-only', or 'dual-stack'."""
        v4 = self.has_ipv4
        v6 = self.has_ipv6
        if v4 and v6:
            return "dual-stack"
        if v4:
            return "ipv4-only"
        if v6:
            return "ipv6-only"
        return "unreachable"


@dataclass(frozen=True)
class HostReachability:
    """Pre-computed reachability state for a single host.

    Stores which IPs responded to ping so multiple supplements can
    skip redundant per-host ping loops.
    """

    hostname: str
    active_ips: tuple[str, ...] = ()
    interfaces: tuple[InterfaceReachability, ...] = ()

    @property
    def is_up(self) -> bool:
        """True if any IP responded to ping."""
        return len(self.active_ips) > 0

    @property
    def active_ipv4(self) -> tuple[str, ...]:
        """Reachable IPv4 addresses."""
        return tuple(addr for addr in self.active_ips if _detect_ip_version(addr) == 4)

    @property
    def active_ipv6(self) -> tuple[str, ...]:
        """Reachable IPv6 addresses."""
        return tuple(addr for addr in self.active_ips if _detect_ip_version(addr) == 6)

    @property
    def has_ipv4(self) -> bool:
        """True if any IPv4 address is reachable."""
        return len(self.active_ipv4) > 0

    @property
    def has_ipv6(self) -> bool:
        """True if any IPv6 address is reachable."""
        return len(self.active_ipv6) > 0

    @property
    def reachability_mode(self) -> str:
        """'unreachable', 'ipv4-only', 'ipv6-only', or 'dual-stack'."""
        v4 = self.has_ipv4
        v6 = self.has_ipv6
        if v4 and v6:
            return "dual-stack"
        if v4:
            return "ipv4-only"
        if v6:
            return "ipv6-only"
        return "unreachable"


_MODE_LABELS = {
    "dual-stack": "up (v46)",
    "ipv4-only":  "up (v4_)",
    "ipv6-only":  "up (v_6)",
    "unreachable": "down",
}
_LABEL_WIDTH = max(len(v) for v in _MODE_LABELS.values())


def print_reachability_status(
    reachability: dict[str, HostReachability],
) -> None:
    """Print per-host reachability status to stderr.

    Works with both live scan results and cached data.  When the cache
    is loaded, per-IP packet counts and RTT are not available so only
    the active IPs are shown.
    """
    import shutil
    import sys

    if not reachability:
        return

    sorted_hosts = sorted(
        reachability.values(),
        key=lambda hr: hr.hostname.split(".")[::-1],
    )
    name_width = max(len(hr.hostname) for hr in sorted_hosts)

    all_ips: list[str] = []
    for hr in sorted_hosts:
        all_ips.extend(hr.active_ips)
    ip_width = max((len(ip) for ip in all_ips), default=1)

    prefix_width = 2 + name_width + 1 + _LABEL_WIDTH + 2
    prefix = " " * prefix_width
    cell_width = ip_width
    cell_gap = 2
    term_width = shutil.get_terminal_size().columns
    avail = term_width - prefix_width
    cols = max(1, avail // (cell_width + cell_gap))

    print(file=sys.stderr)

    for hr in sorted_hosts:
        label = _MODE_LABELS.get(hr.reachability_mode, "down")
        cells = [f"{ip:<{ip_width}s}" for ip in hr.active_ips]
        if not cells:
            print(
                f"  {hr.hostname:>{name_width}s}"
                f" {label:<{_LABEL_WIDTH}s}",
                file=sys.stderr,
            )
            continue
        first_row = True
        for row_start in range(0, len(cells), cols):
            row = "  ".join(cells[row_start:row_start + cols])
            if first_row:
                print(
                    f"  {hr.hostname:>{name_width}s}"
                    f" {label:<{_LABEL_WIDTH}s}"
                    f"  {row}",
                    file=sys.stderr,
                )
                first_row = False
            else:
                print(f"{prefix}{row}", file=sys.stderr)

    print(file=sys.stderr)


def save_reachability_cache(
    cache_path: Path,
    reachability: dict[str, HostReachability],
) -> None:
    """Save reachability data to disk cache (v2 format).

    The v2 format stores full ping data per interface so that cached
    output is identical to live output.
    """
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    hosts: dict[str, dict] = {}
    for hostname, hr in reachability.items():
        ifaces: list[list[dict]] = []
        for ir in hr.interfaces:
            pings: list[dict] = []
            for ip_str, pr in ir.pings:
                pings.append({
                    "ip": ip_str,
                    "transmitted": pr.transmitted,
                    "received": pr.received,
                    "rtt_avg_ms": pr.rtt_avg_ms,
                })
            ifaces.append(pings)
        hosts[hostname] = {"interfaces": ifaces}
    data = {"version": 2, "hosts": hosts}
    with open(cache_path, "w") as f:
        json.dump(data, f, indent="  ", sort_keys=True)


def load_reachability_cache(
    cache_path: Path,
    max_age: float = 300,
) -> tuple[dict[str, HostReachability], float] | None:
    """Load cached reachability data from disk.

    Returns (data, age_seconds) tuple if cache is fresh, or None if the
    cache file is missing, older than max_age seconds, or corrupted.
    """
    if not cache_path.exists():
        return None
    age = time.time() - cache_path.stat().st_mtime
    if age >= max_age:
        return None
    try:
        with open(cache_path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None
    # Cache only persists host-level active_ips; per-interface detail
    # (the `interfaces` field) is not saved and will be empty on load.
    reachability = {
        hostname: HostReachability(hostname=hostname, active_ips=tuple(ips))
        for hostname, ips in data.items()
    }
    return (reachability, age)


def check_all_hosts_reachability(
    hosts: list[Host],
    verbose: bool = False,
    max_workers: int = 64,
) -> dict[str, HostReachability]:
    """Ping all IPs for every host in parallel and return reachability state.

    All pings are submitted to a thread pool immediately.  Results are
    collected per-host in sorted order so verbose output stays ordered
    even though the actual pings run concurrently.

    Args:
        hosts: Host objects with IPs to check.
        verbose: Print progress to stderr.
        max_workers: Maximum concurrent ping subprocesses.

    Returns:
        Mapping of hostname to HostReachability.
    """
    import sys
    from concurrent.futures import Future, ThreadPoolExecutor

    result: dict[str, HostReachability] = {}
    sorted_hosts = sorted(hosts, key=lambda h: h.hostname.split(".")[::-1])
    name_width = max((len(h.hostname) for h in sorted_hosts), default=0)

    # Pre-compute alignment widths from the known IP strings so we can
    # print each host progressively as its pings complete, rather than
    # waiting for all hosts to finish before displaying anything.
    all_known_ips: list[str] = []
    for host in sorted_hosts:
        for vi in host.virtual_interfaces:
            all_known_ips.extend(vi.all_ips)
    ip_width = max((len(ip) for ip in all_known_ips), default=1)

    if verbose:
        import shutil

        prefix_width = 2 + name_width + 1 + _LABEL_WIDTH + 2
        prefix = " " * prefix_width
        rtt_width = 8  # e.g. " 489.2ms"
        cell_width = ip_width + 2 + 5 + 2 + rtt_width
        cell_gap = 2
        term_width = shutil.get_terminal_size().columns
        avail = term_width - prefix_width
        cols = max(1, avail // (cell_width + cell_gap))

        print(file=sys.stderr)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        # Submit all pings up front, deduplicating IPs across interfaces.
        host_futures: list[
            tuple[Host, list[tuple[int, str, Future[PingResult]]]]
        ] = []
        for host in sorted_hosts:
            ip_futures: list[tuple[int, str, Future[PingResult]]] = []
            seen_ips: set[str] = set()
            for vi_idx, vi in enumerate(host.virtual_interfaces):
                for ip_str in vi.all_ips:
                    if ip_str in seen_ips:
                        continue
                    seen_ips.add(ip_str)
                    future = pool.submit(check_reachable, ip_str)
                    ip_futures.append((vi_idx, ip_str, future))
            host_futures.append((host, ip_futures))

        # Collect results in sorted order — blocks on each host's futures
        # while remaining hosts continue pinging in the background.
        # Prints each host as soon as its pings complete.
        for host, ip_futures in host_futures:
            active_ips: list[str] = []
            vi_count = len(host.virtual_interfaces)
            iface_pings: list[list[tuple[str, PingResult]]] = [
                [] for _ in range(vi_count)
            ]

            for vi_idx, ip_str, future in ip_futures:
                ping = future.result()
                iface_pings[vi_idx].append((ip_str, ping))
                if ping:
                    active_ips.append(ip_str)

            iface_reachability = tuple(
                InterfaceReachability(pings=tuple(pings))
                for pings in iface_pings
            )

            hr = HostReachability(
                hostname=host.hostname,
                active_ips=tuple(active_ips),
                interfaces=iface_reachability,
            )
            result[host.hostname] = hr

            # Print this host immediately.
            if verbose:
                label = _MODE_LABELS.get(hr.reachability_mode, "down")
                first_row = True
                for pings in iface_pings:
                    cells = []
                    for ip_str, ping in pings:
                        pkt = f"{ping.received:>2}/{ping.transmitted}"
                        if ping.rtt_avg_ms is not None:
                            rtt = f"{ping.rtt_avg_ms:>6.1f}ms"
                        else:
                            rtt = " " * rtt_width
                        cells.append(
                            f"{ip_str:<{ip_width}s}  {pkt}  {rtt}"
                        )
                    for row_start in range(0, len(cells), cols):
                        row = "  ".join(
                            cells[row_start:row_start + cols]
                        )
                        if first_row:
                            print(
                                f"  {host.hostname:>{name_width}s}"
                                f" {label:<{_LABEL_WIDTH}s}"
                                f"  {row}",
                                file=sys.stderr,
                            )
                            first_row = False
                        else:
                            print(
                                f"{prefix}{row}",
                                file=sys.stderr,
                            )

    if verbose:
        print(file=sys.stderr)

    return result
