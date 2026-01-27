"""Supplement: SSH fingerprint scanning.

Scans hosts for SSH availability and retrieves SSHFP (DNS RR type 44)
records using ssh-keyscan. Results are cached in sshfp.json to avoid
re-scanning on every pipeline run.

This is a Supplement, not a Source — it enriches existing Host records
with additional data from external systems (SSH daemons).
"""

from __future__ import annotations

import json
import socket
import subprocess
import time
from pathlib import Path

from gdoc2netcfg.models.host import Host


def _ping(ip: str, packets: int = 5) -> bool:
    """Check if a host responds to ICMP ping."""
    try:
        result = subprocess.run(
            ["ping", "-n", "-A", "-c", str(packets), "-w", "1", ip],
            capture_output=True,
            text=True,
        )
        return f"{packets} packets transmitted, {packets} received" in result.stdout
    except FileNotFoundError:
        return False


def _check_ssh_port(ip: str, timeout: float = 0.5) -> bool:
    """Check if SSH port 22 is open on the host."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((ip, 22)) == 0
    finally:
        sock.close()


def _keyscan(ip: str, hostname: str) -> list[str]:
    """Run ssh-keyscan -D and return SSHFP records.

    Returns lines like "hostname IN SSHFP 1 2 abc123..."
    """
    try:
        result = subprocess.run(
            ["ssh-keyscan", "-D", ip],
            capture_output=True,
            text=True,
            timeout=10,
        )
        lines = result.stdout.replace(ip, hostname).splitlines()
        lines.sort()
        return lines
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return []


def load_sshfp_cache(cache_path: Path) -> dict[str, list[str]]:
    """Load cached SSHFP data from disk."""
    if not cache_path.exists():
        return {}
    with open(cache_path) as f:
        return json.load(f)


def save_sshfp_cache(cache_path: Path, data: dict[str, list[str]]) -> None:
    """Save SSHFP data to disk cache."""
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    with open(cache_path, "w") as f:
        json.dump(data, f, indent="  ", sort_keys=True)


def scan_sshfp(
    hosts: list[Host],
    cache_path: Path,
    force: bool = False,
    max_age: float = 300,
    verbose: bool = False,
) -> dict[str, list[str]]:
    """Scan hosts for SSH fingerprints.

    Args:
        hosts: Host objects with IPs to scan.
        cache_path: Path to sshfp.json cache file.
        force: Force re-scan even if cache is fresh.
        max_age: Maximum cache age in seconds (default 5 minutes).
        verbose: Print progress to stdout.

    Returns:
        Mapping of hostname → list of SSHFP record lines.
    """
    import sys

    sshfp = load_sshfp_cache(cache_path)

    # Check if cache is fresh enough
    if not force and cache_path.exists():
        age = time.time() - cache_path.stat().st_mtime
        if age < max_age:
            if verbose:
                print(f"sshfp.json last updated {age:.0f}s ago, using cache.", file=sys.stderr)
            return sshfp

    for host in sorted(hosts, key=lambda h: h.hostname.split(".")[::-1]):
        if verbose:
            print(f"  {host.hostname:>20s} ", end="", flush=True, file=sys.stderr)

        # Ping all IPs to find active ones
        active_ips = []
        for iface in host.interfaces:
            ip_str = str(iface.ipv4)
            if _ping(ip_str):
                active_ips.append(ip_str)

        if not active_ips:
            if verbose:
                print("down", file=sys.stderr)
            continue

        if verbose:
            print(f"up({','.join(active_ips)}) ", end="", flush=True, file=sys.stderr)

        # Check SSH availability
        ssh_ip = None
        for ip in active_ips:
            if _check_ssh_port(ip):
                ssh_ip = ip
                break

        if ssh_ip is None:
            if verbose:
                print("no-ssh", file=sys.stderr)
            continue

        if verbose:
            print("with-ssh", file=sys.stderr)

        records = _keyscan(ssh_ip, host.hostname)
        if records:
            sshfp[host.hostname] = records

    save_sshfp_cache(cache_path, sshfp)
    return sshfp


def enrich_hosts_with_sshfp(
    hosts: list[Host],
    sshfp_data: dict[str, list[str]],
) -> None:
    """Attach cached SSHFP records to Host objects.

    Modifies hosts in-place by setting host.sshfp_records.
    """
    for host in hosts:
        records = sshfp_data.get(host.hostname, [])
        host.sshfp_records = records
