"""Supplement: SSH fingerprint scanning.

Scans hosts for SSH availability and retrieves SSHFP (DNS RR type 44)
records using ssh-keyscan. Results are cached in sshfp.json to avoid
re-scanning on every pipeline run.

This is a Supplement, not a Source — it enriches existing Host records
with additional data from external systems (SSH daemons).
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

from gdoc2netcfg.models.host import Host
from gdoc2netcfg.supplements.reachability import (
    HostReachability,
    check_port_open,
)


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
    reachability: dict[str, HostReachability] | None = None,
) -> dict[str, list[str]]:
    """Scan reachable hosts for SSH fingerprints.

    Args:
        hosts: Host objects with IPs to scan.
        cache_path: Path to sshfp.json cache file.
        force: Force re-scan even if cache is fresh.
        max_age: Maximum cache age in seconds (default 5 minutes).
        verbose: Print progress to stderr.
        reachability: Pre-computed reachability data from the
            reachability pass. Only reachable hosts are scanned.

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

    sorted_hosts = sorted(hosts, key=lambda h: h.hostname.split(".")[::-1])
    name_width = max((len(h.hostname) for h in sorted_hosts), default=0)

    for host in sorted_hosts:
        # Skip hosts not in reachability data or not reachable
        host_reach = reachability.get(host.hostname) if reachability else None
        if host_reach is None or not host_reach.is_up:
            continue
        active_ips = list(host_reach.active_ips)

        if verbose:
            print(
                f"  {host.hostname:>{name_width}s} up({','.join(active_ips)}) ",
                end="", flush=True, file=sys.stderr,
            )

        # Check SSH availability on all reachable IPs
        ssh_ips = [ip for ip in active_ips if check_port_open(ip, 22)]

        if not ssh_ips:
            if verbose:
                print("no-ssh", file=sys.stderr)
            continue

        if verbose:
            print(f"with-ssh({','.join(ssh_ips)})", file=sys.stderr)

        # Keyscan all IPs with SSH and merge records (deduplicated)
        all_records: set[str] = set()
        for ssh_ip in ssh_ips:
            records = _keyscan(ssh_ip, host.hostname)
            all_records.update(records)

        if all_records:
            sshfp[host.hostname] = sorted(all_records)

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
