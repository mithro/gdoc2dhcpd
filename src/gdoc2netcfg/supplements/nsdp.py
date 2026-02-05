"""Supplement: NSDP discovery data collection.

Scans Netgear switches via the NSDP broadcast protocol to retrieve
device identity, firmware version, port status, and VLAN configuration.
Results are cached in nsdp.json.

This is primarily useful for unmanaged switches (hardware_type =
"netgear-switch-plus") that lack SNMP support. NSDP provides the only
programmatic way to query these devices.

The NSDP protocol client lives in the standalone `nsdp` package.
This module is the bridge between that package and gdoc2netcfg's
supplement pipeline.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

from gdoc2netcfg.derivations.hardware import (
    HARDWARE_NETGEAR_SWITCH,
    HARDWARE_NETGEAR_SWITCH_PLUS,
)
from gdoc2netcfg.models.host import NSDPData

if TYPE_CHECKING:
    from gdoc2netcfg.models.host import Host
    from gdoc2netcfg.supplements.reachability import HostReachability

NSDP_HARDWARE_TYPES = frozenset({HARDWARE_NETGEAR_SWITCH, HARDWARE_NETGEAR_SWITCH_PLUS})


def load_nsdp_cache(cache_path: Path) -> dict[str, dict]:
    """Load cached NSDP data from disk."""
    if not cache_path.exists():
        return {}
    with open(cache_path) as f:
        return json.load(f)


def save_nsdp_cache(cache_path: Path, data: dict[str, dict]) -> None:
    """Save NSDP data to disk cache."""
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    with open(cache_path, "w") as f:
        json.dump(data, f, indent="  ", sort_keys=True)


def scan_nsdp(
    hosts: list[Host],
    cache_path: Path,
    force: bool = False,
    max_age: float = 300,
    verbose: bool = False,
    reachability: dict[str, HostReachability] | None = None,
    interface: str | None = None,
) -> dict[str, dict]:
    """Scan Netgear switches via NSDP broadcast discovery.

    Sends a single NSDP broadcast and matches responses to known hosts
    by MAC address.

    Args:
        hosts: Host objects to match against NSDP responses.
        cache_path: Path to nsdp.json cache file.
        force: Force re-scan even if cache is fresh.
        max_age: Maximum cache age in seconds (default 5 minutes).
        verbose: Print progress to stderr.
        reachability: Pre-computed reachability data (not used for
            filtering — NSDP is broadcast-based, so all switches on
            the broadcast domain respond regardless).
        interface: Network interface for NSDP broadcast (e.g. "eth0").
            Required for actual scanning; if None, returns cached data
            only.

    Returns:
        Mapping of hostname to NSDP data dict.
    """
    nsdp_data = load_nsdp_cache(cache_path)

    # Check if cache is fresh enough
    if not force and cache_path.exists():
        age = time.time() - cache_path.stat().st_mtime
        if age < max_age:
            if verbose:
                print(f"nsdp.json last updated {age:.0f}s ago, using cache.", file=sys.stderr)
            return nsdp_data

    if interface is None:
        if verbose:
            print("No interface specified for NSDP scan, using cache only.", file=sys.stderr)
        return nsdp_data

    # Build MAC → hostname index for matching NSDP responses to hosts
    mac_to_hostname: dict[str, str] = {}
    for host in hosts:
        if host.hardware_type not in NSDP_HARDWARE_TYPES:
            continue
        for iface in host.interfaces:
            mac_to_hostname[str(iface.mac).lower()] = host.hostname

    if not mac_to_hostname:
        if verbose:
            print("No Netgear switches to scan.", file=sys.stderr)
        return nsdp_data

    if verbose:
        print(f"Scanning {len(mac_to_hostname)} Netgear switch(es) via NSDP...", file=sys.stderr)

    try:
        from nsdp import NSDPClient

        with NSDPClient(interface) as client:
            devices = client.discover(timeout=3.0)

        for device in devices:
            hostname = mac_to_hostname.get(device.mac.lower())
            if hostname is None:
                if verbose:
                    print(
                        f"  NSDP: unknown device {device.model} "
                        f"({device.mac}) at {device.ip}",
                        file=sys.stderr,
                    )
                continue

            entry: dict = {
                "model": device.model,
                "mac": device.mac,
            }
            if device.hostname is not None:
                entry["hostname"] = device.hostname
            if device.ip is not None:
                entry["ip"] = device.ip
            if device.netmask is not None:
                entry["netmask"] = device.netmask
            if device.gateway is not None:
                entry["gateway"] = device.gateway
            if device.firmware_version is not None:
                entry["firmware_version"] = device.firmware_version
            if device.dhcp_enabled is not None:
                entry["dhcp_enabled"] = device.dhcp_enabled
            if device.port_count is not None:
                entry["port_count"] = device.port_count
            if device.serial_number is not None:
                entry["serial_number"] = device.serial_number
            if device.port_status:
                entry["port_status"] = [
                    (ps.port_id, ps.speed.value) for ps in device.port_status
                ]
            if device.port_pvids:
                entry["port_pvids"] = [
                    (pp.port_id, pp.vlan_id) for pp in device.port_pvids
                ]

            nsdp_data[hostname] = entry
            if verbose:
                fw = device.firmware_version or "?"
                print(f"  {hostname}: {device.model} fw={fw}", file=sys.stderr)

    except PermissionError:
        print(
            "Error: NSDP scan requires elevated privileges.\n"
            "  Run with: sudo uv run gdoc2netcfg nsdp --interface <iface>\n"
            "  Or grant capability: sudo setcap cap_net_raw+ep $(which python3)",
            file=sys.stderr,
        )
    except Exception as e:
        print(f"Error during NSDP scan: {e}", file=sys.stderr)

    save_nsdp_cache(cache_path, nsdp_data)
    return nsdp_data


def enrich_hosts_with_nsdp(
    hosts: list[Host],
    nsdp_cache: dict[str, dict],
) -> None:
    """Attach cached NSDP data to Host objects.

    Modifies hosts in-place by setting host.nsdp_data.
    """
    for host in hosts:
        info = nsdp_cache.get(host.hostname)
        if info is not None:
            host.nsdp_data = NSDPData(
                model=info["model"],
                mac=info["mac"],
                hostname=info.get("hostname"),
                ip=info.get("ip"),
                netmask=info.get("netmask"),
                gateway=info.get("gateway"),
                firmware_version=info.get("firmware_version"),
                dhcp_enabled=info.get("dhcp_enabled"),
                port_count=info.get("port_count"),
                serial_number=info.get("serial_number"),
                port_status=tuple(
                    (ps[0], ps[1]) for ps in info.get("port_status", [])
                ),
                port_pvids=tuple(
                    (pp[0], pp[1]) for pp in info.get("port_pvids", [])
                ),
            )
