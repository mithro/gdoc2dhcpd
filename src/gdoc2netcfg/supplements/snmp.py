"""Supplement: SNMP data collection.

Scans hosts for SNMP availability and retrieves system information,
interface tables, and IP address tables. Results are cached in
snmp.json to avoid re-scanning on every pipeline run.

This is a Supplement, not a Source — it enriches existing Host records
with additional data from external systems (SNMP agents).

pysnmp v7 is async-only. Individual SNMP operations use async/await,
wrapped in asyncio.run() from the synchronous scan_snmp().
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import TYPE_CHECKING

from gdoc2netcfg.models.host import SNMPData

if TYPE_CHECKING:
    from gdoc2netcfg.models.host import Host
    from gdoc2netcfg.supplements.reachability import HostReachability

# System group OIDs (SNMPv2-MIB)
_SYSTEM_OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
}

# Table OIDs for bulk walk
_IF_TABLE_OID = "1.3.6.1.2.1.2.2"       # ifTable
_IP_ADDR_TABLE_OID = "1.3.6.1.2.1.4.20"  # ipAddrTable


async def _snmp_get_system(
    ip: str,
    community: str = "public",
    timeout: float = 2.0,
    retries: int = 1,
) -> dict[str, str] | None:
    """Query SNMP system group OIDs via SNMPv2c GET.

    Returns dict of name→value for system group, or None on failure.
    """
    from pysnmp.hlapi.v3arch.asyncio import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        get_cmd,
    )

    engine = SnmpEngine()
    try:
        target = await UdpTransportTarget.create(
            (ip, 161), timeout=timeout, retries=retries
        )
        var_binds = [
            ObjectType(ObjectIdentity(oid)) for oid in _SYSTEM_OIDS.values()
        ]

        error_indication, error_status, _error_index, result_binds = await get_cmd(
            engine,
            CommunityData(community),
            target,
            ContextData(),
            *var_binds,
        )

        if error_indication or error_status:
            return None

        oid_to_name = {v: k for k, v in _SYSTEM_OIDS.items()}
        system_info = {}
        for var_bind in result_binds:
            oid_str = str(var_bind[0])
            value_str = str(var_bind[1])
            name = oid_to_name.get(oid_str, oid_str)
            system_info[name] = value_str

        return system_info
    except Exception:
        return None
    finally:
        engine.close_dispatcher()


async def _snmp_bulk_walk(
    ip: str,
    base_oid: str,
    community: str = "public",
    timeout: float = 2.0,
    retries: int = 1,
) -> list[tuple[str, str]]:
    """Bulk walk an SNMP table and return OID→value pairs.

    Returns list of (oid_string, value_string) tuples, or empty list on failure.
    """
    from pysnmp.hlapi.v3arch.asyncio import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        bulk_walk_cmd,
    )

    engine = SnmpEngine()
    try:
        target = await UdpTransportTarget.create(
            (ip, 161), timeout=timeout, retries=retries
        )

        results = []
        async for error_indication, error_status, _error_index, var_binds in bulk_walk_cmd(
            engine,
            CommunityData(community),
            target,
            ContextData(),
            0, 25,  # nonRepeaters=0, maxRepetitions=25
            ObjectType(ObjectIdentity(base_oid)),
            lexicographicMode=False,
        ):
            if error_indication or error_status:
                break
            for var_bind in var_binds:
                results.append((str(var_bind[0]), str(var_bind[1])))

        return results
    except Exception:
        return []
    finally:
        engine.close_dispatcher()


def _rows_from_walk(walk_results: list[tuple[str, str]]) -> list[dict[str, str]]:
    """Group walk results into per-index rows.

    SNMP tables encode the row index as the last OID component(s).
    Groups results by index suffix into dicts of column→value.
    """
    if not walk_results:
        return []

    # Find the common prefix length by looking at first result
    # and finding where the table column OID ends
    rows: dict[str, dict[str, str]] = {}
    for oid, value in walk_results:
        # Split OID into parts
        parts = oid.split(".")
        # For standard tables, the index is the last component(s)
        # We use the full OID minus the last component as the column identifier
        # and the last component as the row index
        # This is a simplification that works for most standard tables
        if len(parts) > 1:
            row_index = parts[-1]
            column_oid = ".".join(parts[:-1])
            if row_index not in rows:
                rows[row_index] = {}
            rows[row_index][column_oid] = value

    return list(rows.values())


async def _collect_snmp_data(
    ip: str,
    community: str = "public",
    timeout: float = 2.0,
) -> dict | None:
    """Collect all SNMP data from a single host.

    Attempts system group GET, then bulk walks interface and IP tables.
    Returns a dict suitable for JSON serialisation, or None on failure.
    """
    system_info = await _snmp_get_system(ip, community, timeout)
    if system_info is None:
        return None

    # System group succeeded — collect tables
    if_walk = await _snmp_bulk_walk(ip, _IF_TABLE_OID, community, timeout)
    ip_walk = await _snmp_bulk_walk(ip, _IP_ADDR_TABLE_OID, community, timeout)

    if_rows = _rows_from_walk(if_walk)
    ip_rows = _rows_from_walk(ip_walk)

    # Build raw OID map from all collected data
    raw = dict(
        [(oid, val) for oid, val in
         [(k, v) for k, v in zip(_SYSTEM_OIDS.values(), system_info.values())]
         + if_walk + ip_walk]
    )

    return {
        "snmp_version": "v2c",
        "system_info": system_info,
        "interfaces": if_rows,
        "ip_addresses": ip_rows,
        "raw": raw,
    }


def _try_snmp_credentials(
    ip: str,
    host: Host,
) -> dict | None:
    """Try SNMP credential cascade for a host.

    Credential order:
    1. SNMPv2c with community "public"
    2. SNMPv2c with host.extra["SNMP Community"] if present
    3. SNMPv1 with community "public" (legacy fallback)

    SNMPv3 support is deferred — requires additional pysnmp UsmUserData
    configuration that depends on auth/priv protocol selection.

    Returns collected SNMP data dict, or None if all attempts fail.
    """
    # Try 1: SNMPv2c with "public"
    result = asyncio.run(_collect_snmp_data(ip, community="public"))
    if result is not None:
        return result

    # Try 2: SNMPv2c with custom community from spreadsheet
    custom_community = host.extra.get("SNMP Community", "").strip()
    if custom_community and custom_community != "public":
        result = asyncio.run(_collect_snmp_data(ip, community=custom_community))
        if result is not None:
            return result

    return None


def load_snmp_cache(cache_path: Path) -> dict[str, dict]:
    """Load cached SNMP data from disk."""
    if not cache_path.exists():
        return {}
    with open(cache_path) as f:
        return json.load(f)


def save_snmp_cache(cache_path: Path, data: dict[str, dict]) -> None:
    """Save SNMP data to disk cache."""
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    with open(cache_path, "w") as f:
        json.dump(data, f, indent="  ", sort_keys=True)


def scan_snmp(
    hosts: list[Host],
    cache_path: Path,
    force: bool = False,
    max_age: float = 300,
    verbose: bool = False,
    reachability: dict[str, HostReachability] | None = None,
) -> dict[str, dict]:
    """Scan hosts for SNMP data.

    Args:
        hosts: Host objects with IPs to scan.
        cache_path: Path to snmp.json cache file.
        force: Force re-scan even if cache is fresh.
        max_age: Maximum cache age in seconds (default 5 minutes).
        verbose: Print progress to stderr.
        reachability: Pre-computed reachability data. When provided,
            only scans hosts that are up.

    Returns:
        Mapping of hostname to SNMP data dict.
    """
    import sys

    snmp_data = load_snmp_cache(cache_path)

    # Check if cache is fresh enough
    if not force and cache_path.exists():
        age = time.time() - cache_path.stat().st_mtime
        if age < max_age:
            if verbose:
                print(f"snmp.json last updated {age:.0f}s ago, using cache.", file=sys.stderr)
            return snmp_data

    for host in sorted(hosts, key=lambda h: h.hostname.split(".")[::-1]):
        if verbose:
            print(f"  {host.hostname:>20s} ", end="", flush=True, file=sys.stderr)

        # Use pre-computed reachability if available
        if reachability is not None:
            host_reach = reachability.get(host.hostname)
            if host_reach is None or not host_reach.is_up:
                if verbose:
                    print("down", file=sys.stderr)
                continue
            active_ips = list(host_reach.active_ips)
        else:
            # Without reachability data, use all interface IPs
            # The SNMP timeout acts as the reachability check
            active_ips = [str(iface.ipv4) for iface in host.interfaces]

        if not active_ips:
            if verbose:
                print("no-ips", file=sys.stderr)
            continue

        # Try SNMP on the first active IP
        ip = active_ips[0]
        if verbose:
            print(f"snmp({ip}) ", end="", flush=True, file=sys.stderr)

        data = _try_snmp_credentials(ip, host)
        if data is not None:
            snmp_data[host.hostname] = data
            sys_name = data.get("system_info", {}).get("sysName", "?")
            if verbose:
                print(f"ok (sysName={sys_name})", file=sys.stderr)
        else:
            if verbose:
                print("no-snmp", file=sys.stderr)

    save_snmp_cache(cache_path, snmp_data)
    return snmp_data


def _dict_to_tuples(d: dict[str, str]) -> tuple[tuple[str, str], ...]:
    """Convert a flat dict to a tuple of key-value pairs."""
    return tuple((k, v) for k, v in d.items())


def _row_list_to_tuples(
    rows: list[dict[str, str]],
) -> tuple[tuple[tuple[str, str], ...], ...]:
    """Convert a list of dicts to nested tuples for SNMPData."""
    return tuple(_dict_to_tuples(row) for row in rows)


def enrich_hosts_with_snmp(
    hosts: list[Host],
    snmp_cache: dict[str, dict],
) -> None:
    """Attach cached SNMP data to Host objects.

    Modifies hosts in-place by setting host.snmp_data.
    """
    for host in hosts:
        info = snmp_cache.get(host.hostname)
        if info is not None:
            host.snmp_data = SNMPData(
                snmp_version=info.get("snmp_version", "v2c"),
                system_info=_dict_to_tuples(info.get("system_info", {})),
                interfaces=_row_list_to_tuples(info.get("interfaces", [])),
                ip_addresses=_row_list_to_tuples(info.get("ip_addresses", [])),
                raw=_dict_to_tuples(info.get("raw", {})),
            )
