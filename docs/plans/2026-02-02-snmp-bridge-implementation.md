# SNMP Bridge/Network Topology Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a new SNMP supplement that collects switch-level bridge data (MAC address tables, VLAN config, LLDP neighbors, port status) and constraints that validate network topology against the spreadsheet.

**Architecture:** New `supplements/bridge.py` supplement collects bridge-specific SNMP data from managed switches into `.cache/bridge.json`. Shared SNMP infrastructure (pysnmp bulk walk, credential cascade, caching) is extracted to `supplements/snmp_common.py`. A `BridgeData` model on `Host` stores per-switch data. New constraints cross-reference bridge data against the spreadsheet inventory.

**Tech Stack:** pysnmp v7 (async), Q-BRIDGE-MIB, BRIDGE-MIB, LLDP-MIB, IF-MIB, POWER-ETHERNET-MIB

---

### Task 1: Extract shared SNMP infrastructure to snmp_common.py

Extract `_snmp_get_system`, `_snmp_bulk_walk`, and `_try_snmp_credentials` from `supplements/snmp.py` into a shared `supplements/snmp_common.py` module, then update `snmp.py` to import from the shared module.

**Files:**
- Create: `src/gdoc2netcfg/supplements/snmp_common.py`
- Modify: `src/gdoc2netcfg/supplements/snmp.py`
- Create: `tests/test_supplements/test_snmp_common.py`

**Step 1: Write tests for the shared module**

Create `tests/test_supplements/test_snmp_common.py` with tests for `snmp_get_system`, `snmp_bulk_walk`, and `try_snmp_credentials`. These are relocated from the existing `test_snmp.py` credential tests plus new unit tests for the walk/get functions.

```python
"""Tests for shared SNMP infrastructure."""

from unittest.mock import patch

from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface
from gdoc2netcfg.supplements.snmp_common import (
    load_json_cache,
    save_json_cache,
    snmp_bulk_walk,
    snmp_get_system,
    try_snmp_credentials,
)


def _make_host(hostname="switch", ip="10.1.10.1", extra=None):
    return Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=[
            NetworkInterface(
                name=None,
                mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                ipv4=IPv4Address(ip),
                dhcp_name=hostname,
            ),
        ],
        default_ipv4=IPv4Address(ip),
        extra=extra or {},
    )


class TestJSONCache:
    def test_load_missing_returns_empty(self, tmp_path):
        result = load_json_cache(tmp_path / "nonexistent.json")
        assert result == {}

    def test_save_and_load_roundtrip(self, tmp_path):
        cache_path = tmp_path / "cache.json"
        data = {"host1": {"key": "value"}}
        save_json_cache(cache_path, data)
        loaded = load_json_cache(cache_path)
        assert loaded == data

    def test_save_creates_parent_directory(self, tmp_path):
        cache_path = tmp_path / "subdir" / "cache.json"
        save_json_cache(cache_path, {"host": {"k": "v"}})
        assert cache_path.exists()


class TestTrySNMPCredentials:
    @patch("gdoc2netcfg.supplements.snmp_common.asyncio.run")
    def test_public_community_succeeds(self, mock_run):
        mock_run.return_value = {
            "snmp_version": "v2c",
            "system_info": {"sysName": "device"},
        }
        host = _make_host()
        result = try_snmp_credentials("10.1.10.1", host)
        assert result is not None
        assert result["system_info"]["sysName"] == "device"
        assert mock_run.call_count == 1

    @patch("gdoc2netcfg.supplements.snmp_common.asyncio.run")
    def test_fallback_to_custom_community(self, mock_run):
        mock_run.side_effect = [
            None,
            {"snmp_version": "v2c", "system_info": {"sysName": "device"}},
        ]
        host = _make_host(extra={"SNMP Community": "secret"})
        result = try_snmp_credentials("10.1.10.1", host)
        assert result is not None
        assert mock_run.call_count == 2

    @patch("gdoc2netcfg.supplements.snmp_common.asyncio.run")
    def test_all_credentials_fail(self, mock_run):
        mock_run.return_value = None
        host = _make_host()
        result = try_snmp_credentials("10.1.10.1", host)
        assert result is None

    @patch("gdoc2netcfg.supplements.snmp_common.asyncio.run")
    def test_skips_duplicate_community(self, mock_run):
        mock_run.return_value = None
        host = _make_host(extra={"SNMP Community": "public"})
        result = try_snmp_credentials("10.1.10.1", host)
        assert result is None
        assert mock_run.call_count == 1
```

**Step 2: Run tests to verify they fail**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/snmp-bridge-topology && uv run pytest tests/test_supplements/test_snmp_common.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'gdoc2netcfg.supplements.snmp_common'`

**Step 3: Create snmp_common.py**

Create `src/gdoc2netcfg/supplements/snmp_common.py` by extracting these functions from `snmp.py`:
- `_snmp_get_system` → `snmp_get_system` (public)
- `_snmp_bulk_walk` → `snmp_bulk_walk` (public)
- `_try_snmp_credentials` with its `_collect_snmp_data` dependency → `try_snmp_credentials` (public)
- `load_snmp_cache` / `save_snmp_cache` → `load_json_cache` / `save_json_cache` (generic JSON cache, reusable for bridge.json)

The `_collect_snmp_data` function should accept a `table_oids` parameter (list of OIDs to walk) instead of hard-coding `_IF_TABLE_OID` and `_IP_ADDR_TABLE_OID`. This lets `bridge.py` pass different OIDs.

```python
"""Shared SNMP infrastructure for supplements.

Provides pysnmp v7 connection handling, credential cascade, bulk walk,
and JSON cache I/O. Used by both snmp.py (host-level data) and
bridge.py (switch-level topology).

pysnmp v7 is async-only. Individual SNMP operations use async/await,
wrapped in asyncio.run() from synchronous callers.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gdoc2netcfg.models.host import Host

# System group OIDs (SNMPv2-MIB)
SYSTEM_OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
}


async def snmp_get_system(
    ip: str,
    community: str = "public",
    timeout: float = 2.0,
    retries: int = 1,
) -> dict[str, str] | None:
    """Query SNMP system group OIDs via SNMPv2c GET.

    Returns dict of name->value for system group, or None on failure.
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
            ObjectType(ObjectIdentity(oid)) for oid in SYSTEM_OIDS.values()
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

        oid_to_name = {v: k for k, v in SYSTEM_OIDS.items()}
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


async def snmp_bulk_walk(
    ip: str,
    base_oid: str,
    community: str = "public",
    timeout: float = 2.0,
    retries: int = 1,
) -> list[tuple[str, str]]:
    """Bulk walk an SNMP table and return OID->value pairs.

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


async def collect_snmp_tables(
    ip: str,
    community: str = "public",
    timeout: float = 2.0,
    table_oids: dict[str, str] | None = None,
) -> dict | None:
    """Collect SNMP system info and walk specified tables.

    First queries system group. If that fails, returns None (no SNMP).
    Then bulk-walks each table OID.

    Args:
        ip: Host IP address.
        community: SNMP community string.
        timeout: Per-request timeout in seconds.
        table_oids: Mapping of table_name -> base_oid to walk.
            If None, no tables are walked.

    Returns:
        Dict with 'snmp_version', 'system_info', and one key per
        table_oid name containing the walk results. None on failure.
    """
    system_info = await snmp_get_system(ip, community, timeout)
    if system_info is None:
        return None

    result = {
        "snmp_version": "v2c",
        "system_info": system_info,
    }

    for name, oid in (table_oids or {}).items():
        result[name] = await snmp_bulk_walk(ip, oid, community, timeout)

    return result


def try_snmp_credentials(
    ip: str,
    host: Host,
    table_oids: dict[str, str] | None = None,
) -> dict | None:
    """Try SNMP credential cascade for a host.

    Credential order:
    1. SNMPv2c with community "public"
    2. SNMPv2c with host.extra["SNMP Community"] if present and different

    Returns collected SNMP data dict, or None if all attempts fail.
    """
    result = asyncio.run(collect_snmp_tables(ip, community="public", table_oids=table_oids))
    if result is not None:
        return result

    custom_community = host.extra.get("SNMP Community", "").strip()
    if custom_community and custom_community != "public":
        result = asyncio.run(collect_snmp_tables(ip, community=custom_community, table_oids=table_oids))
        if result is not None:
            return result

    return None


def load_json_cache(cache_path: Path) -> dict[str, dict]:
    """Load cached JSON data from disk."""
    if not cache_path.exists():
        return {}
    with open(cache_path) as f:
        return json.load(f)


def save_json_cache(cache_path: Path, data: dict[str, dict]) -> None:
    """Save JSON data to disk cache."""
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    with open(cache_path, "w") as f:
        json.dump(data, f, indent="  ", sort_keys=True)
```

**Step 4: Update snmp.py to import from snmp_common**

Modify `src/gdoc2netcfg/supplements/snmp.py`:
- Remove the duplicated functions (`_snmp_get_system`, `_snmp_bulk_walk`, `_collect_snmp_data`, `_try_snmp_credentials`, `load_snmp_cache`, `save_snmp_cache`)
- Import from `snmp_common` instead
- Keep `_rows_from_walk`, `_dict_to_tuples`, `_row_list_to_tuples`, `enrich_hosts_with_snmp`, `scan_snmp` — these are snmp-supplement-specific
- Update `scan_snmp` to use `snmp_common.try_snmp_credentials` and `snmp_common.load_json_cache` / `snmp_common.save_json_cache`
- Keep the module's host-specific table OIDs (`_IF_TABLE_OID`, `_IP_ADDR_TABLE_OID`) and pass them via `table_oids`

**Step 5: Run all tests to verify nothing broke**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/snmp-bridge-topology && uv run pytest tests/test_supplements/test_snmp_common.py tests/test_supplements/test_snmp.py -v`
Expected: All tests PASS. The existing `test_snmp.py` tests still work because `scan_snmp` and `enrich_hosts_with_snmp` have the same public API.

**Step 6: Run full test suite**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/snmp-bridge-topology && uv run pytest`
Expected: 565+ tests pass (new tests added).

**Step 7: Commit**

```bash
cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/snmp-bridge-topology
git add src/gdoc2netcfg/supplements/snmp_common.py src/gdoc2netcfg/supplements/snmp.py tests/test_supplements/test_snmp_common.py
git commit -m "Extract shared SNMP infrastructure to snmp_common.py

Move pysnmp connection handling, credential cascade, bulk walk, and
JSON cache I/O to a shared module. snmp.py now imports from
snmp_common instead of duplicating this code. Prepares for bridge.py
supplement which needs the same SNMP infrastructure."
```

---

### Task 2: Add BridgeData model to host.py

Add a `BridgeData` dataclass to `models/host.py` and a `bridge_data` field to `Host`. This stores the parsed bridge data per switch host.

**Files:**
- Modify: `src/gdoc2netcfg/models/host.py:62-113`
- Create: `tests/test_models/test_bridge_data.py`

**Step 1: Write tests for BridgeData**

```python
"""Tests for BridgeData model."""

from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import BridgeData, Host, NetworkInterface


class TestBridgeData:
    def test_frozen(self):
        data = BridgeData(
            mac_table=(("AA:BB:CC:DD:EE:FF", 5, 3, "1/g3"),),
            vlan_names=((1, "Default"), (5, "net")),
            port_pvids=((1, 31), (2, 31)),
        )
        try:
            data.mac_table = ()
            assert False, "Should have raised FrozenInstanceError"
        except AttributeError:
            pass

    def test_empty_defaults(self):
        data = BridgeData()
        assert data.mac_table == ()
        assert data.vlan_names == ()
        assert data.port_pvids == ()
        assert data.port_names == ()
        assert data.port_status == ()
        assert data.lldp_neighbors == ()

    def test_host_bridge_data_default_none(self):
        host = Host(
            machine_name="sw",
            hostname="sw",
            interfaces=[
                NetworkInterface(
                    name=None,
                    mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                    ipv4=IPv4Address("10.1.5.10"),
                ),
            ],
        )
        assert host.bridge_data is None
```

**Step 2: Run test to verify it fails**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/snmp-bridge-topology && uv run pytest tests/test_models/test_bridge_data.py -v`
Expected: FAIL — `ImportError: cannot import name 'BridgeData' from 'gdoc2netcfg.models.host'`

**Step 3: Add BridgeData to host.py**

Add after the `SNMPData` class (after line 82), before `Host`:

```python
@dataclass(frozen=True)
class BridgeData:
    """Switch bridge/topology data collected via SNMP.

    Populated by the bridge supplement for managed switches.
    Contains MAC address table, VLAN configuration, LLDP neighbors,
    and port status. All fields use immutable types.

    Attributes:
        mac_table: (mac_str, vlan_id, bridge_port, port_name) tuples.
        vlan_names: (vlan_id, name) tuples from dot1qVlanStaticName.
        port_pvids: (ifIndex, pvid) tuples from dot1qPvid.
        port_names: (ifIndex, name) tuples from ifName.
        port_status: (ifIndex, oper_status, speed_mbps) tuples.
        lldp_neighbors: (local_ifIndex, remote_sysname, remote_port_id,
            remote_chassis_mac) tuples.
        vlan_egress_ports: (vlan_id, port_bitmap_hex) tuples for tagged membership.
        vlan_untagged_ports: (vlan_id, port_bitmap_hex) tuples for untagged membership.
        poe_status: (ifIndex, admin_status, detection_status) tuples.
    """

    mac_table: tuple[tuple[str, int, int, str], ...] = ()
    vlan_names: tuple[tuple[int, str], ...] = ()
    port_pvids: tuple[tuple[int, int], ...] = ()
    port_names: tuple[tuple[int, str], ...] = ()
    port_status: tuple[tuple[int, int, int], ...] = ()
    lldp_neighbors: tuple[tuple[int, str, str, str], ...] = ()
    vlan_egress_ports: tuple[tuple[int, str], ...] = ()
    vlan_untagged_ports: tuple[tuple[int, str], ...] = ()
    poe_status: tuple[tuple[int, int, int], ...] = ()
```

Add to `Host` class after `snmp_data` field (line 113):

```python
    bridge_data: BridgeData | None = None
```

**Step 4: Run test to verify it passes**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/snmp-bridge-topology && uv run pytest tests/test_models/test_bridge_data.py -v`
Expected: PASS

**Step 5: Run full test suite**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/snmp-bridge-topology && uv run pytest`
Expected: All tests pass.

**Step 6: Commit**

```bash
cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/snmp-bridge-topology
git add src/gdoc2netcfg/models/host.py tests/test_models/test_bridge_data.py
git commit -m "Add BridgeData model for switch topology data

Frozen dataclass storing MAC address table, VLAN config, LLDP
neighbors, port status, and PoE data collected from managed switches
via SNMP bridge supplement."
```

---

### Task 3: Create bridge supplement with OID definitions and parsing

Create `supplements/bridge.py` with bridge-specific OID constants, raw SNMP walk result parsing functions, and the scan/enrich pipeline.

**Files:**
- Create: `src/gdoc2netcfg/supplements/bridge.py`
- Create: `tests/test_supplements/test_bridge.py`

**Step 1: Write tests for OID parsing functions**

The key parsing challenge is `dot1qTpFdbTable` where the OID encodes VLAN ID and MAC address:
`.1.3.6.1.2.1.17.7.1.2.2.1.2.<VLAN>.<M1>.<M2>.<M3>.<M4>.<M5>.<M6> = INTEGER: <bridge_port>`

```python
"""Tests for the bridge SNMP supplement."""

import json
from unittest.mock import patch

from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import BridgeData, Host, NetworkInterface
from gdoc2netcfg.supplements.bridge import (
    enrich_hosts_with_bridge_data,
    parse_bridge_port_map,
    parse_if_names,
    parse_lldp_neighbors,
    parse_mac_table,
    parse_port_pvids,
    parse_port_status,
    parse_vlan_names,
    scan_bridge,
)
from gdoc2netcfg.supplements.reachability import HostReachability
from gdoc2netcfg.supplements.snmp_common import save_json_cache


def _make_switch(hostname="sw-test", ip="10.1.5.10"):
    return Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=[
            NetworkInterface(
                name="manage",
                mac=MACAddress.parse("08:bd:43:6b:b8:d8"),
                ipv4=IPv4Address(ip),
                dhcp_name=hostname,
            ),
        ],
        default_ipv4=IPv4Address(ip),
        hardware_type="netgear-switch",
        extra={},
    )


class TestParseMacTable:
    """Parse dot1qTpFdbTable walk results into (mac, vlan, port, name) tuples."""

    def test_parses_mac_vlan_port(self):
        # OID: .1.3.6.1.2.1.17.7.1.2.2.1.2.<VLAN>.<M1>.<M2>.<M3>.<M4>.<M5>.<M6>
        walk = [
            ("1.3.6.1.2.1.17.7.1.2.2.1.2.5.8.189.67.107.184.216", "313"),
            ("1.3.6.1.2.1.17.7.1.2.2.1.2.31.228.95.1.141.247.23", "3"),
        ]
        bridge_to_if = {313: 313, 3: 3}
        if_names = {313: "CPU Interface:  0/5/1", 3: "1/g3"}
        result = parse_mac_table(walk, bridge_to_if, if_names)
        assert len(result) == 2
        assert result[0] == ("08:BD:43:6B:B8:D8", 5, 313, "CPU Interface:  0/5/1")
        assert result[1] == ("E4:5F:01:8D:F7:17", 31, 3, "1/g3")

    def test_empty_walk(self):
        assert parse_mac_table([], {}, {}) == []

    def test_unknown_bridge_port(self):
        walk = [
            ("1.3.6.1.2.1.17.7.1.2.2.1.2.5.170.187.204.221.238.255", "99"),
        ]
        result = parse_mac_table(walk, {}, {})
        assert len(result) == 1
        assert result[0] == ("AA:BB:CC:DD:EE:FF", 5, 99, "port99")


class TestParseIfNames:
    def test_parses_if_names(self):
        walk = [
            ("1.3.6.1.2.1.31.1.1.1.1.1", "1/g1"),
            ("1.3.6.1.2.1.31.1.1.1.1.49", "1/xg49"),
        ]
        result = parse_if_names(walk)
        assert result == {1: "1/g1", 49: "1/xg49"}

    def test_empty(self):
        assert parse_if_names([]) == {}


class TestParseBridgePortMap:
    def test_parses_mapping(self):
        walk = [
            ("1.3.6.1.2.1.17.1.4.1.2.1", "1"),
            ("1.3.6.1.2.1.17.1.4.1.2.50", "50"),
            ("1.3.6.1.2.1.17.1.4.1.2.314", "314"),
        ]
        result = parse_bridge_port_map(walk)
        assert result == {1: 1, 50: 50, 314: 314}


class TestParseVlanNames:
    def test_parses_names(self):
        walk = [
            ("1.3.6.1.2.1.17.7.1.4.3.1.1.1", "Default"),
            ("1.3.6.1.2.1.17.7.1.4.3.1.1.5", "net"),
            ("1.3.6.1.2.1.17.7.1.4.3.1.1.10", "int"),
        ]
        result = parse_vlan_names(walk)
        assert result == [(1, "Default"), (5, "net"), (10, "int")]


class TestParsePortPvids:
    def test_parses_pvids(self):
        walk = [
            ("1.3.6.1.2.1.17.7.1.4.5.1.1.1", "31"),
            ("1.3.6.1.2.1.17.7.1.4.5.1.1.40", "5"),
        ]
        result = parse_port_pvids(walk)
        assert result == [(1, 31), (40, 5)]


class TestParsePortStatus:
    def test_parses_status_and_speed(self):
        oper_walk = [
            ("1.3.6.1.2.1.2.2.1.8.1", "2"),   # down
            ("1.3.6.1.2.1.2.2.1.8.3", "1"),   # up
        ]
        speed_walk = [
            ("1.3.6.1.2.1.31.1.1.1.15.1", "0"),
            ("1.3.6.1.2.1.31.1.1.1.15.3", "1000"),
        ]
        result = parse_port_status(oper_walk, speed_walk)
        assert (1, 2, 0) in result
        assert (3, 1, 1000) in result


class TestParseLldpNeighbors:
    def test_parses_neighbors(self):
        walk = [
            # lldpRemChassisIdSubtype (OID .4)
            ("1.0.8802.1.1.2.1.4.1.1.4.97.50.1", "4"),
            # lldpRemChassisId (OID .5) - hex MAC
            ("1.0.8802.1.1.2.1.4.1.1.5.97.50.1", "0xc80084897170"),
            # lldpRemPortId (OID .7)
            ("1.0.8802.1.1.2.1.4.1.1.7.97.50.1", "gi24"),
            # lldpRemSysName (OID .9)
            ("1.0.8802.1.1.2.1.4.1.1.9.97.50.1", "sw-cisco-shed"),
        ]
        result = parse_lldp_neighbors(walk)
        assert len(result) == 1
        assert result[0] == (50, "sw-cisco-shed", "gi24", "C8:00:84:89:71:70")


class TestEnrichHostsWithBridgeData:
    def test_enriches_switch_hosts(self):
        host = _make_switch()
        cache = {
            "sw-test": {
                "mac_table": [["AA:BB:CC:DD:EE:FF", 5, 3, "1/g3"]],
                "vlan_names": [[1, "Default"], [5, "net"]],
                "port_pvids": [[1, 31]],
                "port_names": [[1, "1/g1"]],
                "port_status": [[1, 2, 0]],
                "lldp_neighbors": [],
                "vlan_egress_ports": [],
                "vlan_untagged_ports": [],
                "poe_status": [],
            }
        }
        enrich_hosts_with_bridge_data([host], cache)
        assert host.bridge_data is not None
        assert len(host.bridge_data.mac_table) == 1
        assert host.bridge_data.mac_table[0] == ("AA:BB:CC:DD:EE:FF", 5, 3, "1/g3")

    def test_no_data_for_host(self):
        host = _make_switch()
        enrich_hosts_with_bridge_data([host], {})
        assert host.bridge_data is None


class TestScanBridge:
    @patch("gdoc2netcfg.supplements.bridge._collect_bridge_data")
    def test_scan_collects_from_switch(self, mock_collect, tmp_path):
        mock_collect.return_value = {
            "mac_table": [["AA:BB:CC:DD:EE:FF", 5, 3, "1/g3"]],
            "vlan_names": [[5, "net"]],
            "port_pvids": [],
            "port_names": [],
            "port_status": [],
            "lldp_neighbors": [],
            "vlan_egress_ports": [],
            "vlan_untagged_ports": [],
            "poe_status": [],
        }
        host = _make_switch()
        cache_path = tmp_path / "bridge.json"
        reachability = {
            "sw-test": HostReachability(hostname="sw-test", active_ips=("10.1.5.10",)),
        }
        result = scan_bridge([host], cache_path, force=True, reachability=reachability)
        assert "sw-test" in result
        mock_collect.assert_called_once()

    @patch("gdoc2netcfg.supplements.bridge._collect_bridge_data")
    def test_scan_skips_non_switches(self, mock_collect, tmp_path):
        host = Host(
            machine_name="desktop",
            hostname="desktop",
            interfaces=[
                NetworkInterface(
                    name=None,
                    mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                    ipv4=IPv4Address("10.1.10.5"),
                ),
            ],
            hardware_type=None,
        )
        cache_path = tmp_path / "bridge.json"
        reachability = {
            "desktop": HostReachability(hostname="desktop", active_ips=("10.1.10.5",)),
        }
        result = scan_bridge([host], cache_path, force=True, reachability=reachability)
        assert result == {}
        mock_collect.assert_not_called()

    @patch("gdoc2netcfg.supplements.bridge._collect_bridge_data")
    def test_scan_skips_unreachable(self, mock_collect, tmp_path):
        host = _make_switch()
        cache_path = tmp_path / "bridge.json"
        reachability = {
            "sw-test": HostReachability(hostname="sw-test", active_ips=()),
        }
        result = scan_bridge([host], cache_path, force=True, reachability=reachability)
        assert result == {}
        mock_collect.assert_not_called()

    @patch("gdoc2netcfg.supplements.bridge._collect_bridge_data")
    def test_scan_uses_cache_when_fresh(self, mock_collect, tmp_path):
        cache_path = tmp_path / "bridge.json"
        existing = {
            "sw-test": {
                "mac_table": [], "vlan_names": [], "port_pvids": [],
                "port_names": [], "port_status": [], "lldp_neighbors": [],
                "vlan_egress_ports": [], "vlan_untagged_ports": [], "poe_status": [],
            }
        }
        save_json_cache(cache_path, existing)
        host = _make_switch()
        result = scan_bridge([host], cache_path, force=False, max_age=9999)
        assert result == existing
        mock_collect.assert_not_called()
```

**Step 2: Run tests to verify they fail**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/snmp-bridge-topology && uv run pytest tests/test_supplements/test_bridge.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'gdoc2netcfg.supplements.bridge'`

**Step 3: Implement bridge.py**

Create `src/gdoc2netcfg/supplements/bridge.py`. This file should contain:

- Bridge-specific OID constants (Q-BRIDGE-MIB, BRIDGE-MIB, LLDP-MIB, IF-MIB, PoE-MIB)
- Parsing functions for each table's walk results
- `_collect_bridge_data()` that calls `snmp_common.try_snmp_credentials` with bridge OIDs and parses results
- `scan_bridge()` that iterates switch hosts, checks reachability, collects data, caches it
- `enrich_hosts_with_bridge_data()` that attaches `BridgeData` to `Host` objects

The parsing functions extract structured data from raw SNMP walk results:
- `parse_mac_table()`: Parse dot1qTpFdbTable OIDs to extract (MAC, VLAN, port, port_name)
- `parse_if_names()`: Parse ifName to get ifIndex→name mapping
- `parse_bridge_port_map()`: Parse dot1dBasePortIfIndex for bridge port→ifIndex
- `parse_vlan_names()`: Parse dot1qVlanStaticName
- `parse_port_pvids()`: Parse dot1qPvid
- `parse_port_status()`: Combine ifOperStatus and ifHighSpeed
- `parse_lldp_neighbors()`: Parse lldpRemTable subfields

The `_collect_bridge_data()` function should:
1. Call `snmp_common.try_snmp_credentials()` with all bridge table OIDs
2. If successful, parse each table using the parsing functions
3. Return a JSON-serialisable dict

The `scan_bridge()` function should:
1. Only target hosts where `hardware_type` is `HARDWARE_NETGEAR_SWITCH` (or hosts with existing `snmp_data`, meaning they responded to SNMP)
2. Follow the same cache/reachability/force pattern as `scan_snmp()`

**Step 4: Run tests to verify they pass**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/snmp-bridge-topology && uv run pytest tests/test_supplements/test_bridge.py -v`
Expected: All PASS

**Step 5: Run full test suite**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/snmp-bridge-topology && uv run pytest`
Expected: All tests pass.

**Step 6: Commit**

```bash
cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/snmp-bridge-topology
git add src/gdoc2netcfg/supplements/bridge.py tests/test_supplements/test_bridge.py
git commit -m "Add bridge supplement for switch topology data collection

Collects MAC address tables, VLAN config, LLDP neighbors, port
status, and PoE data from managed switches via Q-BRIDGE-MIB,
BRIDGE-MIB, LLDP-MIB, and IF-MIB. Caches in bridge.json.
Parses raw SNMP walk results into structured BridgeData model."
```

---

### Task 4: Wire bridge supplement into CLI

Add a `bridge` subcommand to the CLI and load bridge cache in `_build_pipeline()`.

**Files:**
- Modify: `src/gdoc2netcfg/cli/main.py:93-147` (pipeline), `main:536-618` (CLI)

**Step 1: Write test for CLI integration**

Since the CLI tests are integration-level, verify by checking the subcommand exists and `_build_pipeline` loads bridge cache.

```python
# Add to a new file or inline verification:
# The test is: run `uv run gdoc2netcfg bridge --help` and verify it shows help text.
```

**Step 2: Add bridge cache loading to _build_pipeline()**

In `_build_pipeline()` (after line 142 where SNMP enrichment happens), add:

```python
    # Load bridge cache and enrich (don't scan — that's a separate subcommand)
    bridge_cache_path = Path(config.cache.directory) / "bridge.json"
    bridge_cache = load_json_cache(bridge_cache_path)
    enrich_hosts_with_bridge_data(hosts, bridge_cache)
```

Add imports at the top of `_build_pipeline`:
```python
    from gdoc2netcfg.supplements.bridge import enrich_hosts_with_bridge_data
    from gdoc2netcfg.supplements.snmp_common import load_json_cache
```

**Step 3: Add cmd_bridge() subcommand**

Follow the same pattern as `cmd_snmp()` (lines 475-529). The bridge subcommand should:
1. Build minimal pipeline (parse CSV, build hosts)
2. Run reachability check
3. Call `scan_bridge()` with reachability
4. Enrich hosts
5. Report results

```python
def cmd_bridge(args: argparse.Namespace) -> int:
    """Scan switches for bridge/topology data."""
    config = _load_config(args)

    from gdoc2netcfg.derivations.host_builder import build_hosts
    from gdoc2netcfg.sources.parser import parse_csv
    from gdoc2netcfg.supplements.bridge import (
        enrich_hosts_with_bridge_data,
        scan_bridge,
    )
    from gdoc2netcfg.supplements.reachability import check_all_hosts_reachability
    from gdoc2netcfg.supplements.snmp_common import load_json_cache

    csv_data = _fetch_or_load_csvs(config, use_cache=True)
    _enrich_site_from_vlan_sheet(config, csv_data)
    all_records = []
    for name, csv_text in csv_data:
        if name == "vlan_allocations":
            continue
        records = parse_csv(csv_text, name)
        all_records.extend(records)

    hosts = build_hosts(all_records, config.site)

    print("Checking host reachability...", file=sys.stderr)
    reachability = check_all_hosts_reachability(hosts, verbose=True)

    cache_path = Path(config.cache.directory) / "bridge.json"
    print("\nScanning bridge data...", file=sys.stderr)
    bridge_data = scan_bridge(
        hosts,
        cache_path=cache_path,
        force=args.force,
        verbose=True,
        reachability=reachability,
    )

    enrich_hosts_with_bridge_data(hosts, bridge_data)

    # Report
    switches_with_data = sum(1 for h in hosts if h.bridge_data is not None)
    total_macs = sum(
        len(h.bridge_data.mac_table) for h in hosts if h.bridge_data is not None
    )
    print(f"\nBridge data for {switches_with_data} switches "
          f"({total_macs} MAC table entries).")

    return 0
```

**Step 4: Register the subparser**

After the snmp subparser registration (around line 596), add:

```python
    # bridge
    bridge_parser = subparsers.add_parser("bridge", help="Scan switches for bridge/topology data")
    bridge_parser.add_argument(
        "--force", action="store_true",
        help="Force re-scan even if cache is fresh",
    )
```

Add `"bridge": cmd_bridge` to the `commands` dict (around line 611).

**Step 5: Run full test suite**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/snmp-bridge-topology && uv run pytest`
Expected: All tests pass.

**Step 6: Verify CLI works**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/snmp-bridge-topology && uv run gdoc2netcfg bridge --help`
Expected: Shows bridge subcommand help.

**Step 7: Commit**

```bash
cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/snmp-bridge-topology
git add src/gdoc2netcfg/cli/main.py
git commit -m "Wire bridge supplement into CLI and pipeline

Add 'bridge' subcommand for switch topology scanning. Load bridge
cache during _build_pipeline() so generators and constraints can
access bridge data."
```

---

### Task 5: Add VLAN name consistency constraint

First validation constraint: compare VLAN names on switches against the VLAN Allocations spreadsheet.

**Files:**
- Create: `src/gdoc2netcfg/constraints/bridge_validation.py`
- Create: `tests/test_constraints/test_bridge_validation.py`

**Step 1: Write tests**

```python
"""Tests for bridge/topology validation constraints."""

from gdoc2netcfg.constraints.bridge_validation import validate_vlan_names
from gdoc2netcfg.constraints.errors import Severity
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import BridgeData, Host, NetworkInterface
from gdoc2netcfg.models.network import Site, VLAN


def _make_site_with_vlans():
    return Site(
        name="test",
        domain="test.example.com",
        vlans={
            1: VLAN(id=1, name="tmp", subdomain="tmp", third_octets=(1,)),
            5: VLAN(id=5, name="net", subdomain="net", third_octets=(5,)),
            10: VLAN(id=10, name="int", subdomain="int", third_octets=(10,)),
        },
    )


def _make_switch_with_bridge(hostname, vlan_names):
    host = Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=[
            NetworkInterface(
                name="manage",
                mac=MACAddress.parse("08:bd:43:6b:b8:d8"),
                ipv4=IPv4Address("10.1.5.11"),
            ),
        ],
        hardware_type="netgear-switch",
        bridge_data=BridgeData(
            vlan_names=tuple(vlan_names),
        ),
    )
    return host


class TestValidateVlanNames:
    def test_matching_names_no_violations(self):
        site = _make_site_with_vlans()
        host = _make_switch_with_bridge("sw-test", [(5, "net"), (10, "int")])
        result = validate_vlan_names([host], site)
        assert result.is_valid

    def test_mismatched_name_produces_warning(self):
        site = _make_site_with_vlans()
        host = _make_switch_with_bridge("sw-test", [(5, "wrong-name")])
        result = validate_vlan_names([host], site)
        assert len(result.warnings) == 1
        assert "wrong-name" in result.warnings[0].message
        assert "net" in result.warnings[0].message

    def test_unknown_vlan_on_switch_produces_warning(self):
        site = _make_site_with_vlans()
        host = _make_switch_with_bridge("sw-test", [(4089, "Auto-Video")])
        result = validate_vlan_names([host], site)
        assert len(result.warnings) == 1
        assert "4089" in result.warnings[0].message

    def test_skips_hosts_without_bridge_data(self):
        site = _make_site_with_vlans()
        host = Host(
            machine_name="desktop",
            hostname="desktop",
            interfaces=[
                NetworkInterface(
                    name=None,
                    mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                    ipv4=IPv4Address("10.1.10.5"),
                ),
            ],
        )
        result = validate_vlan_names([host], site)
        assert result.is_valid

    def test_default_vlan_1_name_ignored(self):
        """VLAN 1 named 'Default' on switch but 'tmp' in spreadsheet is OK."""
        site = _make_site_with_vlans()
        host = _make_switch_with_bridge("sw-test", [(1, "Default")])
        result = validate_vlan_names([host], site)
        assert result.is_valid
```

**Step 2: Run tests to verify they fail**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/snmp-bridge-topology && uv run pytest tests/test_constraints/test_bridge_validation.py -v`
Expected: FAIL — `ModuleNotFoundError`

**Step 3: Implement validate_vlan_names**

```python
"""Bridge/topology validation constraints.

Validates switch bridge data (MAC tables, VLAN config, LLDP neighbors)
against the spreadsheet inventory.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from gdoc2netcfg.constraints.errors import (
    ConstraintViolation,
    Severity,
    ValidationResult,
)

if TYPE_CHECKING:
    from gdoc2netcfg.models.host import Host
    from gdoc2netcfg.models.network import Site


def validate_vlan_names(
    hosts: list[Host],
    site: Site,
) -> ValidationResult:
    """Validate VLAN names on switches match the VLAN Allocations spreadsheet.

    For each switch with bridge_data, compares dot1qVlanStaticName entries
    against site.vlans. Reports:
    - Name mismatches (switch says "foo", spreadsheet says "bar")
    - Unknown VLANs on switch (not in spreadsheet)

    VLAN 1 named "Default" is always accepted (standard switch default).
    """
    result = ValidationResult()

    for host in hosts:
        if host.bridge_data is None:
            continue

        for vlan_id, switch_name in host.bridge_data.vlan_names:
            # VLAN 1 "Default" is standard and always acceptable
            if vlan_id == 1 and switch_name == "Default":
                continue

            spreadsheet_vlan = site.vlans.get(vlan_id)
            if spreadsheet_vlan is None:
                result.add(ConstraintViolation(
                    severity=Severity.WARNING,
                    code="bridge_unknown_vlan",
                    message=(
                        f"VLAN {vlan_id} ({switch_name!r}) exists on switch "
                        f"but is not in VLAN Allocations spreadsheet"
                    ),
                    record_id=host.hostname,
                    field="bridge_data.vlan_names",
                ))
            elif spreadsheet_vlan.name != switch_name:
                result.add(ConstraintViolation(
                    severity=Severity.WARNING,
                    code="bridge_vlan_name_mismatch",
                    message=(
                        f"VLAN {vlan_id} named {switch_name!r} on switch "
                        f"but {spreadsheet_vlan.name!r} in spreadsheet"
                    ),
                    record_id=host.hostname,
                    field="bridge_data.vlan_names",
                ))

    return result
```

**Step 4: Run tests**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/snmp-bridge-topology && uv run pytest tests/test_constraints/test_bridge_validation.py -v`
Expected: PASS

**Step 5: Run full test suite**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/snmp-bridge-topology && uv run pytest`
Expected: All pass.

**Step 6: Commit**

```bash
cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/snmp-bridge-topology
git add src/gdoc2netcfg/constraints/bridge_validation.py tests/test_constraints/test_bridge_validation.py
git commit -m "Add VLAN name consistency constraint for bridge data

Compares switch VLAN names from dot1qVlanStaticName against the
VLAN Allocations spreadsheet. Reports mismatched names and
unknown VLANs as warnings."
```

---

### Task 6: Add MAC connectivity discovery constraint

Cross-reference the switch MAC address table against known spreadsheet MACs.

**Files:**
- Modify: `src/gdoc2netcfg/constraints/bridge_validation.py`
- Modify: `tests/test_constraints/test_bridge_validation.py`

**Step 1: Write tests**

Add to `tests/test_constraints/test_bridge_validation.py`:

```python
from gdoc2netcfg.constraints.bridge_validation import validate_mac_connectivity
from gdoc2netcfg.models.host import NetworkInventory


def _make_inventory_with_switch(switch_host, other_hosts, site):
    all_hosts = [switch_host] + other_hosts
    return NetworkInventory(
        site=site,
        hosts=all_hosts,
        ip_to_hostname={},
        ip_to_macs={},
    )


class TestValidateMacConnectivity:
    def test_known_mac_on_switch_no_violation(self):
        site = _make_site_with_vlans()
        desktop = Host(
            machine_name="desktop",
            hostname="desktop",
            interfaces=[
                NetworkInterface(
                    name=None,
                    mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                    ipv4=IPv4Address("10.1.10.5"),
                    vlan_id=10,
                ),
            ],
        )
        switch = _make_switch_with_bridge("sw-test", [])
        switch.bridge_data = BridgeData(
            mac_table=(("AA:BB:CC:DD:EE:FF", 10, 3, "1/g3"),),
        )
        inventory = _make_inventory_with_switch(switch, [desktop], site)
        result = validate_mac_connectivity(inventory)
        assert result.is_valid

    def test_unknown_mac_produces_warning(self):
        site = _make_site_with_vlans()
        switch = _make_switch_with_bridge("sw-test", [])
        switch.bridge_data = BridgeData(
            mac_table=(("FF:FF:FF:00:00:01", 5, 3, "1/g3"),),
        )
        inventory = _make_inventory_with_switch(switch, [], site)
        result = validate_mac_connectivity(inventory)
        assert len(result.warnings) == 1
        assert "FF:FF:FF:00:00:01" in result.warnings[0].message
        assert "unknown" in result.warnings[0].code

    def test_locally_administered_macs_skipped(self):
        """BA:BE:xx MACs (bit 1 of first octet set) are locally administered."""
        site = _make_site_with_vlans()
        switch = _make_switch_with_bridge("sw-test", [])
        switch.bridge_data = BridgeData(
            mac_table=(("BA:BE:12:34:56:78", 5, 50, "1/xg50"),),
        )
        inventory = _make_inventory_with_switch(switch, [], site)
        result = validate_mac_connectivity(inventory)
        assert result.is_valid  # Locally administered MACs are expected noise

    def test_switch_own_mac_skipped(self):
        """Switch's own management MAC should not be flagged."""
        site = _make_site_with_vlans()
        switch = _make_switch_with_bridge("sw-test", [])
        switch.bridge_data = BridgeData(
            mac_table=(("08:BD:43:6B:B8:D8", 5, 313, "CPU Interface:  0/5/1"),),
        )
        inventory = _make_inventory_with_switch(switch, [], site)
        result = validate_mac_connectivity(inventory)
        assert result.is_valid
```

**Step 2: Run tests to verify they fail**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/snmp-bridge-topology && uv run pytest tests/test_constraints/test_bridge_validation.py::TestValidateMacConnectivity -v`
Expected: FAIL — `ImportError`

**Step 3: Implement validate_mac_connectivity**

Add to `src/gdoc2netcfg/constraints/bridge_validation.py`:

```python
def _is_locally_administered(mac: str) -> bool:
    """Check if a MAC address is locally administered (LAA).

    Locally administered MACs have bit 1 of the first octet set.
    These are used by containers, VMs, and virtual interfaces.
    """
    first_octet = int(mac.split(":")[0], 16)
    return bool(first_octet & 0x02)


def validate_mac_connectivity(
    inventory: NetworkInventory,
) -> ValidationResult:
    """Cross-reference switch MAC tables with known spreadsheet MACs.

    Reports unknown MACs seen on switches (not matching any host in
    the inventory). Skips locally-administered MACs (containers/VMs)
    and switch management MACs.
    """
    result = ValidationResult()

    # Build set of all known MACs from inventory
    known_macs: set[str] = set()
    for host in inventory.hosts:
        for mac in host.all_macs:
            known_macs.add(str(mac).upper())

    for host in inventory.hosts:
        if host.bridge_data is None:
            continue

        for mac_str, vlan_id, bridge_port, port_name in host.bridge_data.mac_table:
            mac_upper = mac_str.upper()

            # Skip locally administered MACs (containers, VMs)
            if _is_locally_administered(mac_upper):
                continue

            # Skip known MACs
            if mac_upper in known_macs:
                continue

            result.add(ConstraintViolation(
                severity=Severity.WARNING,
                code="bridge_unknown_mac",
                message=(
                    f"Unknown MAC {mac_upper} seen on {host.hostname} "
                    f"port {port_name} VLAN {vlan_id}"
                ),
                record_id=host.hostname,
                field="bridge_data.mac_table",
            ))

    return result
```

**Step 4: Run tests**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/snmp-bridge-topology && uv run pytest tests/test_constraints/test_bridge_validation.py -v`
Expected: All PASS

**Step 5: Run full suite and commit**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/snmp-bridge-topology && uv run pytest`

```bash
cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/snmp-bridge-topology
git add src/gdoc2netcfg/constraints/bridge_validation.py tests/test_constraints/test_bridge_validation.py
git commit -m "Add MAC connectivity discovery constraint

Cross-references switch MAC address tables with known spreadsheet
MACs. Reports unknown MACs as warnings. Skips locally-administered
addresses (containers/VMs) and switch management MACs."
```

---

### Task 7: Add LLDP topology validation constraint

Validate LLDP neighbor data against known switch hostnames.

**Files:**
- Modify: `src/gdoc2netcfg/constraints/bridge_validation.py`
- Modify: `tests/test_constraints/test_bridge_validation.py`

**Step 1: Write tests**

```python
from gdoc2netcfg.constraints.bridge_validation import validate_lldp_topology


class TestValidateLldpTopology:
    def test_known_neighbor_no_violation(self):
        site = _make_site_with_vlans()
        neighbor_switch = Host(
            machine_name="sw-cisco-shed",
            hostname="sw-cisco-shed",
            interfaces=[
                NetworkInterface(
                    name="manage",
                    mac=MACAddress.parse("c8:00:84:89:71:70"),
                    ipv4=IPv4Address("10.1.5.35"),
                ),
            ],
            hardware_type="netgear-switch",
        )
        switch = _make_switch_with_bridge("sw-test", [])
        switch.bridge_data = BridgeData(
            lldp_neighbors=((50, "sw-cisco-shed", "gi24", "C8:00:84:89:71:70"),),
        )
        inventory = _make_inventory_with_switch(switch, [neighbor_switch], site)
        result = validate_lldp_topology(inventory)
        assert result.is_valid

    def test_unknown_lldp_neighbor_produces_warning(self):
        site = _make_site_with_vlans()
        switch = _make_switch_with_bridge("sw-test", [])
        switch.bridge_data = BridgeData(
            lldp_neighbors=((50, "unknown-device", "eth0", "AA:BB:CC:DD:EE:FF"),),
        )
        inventory = _make_inventory_with_switch(switch, [], site)
        result = validate_lldp_topology(inventory)
        # Unknown LLDP neighbor is informational, not necessarily bad
        assert len(result.warnings) == 1
        assert "unknown-device" in result.warnings[0].message

    def test_no_lldp_data_no_violations(self):
        site = _make_site_with_vlans()
        switch = _make_switch_with_bridge("sw-test", [])
        switch.bridge_data = BridgeData()
        inventory = _make_inventory_with_switch(switch, [], site)
        result = validate_lldp_topology(inventory)
        assert result.is_valid
```

**Step 2: Run tests, verify fail, implement, verify pass**

The implementation searches inventory hostnames for LLDP sysName matches. FQDNs are checked both as-is and with the domain suffix stripped.

**Step 3: Commit**

```bash
cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/snmp-bridge-topology
git add src/gdoc2netcfg/constraints/bridge_validation.py tests/test_constraints/test_bridge_validation.py
git commit -m "Add LLDP topology validation constraint

Cross-references LLDP neighbor sysName with known inventory
hostnames. Reports unknown neighbors as warnings for topology
discovery."
```

---

### Task 8: Wire bridge validation into bridge CLI subcommand

Update `cmd_bridge()` to run the bridge validation constraints and report results.

**Files:**
- Modify: `src/gdoc2netcfg/cli/main.py` (cmd_bridge function)

**Step 1: Update cmd_bridge to run validation**

After the enrich step in `cmd_bridge()`, add:

```python
    from gdoc2netcfg.constraints.bridge_validation import (
        validate_lldp_topology,
        validate_mac_connectivity,
        validate_vlan_names,
    )
    from gdoc2netcfg.derivations.host_builder import build_inventory

    inventory = build_inventory(hosts, config.site)

    # Run bridge validations
    vlan_result = validate_vlan_names(hosts, config.site)
    mac_result = validate_mac_connectivity(inventory)
    lldp_result = validate_lldp_topology(inventory)

    # Report
    for name, vr in [("VLAN names", vlan_result), ("MAC connectivity", mac_result), ("LLDP topology", lldp_result)]:
        if vr.violations:
            print(f"\n{name}:")
            print(vr.report())
```

**Step 2: Run full test suite**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/snmp-bridge-topology && uv run pytest`
Expected: All pass.

**Step 3: Commit**

```bash
cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/snmp-bridge-topology
git add src/gdoc2netcfg/cli/main.py
git commit -m "Wire bridge validation constraints into CLI

Run VLAN name, MAC connectivity, and LLDP topology validations
in the bridge subcommand and report results."
```

---

### Task 9: Lint check and final verification

**Step 1: Run linter**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/snmp-bridge-topology && uv run ruff check src/ tests/`
Fix any issues.

**Step 2: Run full test suite one final time**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/snmp-bridge-topology && uv run pytest -v`
Expected: All tests pass.

**Step 3: Review all changes**

Run: `cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/snmp-bridge-topology && git log --oneline main..HEAD`

Verify the commit history is clean and each commit is a logical unit.

**Step 4: Fix any lint issues and commit**

```bash
cd /home/tim/github/mithro/gdoc2netcfg/.worktrees/snmp-bridge-topology
git add -A
git commit -m "Fix lint issues"
```
