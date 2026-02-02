# SNMP Bridge/Network Topology Supplement

## Summary

Add a new SNMP supplement focused on collecting switch-level network topology
data (MAC address tables, VLAN configuration, LLDP neighbors, port status, PoE
status) from managed switches. This data enables post-processing validation of
network connectivity and VLAN configuration, and discovery of unknown devices.

## Context

### What exists today

The existing `supplements/snmp.py` collects host-level SNMP data: system info
(`sysDescr`, `sysName`, etc.), `ifTable`, and `ipAddrTable`. This data
describes a host itself. It is stored per-host in `.cache/snmp.json` and
attached to `Host.snmp_data`.

### What this adds

Switch-specific bridge/topology data that describes the *network between hosts*:

- **Q-BRIDGE-MIB** (`dot1qTpFdbTable`): Which MAC addresses are seen on which
  switch port, per VLAN. This is the core data for connectivity discovery.
- **Q-BRIDGE-MIB** VLAN tables (`dot1qVlanStaticTable`, `dot1qPvid`,
  `dot1qVlanStaticEgressPorts`, `dot1qVlanStaticUntaggedPorts`): Actual VLAN
  configuration on each switch port.
- **BRIDGE-MIB** (`dot1dBasePortIfIndex`): Mapping from bridge port numbers to
  ifIndex values (needed to resolve MAC table ports to interface names).
- **LLDP-MIB** (`lldpRemTable`): Link Layer Discovery Protocol neighbors,
  providing switch-to-switch and switch-to-host topology.
- **IF-MIB** (`ifName`, `ifOperStatus`, `ifHighSpeed`): Interface names, link
  status, and speed for each switch port.
- **POWER-ETHERNET-MIB** (`pethPsePortTable`): PoE delivery status per port.

### Verified data availability

Tested against `sw-netgear-s3300-1` (10.1.5.11) on 2026-02-02:

| MIB table                    | Entries | Available |
|------------------------------|---------|-----------|
| dot1qTpFdbTable (MAC table)  | 410     | Yes       |
| dot1qVlanStaticTable         | 121     | Yes       |
| dot1qPvid (port native VLAN) | 468     | Yes       |
| dot1qVlanStaticEgressPorts   | 33      | Yes       |
| dot1qVlanStaticUntaggedPorts | 33      | Yes       |
| dot1dBasePortIfIndex         | 78      | Yes       |
| lldpRemTable                 | 18      | Yes       |
| ifName                       | 79      | Yes       |
| ifOperStatus                 | 79      | Yes       |
| ifHighSpeed                  | 79      | Yes       |
| pethPsePortTable             | 533     | Yes       |
| dot1dTpFdbTable (non-VLAN)   | 0       | No        |

Cross-referencing the MAC table against 365 known spreadsheet MACs produced
72 matches out of 227 switch MAC entries, with 155 unmatched (mostly
locally-administered `BA:BE:xx` container/VM MACs).

### Current switch inventory

From the spreadsheet and reachability testing on 2026-02-02:

| Switch                     | IP         | Reachable | SNMP |
|----------------------------|------------|-----------|------|
| sw-netgear-s3300-1         | 10.1.5.11  | Yes       | Yes (public) |
| sw-netgear-gs110emx1       | 10.1.5.25  | Yes       | No (Plus model) |
| sw-netgear-gs110emx2       | 10.1.5.26  | Yes       | No (Plus model) |
| sw-netgear-gs110emx3       | 10.1.5.27  | Yes       | No (Plus model) |
| sw-cisco-shed              | 10.1.5.35  | Yes       | No (needs enabling) |
| sw-netgear-gs728tpp        | 10.1.5.10  | No        | -    |
| sw-netgear-s3300-2         | 10.1.5.12  | No        | -    |
| sw-netgear-m7300           | 10.1.5.20  | No        | -    |
| sw-netgear-xs748t          | 10.1.5.21  | No        | -    |
| sw-netgear-gsm7252ps-p/s1/s2 | .22-.24 | No        | -    |
| Others                     | .28-.34    | No        | -    |

## Design

### New supplement: `supplements/bridge.py`

Separate from the existing `supplements/snmp.py`. They share SNMP
infrastructure (pysnmp connection handling, credential cascade) but collect
different data for different purposes:

- `snmp.py`: Host-level data (any SNMP host). Enriches individual `Host` objects.
- `bridge.py`: Switch-level topology data. Describes the network between hosts.

#### Data collection

Uses `pysnmp` (consistent with existing supplement). Collects from hosts with
`hardware_type` indicating a managed switch, or where the existing
`Host.snmp_data` indicates SNMP is available.

Single scan pass per switch collects all bridge OID tables listed above.

#### Cache

Stored in `.cache/bridge.json`, keyed by switch hostname. Same caching pattern
as existing supplements (max_age, force flag, reachability-aware skipping).

#### Raw data model

Raw collected data attaches to individual switch `Host` objects initially. The
exact data model will be determined during development based on what proves
useful for validation and reporting.

### Post-processing and validation (constraints)

Constraints to be developed incrementally, consuming the collected bridge data:

1. **MAC connectivity validation**: Cross-reference switch MAC tables with
   known spreadsheet MACs. Report:
   - Known devices seen on unexpected switch ports
   - Unknown MACs on the network (not in spreadsheet)
   - Known devices not seen on any switch (expected but missing)

2. **VLAN configuration validation**: Compare actual switch VLAN-per-port
   config against expected VLANs derived from IP addressing:
   - Port PVID mismatches vs expected VLAN for connected device
   - Missing VLAN membership on trunk ports
   - VLAN names on switch vs VLAN Allocations spreadsheet

3. **LLDP topology validation**: Cross-reference LLDP neighbor data with
   spreadsheet `Parent` column and known switch hostnames:
   - Validate switch-to-switch links
   - Discover topology not recorded in spreadsheet
   - Detect sysName mismatches

4. **Port status checks**:
   - Known devices on down ports
   - PoE status for devices expected to be PoE-powered

### Other SNMP cross-check opportunities (brainstormed)

Beyond the three primary features above, SNMP bridge data enables:

- **Duplicate MAC detection across switches**: If the same MAC appears on
  multiple switches on non-trunk ports, it may indicate a loop or
  misconfiguration.
- **Switch port utilisation reporting**: Which ports are in use, which are
  free, helping with capacity planning.
- **Trunk port validation**: Verify that inter-switch links carry all expected
  VLANs (using egress port bitmaps).
- **Stale MAC detection**: MACs in the switch table that haven't been seen
  recently (if the switch exposes aging info).
- **sysName/sysDescr consistency**: Verify switch model descriptions match
  what's recorded in the spreadsheet `Notes` column.
- **PoE power budgeting**: Compare total PoE draw across ports against switch
  power budget.
- **Interface speed validation**: Verify that inter-switch uplinks are
  negotiated at expected speeds (e.g. 10G uplinks not falling back to 1G).
- **Auto-discovery of switch topology**: Build a graph of switch
  interconnections from LLDP data, detecting unrecorded or changed links.
- **Container/VM MAC cataloguing**: The `BA:BE:xx` locally-administered MACs
  could be cross-referenced with container/VM inventories if those become
  tracked.

### CLI integration

New subcommand `bridge` (or extend existing `snmp` subcommand with a
`--bridge` flag). Follows the same pattern as `cmd_snmp()`: reachability
check, scan, enrich, validate, report.

### Shared SNMP infrastructure

Extract common SNMP functionality from `supplements/snmp.py` into a shared
module (e.g. `supplements/snmp_common.py` or similar) to avoid duplication:

- pysnmp connection setup and credential cascade
- Bulk walk implementation
- Cache load/save pattern
- Reachability-aware host filtering
