# Network Topology Algorithm Design

## Problem Statement

Given a collection of managed network switches, each reporting their MAC address tables (FDB) and LLDP neighbor information, determine the physical topology of the network: which interface is connected to which switch port.

A host has multiple network interfaces, each with its own MAC address. Each interface is independently cabled to a switch port. The algorithm resolves each MAC (interface) to a specific (switch, port) pair.

### Inputs

- **Managed switches**: Hosts in the inventory that have `bridge_data`. Each provides:
  - **FDB (MAC table)**: `(mac, vlan_id, port_name)` — which MACs are learned on which port
  - **LLDP neighbors**: `(local_port, remote_sysname, remote_port_id, remote_chassis_mac)` — directly connected neighbors that speak LLDP
  - **Port metadata**: port names, operational status, speed, PVIDs, VLAN names
- **Host inventory**: All known hosts with their interfaces, MAC addresses, and metadata (hostname, hardware_type, interface names)

### Outputs

- **TopologyConnection per interface**: Which switch and port each MAC is physically connected to. A host with N interfaces may have up to N TopologyConnections.
- **Inferred devices**: Hidden switches, wireless APs — intermediary devices not in our inventory
- **Virtual devices**: Containers/VMs running inside hosts

## Core Principles

### Principle 1: One Physical Device Per Port

Every physical switch port connects to at most one physical device. If we observe evidence of multiple devices (multiple LLDP neighbors, multiple host MACs), there must be an intermediary device between the switch port and those devices.

The algorithm's job is to identify the one device on each port. If it's a hidden switch, the other devices are behind that hidden switch, not directly on the port.

### Principle 2: LLDP Is One-Hop

LLDP frames are link-local. They are consumed by the first bridge that receives them and do not cross managed switches.

- **1 LLDP neighbor** on a port → that neighbor is directly connected (one hop away)
- **Multiple LLDP neighbors** on a port → an unmanaged device (hub, dumb switch) sits between our port and those neighbors, passing LLDP through without consuming it
- **0 LLDP neighbors** → the connected device doesn't speak LLDP; use MAC analysis

### Principle 3: Match By MAC, Not Hostname

LLDP chassis MACs are the reliable identifier for matching LLDP neighbors to inventory hosts. LLDP sysName (hostname) is unreliable:
- Management prefixes differ (`manage-sw-X` vs `sw-X`)
- Domain suffixes may be present or absent
- sysName may not match inventory hostname at all

All LLDP neighbor resolution must match `chassis_mac` against the host inventory's MAC index.

### Principle 4: Never Drop, Only Move

Every MAC address in a switch's FDB must be accounted for. No MAC is silently filtered or discarded. Instead, each MAC is explicitly **moved** to its correct location with a traceable destination string:

- `"downstream:{switch_hostname}"` — MAC is on a more specific port of a downstream switch
- `"switch-identity:{switch_hostname}"` — MAC belongs to a switch's own interface
- `"wireless-client:{ap_hostname}"` — wireless interface behind an AP
- `"container:{parent_hostname}"` — container/VM interface on a virtualization host
- `"behind-hidden:{hidden_device_id}"` — behind an inferred hidden switch

### Principle 5: Most Specific Port Wins

A MAC address on an uplink port also appears in the downstream switch's FDB. The downstream port is the actual connection point — the uplink just carries the traffic in transit.

This applies recursively through chains of switches. A MAC on Switch A's uplink to Switch B, also in Switch B's FDB on its uplink to Switch C, also in Switch C's FDB on access port 5 — the interface belongs to Switch C port 5.

Each switch independently resolves its own ports. The cascading resolution emerges naturally: each switch moves downstream MACs, and the MAC only becomes a `connected_interface` on the final switch where no further downstream resolution applies.

### Principle 6: Port Classification Is Exhaustive

Every port gets exactly one classification with a defined expected number of connected interfaces:

| Type | Connected interfaces | Meaning |
|---|---|---|
| `access` | 1 | One interface directly connected |
| `access-shared` | 2 | BMC piggy-backing (two interfaces, one physical connection) |
| `uplink` | 1 | Connects to a managed switch (one interface: the switch's) |
| `aggregation-point` | 1 | Hidden switch, hub, or AP — one intermediary device |
| `switch-self` | 0 | Virtual/internal port (CPU, LAG, loopback) |

### Principle 7: Fail Loud

If a MAC can't be resolved, a port can't be classified, or any invariant is violated — raise an error. Never substitute defaults, silently skip, or generate synthetic data.

## Algorithm

### Phase 1: Build Port Index

For each managed switch, iterate its FDB and build a port index:

```
ports: dict[(switch_hostname, port_name) → Port]

Port:
    switch_hostname: str
    port_name: str
    raw_macs: set[str]         # All MACs observed on this port
    moved_macs: dict[str, str] # MAC → destination (where it was moved)
    remaining_macs: set[str]   # raw_macs minus moved_macs keys
    port_type: str             # Classification result
    connected_interfaces: list[(hostname, mac)] # The interface(s) on this port
```

#### MAC-to-interface resolution

Build a `mac_to_interface` index from the inventory. For each host, for each interface on that host, map `interface.mac → (host, interface)`. Then, for every MAC in every switch's FDB, ensure it maps to an interface:

- **Known MAC** — already in `mac_to_interface` from the inventory. Nothing to do.
- **Unknown non-LAA MAC** — create an unknown device (Host stub with `hostname="unknown-{mac}"` and a single interface with that MAC). Add it to `mac_to_interface`. It participates in the algorithm identically to known interfaces.
- **Unknown LAA MAC** — create a virtual device (Host stub with `hostname="virtual-{mac}"` and a single interface with that MAC). Add it to `mac_to_interface`. LAA MACs are identified by bit 1 of the first octet being set (e.g. Docker `02:42:xx`).

**Invariant**: By the end of Phase 1, every MAC address in every switch's FDB is associated with a (host, interface) pair in `mac_to_interface`. No unresolved MACs enter Phase 2.

### Phase 2: Classify Each Port

Process every port through these named steps in order. Each step may move some MACs (adding to `moved_macs`) and recalculate `remaining_macs`. Once a port is classified (`port_type` is set), skip remaining steps for that port unless noted.

Virtual/internal ports (LAGs, CPU interfaces, loopbacks, tunnels) are classified as `switch-self` and skipped immediately.

#### Step: "Identify connected interface from LLDP"

Look up LLDP neighbors for this port, resolving each by chassis MAC (Principle 3).

**Case: Multiple LLDP neighbors** (Principle 2 — hidden device)

There is an unmanaged intermediary on this port. Create a hidden switch.

All LLDP neighbors are behind the hidden switch. Any LLDP neighbor that is a managed switch triggers downstream MAC resolution (see "Move MACs downstream" below). Remaining MACs after downstream resolution are interfaces behind the hidden switch.

Classify port as `aggregation-point` with the hidden switch as the connected interface.

**Case: Single LLDP neighbor is a managed switch**

This is an uplink. The downstream switch is the one device on this port (Principle 1). Move all MACs downstream through that switch (see "Move MACs downstream" below).

Classify port as `uplink` with the downstream switch's interface as the connected interface.

**Case: Single LLDP neighbor is an AP**

The AP is the one device on this port. All other MACs are wireless clients behind the AP. Move them: `moved_macs[mac] = "wireless-client:{ap}"`.

Classify port as `aggregation-point` with the AP's interface as the connected interface.

**Case: Single LLDP neighbor is a regular host**

That interface is directly connected. If there are additional MACs, continue to subsequent steps (they may be containers, BMC pairs, etc.).

**Case: No LLDP neighbors**

Continue to subsequent steps for MAC-based analysis.

#### Step: "Move MACs downstream through managed switch"

This step runs when we've identified a managed switch on (or behind) this port — either as a direct uplink or as an LLDP neighbor behind a hidden device.

The resolution is **transitive** — it follows the entire chain of managed switches reachable through the immediate downstream switch, not just one level deep. A trunk port to switch B carries traffic from B, from switches behind B, from switches behind those switches, etc. All of those MACs must be resolvable.

Given downstream switch S, build the **downstream set** by walking the tree of managed switches reachable through S:

1. Start with S. Add S's own MACs (from all of S's interfaces) to `identity_macs` (mapping MAC → switch hostname). Add all MACs in S's FDB to `fdb_macs`.
2. For each managed switch T that S has an LLDP neighbor relationship with (i.e. T appears as an LLDP neighbor on one of S's ports), **excluding the switch we came from**: recurse — add T's own MACs to `identity_macs`, add T's FDB to `fdb_macs`, and follow T's LLDP neighbors in turn.
3. The result is two sets covering the entire downstream tree:
   - `identity_macs`: MAC → switch hostname, for all switch interface MACs reachable through S
   - `fdb_macs`: all MACs that appear in any FDB in the downstream tree

Then, for each MAC on this port (in `remaining_macs`):
- MAC is in `identity_macs` → `moved_macs[mac] = "switch-identity:{identity_macs[mac]}"`
- MAC appears in `fdb_macs` → `moved_macs[mac] = "downstream:{S}"`
- Neither → stays in `remaining_macs`

Recalculate `remaining_macs`.

**For uplinks** (single LLDP to managed switch): After transitive downstream resolution, any remaining MACs are **a fatal error**. LLDP says there is exactly one device on this port (Principle 1) and transitive resolution covers the entire downstream tree. An unresolvable MAC means the algorithm has a bug or the network data is inconsistent.

**For hidden devices** (multi-LLDP with a managed switch behind it): After downstream resolution, remaining MACs are NOT moved — they belong to OTHER devices behind the hidden switch. Leave them in `remaining_macs`.

#### Step: "Move LAA MACs to virtualization host"

LAA (Locally Administered Address) MACs are identified by bit 1 of the first octet being set. Docker containers typically use `02:42:xx:xx:xx:xx`, other virtualizers use other LAA ranges.

For LAA MACs in `remaining_macs`:
- Find non-LAA (physical) MACs also in `remaining_macs`
- If a physical MAC is found → it's the host's physical interface, LAA MACs are its containers:
  - Create a VirtualDevice for the containers
  - Move LAA MACs: `moved_macs[mac] = "container:{parent_hostname}"`
- If no physical MAC found → **fatal error**. An LAA MAC without a physical parent on the same port should never happen — it indicates a bug or unexpected network condition that needs investigation.

#### Step: "Move wireless MACs to AP"

If no AP was identified via LLDP, check whether any remaining MAC belongs to a known AP (identified by `hardware_type` in the inventory).

If an AP is found:
- The AP's interface is the connected interface on this port
- Other MACs are wireless clients: `moved_macs[mac] = "wireless-client:{ap}"`
- Classify port as `aggregation-point` with the AP's interface as connected interface

#### Step: "Detect BMC piggy-backing"

If exactly 2 remaining MACs and one belongs to host `bmc.X` while the other belongs to host `X`:
- Both interfaces share a single physical NIC (the BMC piggy-backs on the host's NIC)
- Classify port as `access-shared` with both interfaces as connected interfaces

#### Step: "Classify remaining MACs"

After all move operations:
- **0 remaining** → **fatal error**. A port with MACs that all got moved without the port being classified is an impossible state — it indicates a bug in the algorithm.
- **1 remaining** → `port_type = "access"` (single interface directly connected)
- **Multiple remaining** → a hidden switch must exist (Principle 1). Create an `InferredDevice(device_type="hidden")`. All remaining MACs are interfaces behind this hidden switch. Classify port as `aggregation-point`.

### Phase 3: Build Topology Connections

After Phase 2, each MAC in the network is in exactly one of these states:
- It's in a port's `connected_interfaces` (that interface is on that port)
- It's in a port's `moved_macs` (it was moved to a more specific location)
- It's in an InferredDevice's `interfaces_behind` (it's behind a hidden switch or AP)
- It's in a VirtualDevice's `interfaces_behind` (it's a container/VM)

Build a `TopologyConnection` for each interface (MAC) by iterating:
1. All ports' `connected_interfaces` — these are direct connections
2. All InferredDevices' `interfaces_behind` — these are via-hidden or via-wireless connections

Since each MAC was either moved (and doesn't appear as connected_interface) or placed exactly once, no priority resolution is needed. Each MAC has one unambiguous home.

A host with multiple interfaces (e.g. eth0 and eth1) will have multiple TopologyConnections — one per interface, potentially on different switch ports.

### Phase 4: Validate Invariants

Assert:
- Every port has been classified (has a `port_type`)
- Every port has the expected number of `connected_interfaces` for its type
- Every MAC in every port's `raw_macs` is either in `moved_macs` or in `connected_interfaces` or in an InferredDevice/VirtualDevice

## Worked Examples

### Example 1: Simple Access Port

```
Switch A, port gi1:
  FDB: {MAC_X}
  LLDP: (none)

MAC_X → host "desktop", interface eth0
```

**Step "Identify from LLDP"**: No LLDP. Skip.
**Step "Move downstream"**: No managed switch identified. Skip.
**Step "Move LAA"**: MAC_X is not LAA. Skip.
**Step "Move wireless"**: No AP. Skip.
**Step "Detect BMC"**: Only 1 MAC. Skip.
**Step "Classify remaining"**: 1 remaining → `access`.

Result: `gi1` is `access`, connected interface is desktop:eth0 (MAC_X).

### Example 2: Uplink to Managed Switch

```
Switch A, port gi24:
  FDB: {MAC_B, MAC_X, MAC_Y}
  LLDP: [(gi24, sysname="manage-sw-B", chassis_mac=MAC_B)]

MAC_B → host "sw-B" (managed switch), interface mgmt0
  sw-B's FDB contains: MAC_X on port 1, MAC_Y on port 5
MAC_X → host "server1", interface eth0
MAC_Y → host "server2", interface eth0
```

**Step "Identify from LLDP"**: 1 LLDP neighbor. Resolve chassis MAC_B → `sw-B`. `sw-B` is a managed switch → uplink.

**Step "Move downstream"**: Downstream switch is `sw-B`.
- MAC_B is sw-B's own interface MAC → `moved_macs[MAC_B] = "switch-identity:sw-B"`
- MAC_X is in sw-B's FDB → `moved_macs[MAC_X] = "downstream:sw-B"`
- MAC_Y is in sw-B's FDB → `moved_macs[MAC_Y] = "downstream:sw-B"`
- 0 remaining.

Result: `gi24` is `uplink`, connected interface is sw-B:mgmt0 (MAC_B). All 3 MACs accounted for.

When processing `sw-B`, MAC_X resolves to port 1 (access, server1:eth0) and MAC_Y resolves to port 5 (access, server2:eth0). The cascading naturally gives each interface its most specific port.

### Example 3: Cascading Switches (A → B → C → Host)

```
Switch A, port gi1:
  FDB: {MAC_B, MAC_C, MAC_X}
  LLDP: [(gi1, chassis_mac=MAC_B)]  →  sw-B is managed switch

Switch B, port gi5:
  FDB: {MAC_C, MAC_X}
  LLDP: [(gi5, chassis_mac=MAC_C)]  →  sw-C is managed switch

Switch C, port gi3:
  FDB: {MAC_X}
  LLDP: (none)

sw-B's interfaces: mgmt0=MAC_B
sw-C's interfaces: mgmt0=MAC_C
MAC_X → host "server1", interface eth0
```

**Processing Switch A, gi1:**
- LLDP → sw-B (managed switch) → uplink
- Build transitive downstream set through sw-B:
  - sw-B: identity={MAC_B → sw-B}, FDB={MAC_C, MAC_X}
  - sw-B has LLDP to sw-C (managed) on gi5: recurse
  - sw-C: identity={MAC_C → sw-C}, FDB={MAC_X}
  - Combined: identity_macs={MAC_B → sw-B, MAC_C → sw-C}, fdb_macs={MAC_C, MAC_X}
- Move downstream:
  - MAC_B → in identity_macs → `"switch-identity:sw-B"`
  - MAC_C → in identity_macs → `"switch-identity:sw-C"`
  - MAC_X → in fdb_macs → `"downstream:sw-B"`
- 0 remaining → `uplink` to sw-B

**Processing Switch B, gi5:**
- LLDP → sw-C (managed switch) → uplink
- Build transitive downstream set through sw-C:
  - sw-C: identity={MAC_C → sw-C}, FDB={MAC_X}
  - Combined: identity_macs={MAC_C → sw-C}, fdb_macs={MAC_X}
- Move downstream:
  - MAC_C → `"switch-identity:sw-C"`
  - MAC_X → `"downstream:sw-C"` (in C's FDB)
- 0 remaining → `uplink` to sw-C

**Processing Switch C, gi3:**
- No LLDP, 1 MAC → `access`
- Result: `access`, connected interface is server1:eth0 (MAC_X)

**TopologyConnection for server1:eth0**: Switch C, port gi3, connection_type="direct". The MAC was moved downstream at each level, and only surfaces as a `connected_interface` at its most specific port.

Note: MAC_C (sw-C's interface MAC) is correctly resolved on Switch A's trunk port even if MAC_C doesn't appear in sw-B's FDB (e.g. because it's a management/CPU MAC that doesn't transit the bridge). The transitive walk finds sw-C via sw-B's LLDP neighbors and includes sw-C's interface MACs directly.

### Example 4: Hidden Switch via Multi-LLDP

```
Switch A, port gi27:
  FDB: {MAC_B, MAC_X, MAC_D, MAC_E}
  LLDP: [
    (gi27, chassis_mac=MAC_B),   → sw-B is managed switch
    (gi27, chassis_mac=MAC_X),   → "server1" is regular host
  ]

sw-B's FDB contains: MAC_D on port 3, MAC_E on port 8
MAC_X → host "server1", interface eth0
MAC_D → host "laptop1", interface wlan0
MAC_E → host "printer1", interface eth0
```

**Step "Identify from LLDP"**: 2 LLDP neighbors → hidden device (Principle 2).

Create hidden switch `hidden-A-gi27`.

**Step "Move downstream"**: LLDP neighbor sw-B is a managed switch:
- MAC_B (sw-B's own interface MAC) → `moved_macs[MAC_B] = "switch-identity:sw-B"`
- MAC_D (in sw-B's FDB) → `moved_macs[MAC_D] = "downstream:sw-B"`
- MAC_E (in sw-B's FDB) → `moved_macs[MAC_E] = "downstream:sw-B"`
- MAC_X is NOT in sw-B's FDB → stays in remaining (it's another interface behind the hidden switch)

**Step "Classify remaining"**: 1 remaining (MAC_X) → but we already created the hidden switch, so server1:eth0 is behind the hidden switch.

Result: `gi27` is `aggregation-point`. Hidden switch `hidden-A-gi27` has: sw-B and server1:eth0 behind it. MAC_D and MAC_E were moved downstream — they'll be resolved to sw-B's specific ports (3 and 8) when processing sw-B.

### Example 5: Hidden Switch via MAC Analysis (No LLDP)

```
Switch A, port gi1:
  FDB: {MAC_X, MAC_Y}
  LLDP: (none)

MAC_X → host "fritz-box", interface eth0
MAC_Y → host "laptop", interface eth0
```

**Step "Identify from LLDP"**: No LLDP. Skip.
**Steps "Move downstream/LAA/wireless/BMC"**: None apply.
**Step "Classify remaining"**: 2 remaining → hidden switch (Principle 1).

Create hidden switch `hidden-A-gi1` with fritz-box:eth0 and laptop:eth0 behind it.

Result: `gi1` is `aggregation-point`. Both interfaces are behind the hidden switch.

### Example 6: Wireless Access Point

```
Switch A, port gi5:
  FDB: {MAC_AP, MAC_W1, MAC_W2}
  LLDP: [(gi5, chassis_mac=MAC_AP)]  → "ubiquiti-ap" with hardware_type="access-point"

MAC_AP → host "ubiquiti-ap", interface eth0
MAC_W1 → host "phone1", interface wlan0
MAC_W2 → host "laptop2", interface wlp3s0
```

**Step "Identify from LLDP"**: 1 LLDP neighbor. Resolve chassis MAC → `ubiquiti-ap`. It's an AP → AP port.

Move wireless clients:
- `moved_macs[MAC_W1] = "wireless-client:ubiquiti-ap"`
- `moved_macs[MAC_W2] = "wireless-client:ubiquiti-ap"`

Result: `gi5` is `aggregation-point`, connected interface is ubiquiti-ap:eth0 (MAC_AP). Wireless client interfaces phone1:wlan0 and laptop2:wlp3s0 are behind the AP.

### Example 7: Docker Containers (LAA MACs)

```
Switch A, port gi8:
  FDB: {MAC_HOST, MAC_C1, MAC_C2}
  LLDP: (none)

MAC_HOST = 00:11:22:33:44:55  → host "docker-server", interface eth0
MAC_C1 = 02:42:AC:11:00:02    → LAA (Docker container, not in inventory)
MAC_C2 = 02:42:AC:11:00:03    → LAA (Docker container, not in inventory)
```

**Step "Identify from LLDP"**: No LLDP. Skip.
**Step "Move downstream"**: No managed switch. Skip.
**Step "Move LAA"**: MAC_C1 and MAC_C2 are LAA. Physical MAC MAC_HOST found → docker-server:eth0 is the parent interface.
- `moved_macs[MAC_C1] = "container:docker-server"`
- `moved_macs[MAC_C2] = "container:docker-server"`
- Create VirtualDevice for the containers

**Step "Classify remaining"**: 1 remaining (MAC_HOST) → `access`.

Result: `gi8` is `access`, connected interface is docker-server:eth0 (MAC_HOST). Two container interfaces running inside it.

### Example 8: BMC Piggy-backing

```
Switch A, port gi12:
  FDB: {MAC_H, MAC_B}
  LLDP: (none)

MAC_H → host "big-storage", interface eth0
MAC_B → host "bmc.big-storage", interface bmc
```

**Step "Identify from LLDP"**: No LLDP. Skip.
**Steps "Move downstream/LAA/wireless"**: None apply.
**Step "Detect BMC"**: 2 remaining, `bmc.big-storage` and `big-storage` → BMC pair.

Result: `gi12` is `access-shared`, connected interfaces are big-storage:eth0 (MAC_H) and bmc.big-storage:bmc (MAC_B).

### Example 9: Uplink with Unexplained MAC (Fatal Error)

```
Switch A, port gi24:
  FDB: {MAC_B, MAC_X, MAC_MYSTERY}
  LLDP: [(gi24, chassis_mac=MAC_B)]  → sw-B is managed switch

sw-B's interfaces: mgmt0=MAC_B
sw-B's FDB contains: MAC_X on port 3
sw-B has no LLDP neighbors that are managed switches
MAC_X → host "server1", interface eth0
MAC_MYSTERY → unknown device "unknown-{MAC_MYSTERY}" (synthesized in Phase 1)
```

**Step "Identify from LLDP"**: 1 LLDP neighbor → sw-B (managed switch) → uplink.

**Step "Move downstream"** (transitive through sw-B):
- Build downstream set: identity_macs={MAC_B → sw-B}, fdb_macs={MAC_X}
  (sw-B has no further managed switches behind it, so no recursion)
- MAC_B → `"switch-identity:sw-B"`
- MAC_X → `"downstream:sw-B"` (in fdb_macs)
- MAC_MYSTERY → not in identity_macs, not in fdb_macs. Stays in remaining.
- 1 remaining on an uplink → **fatal error**.

This is an uplink — LLDP says sw-B is the only device on this cable (Principle 1), and transitive resolution covered the entire downstream tree. MAC_MYSTERY being unresolvable means either the network data is inconsistent (SNMP polls taken at different times) or there's a bug in the algorithm. Either way, it must be investigated, not silently papered over.

### Example 10: Switch Identity MAC Not in Intermediate FDB

This example demonstrates why transitive downstream resolution is necessary.

```
Switch C, port gi1:
  FDB: {MAC_B, MAC_A, MAC_X, MAC_Y}
  LLDP: [(gi1, chassis_mac=MAC_B)]  → sw-B is managed switch

sw-B's interfaces: mgmt0=MAC_B
sw-B's FDB: {MAC_X on gi8, MAC_Y on gi5, MAC_A on gi5}
  NOTE: MAC_A may or may NOT be in sw-B's FDB — management/CPU MACs
  don't always transit the bridge. This example covers both cases.

sw-B, port gi5:
  LLDP: [(gi5, chassis_mac=MAC_A)]  → sw-A is managed switch

sw-A's interfaces: mgmt0=MAC_A
sw-A's FDB: {MAC_Y on gi3}

MAC_X → host "server1", interface eth0 (connected to sw-B:gi8)
MAC_Y → host "laptop1", interface eth0 (connected to sw-A:gi3)
```

**Processing Switch C, gi1:**
- LLDP → sw-B (managed switch) → uplink
- Build transitive downstream set through sw-B:
  - sw-B: identity={MAC_B → sw-B}, FDB={MAC_X, MAC_Y, maybe MAC_A}
  - sw-B has LLDP to sw-A (managed) on gi5: recurse
  - sw-A: identity={MAC_A → sw-A}, FDB={MAC_Y}
  - Combined: identity_macs={MAC_B → sw-B, MAC_A → sw-A}, fdb_macs={MAC_X, MAC_Y, maybe MAC_A}
- Move downstream:
  - MAC_B → in identity_macs → `"switch-identity:sw-B"`
  - MAC_A → in identity_macs → `"switch-identity:sw-A"`
  - MAC_X → in fdb_macs → `"downstream:sw-B"`
  - MAC_Y → in fdb_macs → `"downstream:sw-B"`
- 0 remaining → `uplink` to sw-B

**Key point**: MAC_A is resolved via `identity_macs` from the transitive walk, regardless of whether it appears in sw-B's FDB. Without transitive resolution, MAC_A would be left in `remaining_macs` — a fatal error on an uplink port. With transitive resolution, it's correctly identified as sw-A's interface MAC.

**Processing sw-B, gi5:**
- LLDP → sw-A (managed switch) → uplink
- Transitive downstream: identity_macs={MAC_A → sw-A}, fdb_macs={MAC_Y}
- MAC_A → `"switch-identity:sw-A"`, MAC_Y → `"downstream:sw-A"`
- 0 remaining → `uplink` to sw-A

**Processing sw-B, gi8:**
- No LLDP, 1 MAC → `access`, connected interface is server1:eth0 (MAC_X)

**Processing sw-A, gi3:**
- No LLDP, 1 MAC → `access`, connected interface is laptop1:eth0 (MAC_Y)

### Example 11: Host with Multiple Interfaces on Different Ports

This example demonstrates that the algorithm resolves each interface independently.

```
Switch A, port gi1:
  FDB: {MAC_ETH0}
  LLDP: (none)

Switch A, port gi2:
  FDB: {MAC_ETH1}
  LLDP: (none)

MAC_ETH0 → host "big-storage", interface eth0
MAC_ETH1 → host "big-storage", interface eth1
```

**Processing gi1**: 1 MAC, no LLDP → `access`, connected interface is big-storage:eth0 (MAC_ETH0).

**Processing gi2**: 1 MAC, no LLDP → `access`, connected interface is big-storage:eth1 (MAC_ETH1).

**TopologyConnections for big-storage**: Two connections — eth0 on gi1, eth1 on gi2. Each interface is resolved independently.

### Example 12: Hidden Switch with Cascading Resolution

```
Switch A, port gi27:
  FDB: {MAC_B, MAC_X, MAC_C, MAC_Z}
  LLDP: [
    (gi27, chassis_mac=MAC_B),  → sw-B is managed switch
    (gi27, chassis_mac=MAC_X),  → "server1" is regular host
  ]

sw-B's interfaces: mgmt0=MAC_B
sw-B's FDB: {MAC_C on port gi1, MAC_Z on port gi1}

Switch B, port gi1:
  LLDP: [(gi1, chassis_mac=MAC_C)]  → sw-C is managed switch
  sw-C's FDB: {MAC_Z on port 5}

MAC_X → host "server1", interface eth0
MAC_Z → host "workstation1", interface eth0
```

**Processing Switch A, gi27:**
- Multi-LLDP → hidden switch `hidden-A-gi27`
- Downstream resolution for sw-B:
  - MAC_B → `"switch-identity:sw-B"`
  - MAC_C → `"downstream:sw-B"` (in B's FDB)
  - MAC_Z → `"downstream:sw-B"` (in B's FDB)
  - MAC_X → not in B's FDB → stays in remaining (it's server1:eth0, behind the hidden switch)
- Hidden switch has sw-B and server1:eth0 behind it

**Processing Switch B, gi1:**
- LLDP → sw-C (managed switch) → uplink
- MAC_C → `"switch-identity:sw-C"`
- MAC_Z → `"downstream:sw-C"` (in C's FDB)

**Processing Switch C, port 5:**
- MAC_Z, no LLDP → `access`, connected interface is workstation1:eth0 (MAC_Z)

**Final result for workstation1:eth0**: TopologyConnection to Switch C, port 5. The MAC cascaded through hidden-switch → sw-B → sw-C to its most specific port.
