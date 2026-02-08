# Network Topology Algorithm Design

## Problem Statement

Given a collection of managed network switches, each reporting their MAC address tables (FDB) and LLDP neighbor information, determine the physical topology of the network: which device is connected to which switch port.

### Inputs

- **Managed switches**: Hosts in the inventory that have `bridge_data`. Each provides:
  - **FDB (MAC table)**: `(mac, vlan_id, port_name)` — which MACs are learned on which port
  - **LLDP neighbors**: `(local_port, remote_sysname, remote_port_id, remote_chassis_mac)` — directly connected devices that speak LLDP
  - **Port metadata**: port names, operational status, speed, PVIDs, VLAN names
- **Host inventory**: All known hosts with their MAC addresses and metadata (hostname, hardware_type, interface names)

### Outputs

- **TopologyConnection per host interface**: Which switch and port each host MAC is physically connected to
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
- `"switch-identity:{switch_hostname}"` — MAC belongs to the switch itself
- `"wireless-client:{ap_hostname}"` — wireless device behind an AP
- `"container:{parent_hostname}"` — container/VM on a virtualization host
- `"behind-hidden:{hidden_device_id}"` — behind an inferred hidden switch

### Principle 5: Most Specific Port Wins

A MAC address on an uplink port also appears in the downstream switch's FDB. The downstream port is the actual connection point — the uplink just carries the traffic in transit.

This applies recursively through chains of switches. A MAC on Switch A's uplink to Switch B, also in Switch B's FDB on its uplink to Switch C, also in Switch C's FDB on access port 5 — the MAC belongs to Switch C port 5.

Each switch independently resolves its own ports. The cascading resolution emerges naturally: each switch moves downstream MACs, and the MAC only becomes a `connected_interface` on the final switch where no further downstream resolution applies.

### Principle 6: Port Classification Is Exhaustive

Every port gets exactly one classification with a defined expected number of connected interfaces:

| Type | Connected interfaces | Meaning |
|---|---|---|
| `access` | 1 | One device directly connected |
| `access-shared` | 2 | BMC piggy-backing (two hosts, one physical connection) |
| `uplink` | 1 | Connects to a managed switch |
| `aggregation-point` | 1 | Hidden switch, hub, or AP — one intermediary device |
| `filtered` | 0 | All MACs moved elsewhere (e.g. all were downstream) |
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
    connected_interfaces: list # The device(s) on this port
```

Also synthesize "unknown" Host objects for any non-LAA MAC in a switch's FDB that doesn't belong to any known host. These unknown hosts participate in the algorithm identically to known hosts.

### Phase 2: Classify Each Port

Process every port through these named steps in order. Each step may move some MACs (adding to `moved_macs`) and recalculate `remaining_macs`. Once a port is classified (`port_type` is set), skip remaining steps for that port unless noted.

Virtual/internal ports (LAGs, CPU interfaces, loopbacks, tunnels) are classified as `switch-self` and skipped immediately.

#### Step: "Identify connected device from LLDP"

Look up LLDP neighbors for this port, resolving each by chassis MAC (Principle 3).

**Case: Multiple LLDP neighbors** (Principle 2 — hidden device)

There is an unmanaged intermediary on this port. Create a hidden switch.

All LLDP neighbors are behind the hidden switch. Any LLDP neighbor that is a managed switch triggers downstream MAC resolution (see "Move MACs downstream" below). Remaining MACs after downstream resolution are devices behind the hidden switch.

Classify port as `aggregation-point` with the hidden switch as the connected device.

**Case: Single LLDP neighbor is a managed switch**

This is an uplink. The downstream switch is the one device on this port (Principle 1). Move all MACs downstream through that switch (see "Move MACs downstream" below).

Classify port as `uplink` with the downstream switch as the connected device.

**Case: Single LLDP neighbor is an AP**

The AP is the one device on this port. All other MACs are wireless clients behind the AP. Move them: `moved_macs[mac] = "wireless-client:{ap}"`.

Classify port as `aggregation-point` with the AP as the connected device.

**Case: Single LLDP neighbor is a regular host**

That host is directly connected. If there are additional MACs, continue to subsequent steps (they may be containers, BMC pairs, etc.).

**Case: No LLDP neighbors**

Continue to subsequent steps for MAC-based analysis.

#### Step: "Move MACs downstream through managed switch"

This step runs when we've identified a managed switch on (or behind) this port — either as a direct uplink or as an LLDP neighbor behind a hidden device.

Given downstream switch S:

1. Collect S's FDB: all MACs that S has learned on any of its ports
2. Collect S's own MACs: all interface MACs from S's host inventory entry
3. For each MAC on this port (in `remaining_macs`):
   - MAC is one of S's own MACs → `moved_macs[mac] = "switch-identity:{S}"`
   - MAC appears in S's FDB → `moved_macs[mac] = "downstream:{S}"`
4. Recalculate `remaining_macs`

**For uplinks** (single LLDP to managed switch): After downstream resolution, any remaining MACs are unexplained — they're on the cable to S but S doesn't know about them. These could be per-port interface MACs, management artifacts, etc. Move them as `moved_macs[mac] = "downstream:{S}"` with a warning. One device per port means everything here is attributable to S.

**For hidden devices** (multi-LLDP with a managed switch behind it): After downstream resolution, remaining MACs are NOT moved — they belong to OTHER devices behind the hidden switch. Leave them in `remaining_macs`.

#### Step: "Move LAA MACs to virtualization host"

LAA (Locally Administered Address) MACs are identified by bit 1 of the first octet being set. Docker containers typically use `02:42:xx:xx:xx:xx`, other virtualizers use other LAA ranges.

For LAA MACs in `remaining_macs`:
- Find non-LAA (physical) MACs also in `remaining_macs`
- If a physical MAC is found → it's the host, LAA MACs are its containers:
  - Create a VirtualDevice for the containers
  - Move LAA MACs: `moved_macs[mac] = "container:{parent_hostname}"`
- If no physical MAC found → leave LAA MACs in `remaining_macs` (they represent real devices whose physical NIC MAC isn't in the FDB — do NOT drop them)

#### Step: "Move wireless MACs to AP"

If no AP was identified via LLDP, check whether any remaining MAC belongs to a known AP (identified by `hardware_type` in the inventory).

If an AP is found:
- The AP is the device on this port
- Other MACs are wireless clients: `moved_macs[mac] = "wireless-client:{ap}"`
- Classify port as `aggregation-point` with the AP as connected device

#### Step: "Detect BMC piggy-backing"

If exactly 2 remaining MACs and one host is `bmc.X` while the other is `X`:
- Both hosts share a single physical NIC (the BMC piggy-backs on the host's NIC)
- Classify port as `access-shared` with both as connected interfaces

#### Step: "Classify remaining MACs"

After all move operations:
- **0 remaining** → `port_type = "filtered"` (everything was moved elsewhere)
- **1 remaining** → `port_type = "access"` (single device directly connected)
- **Multiple remaining** → a hidden switch must exist (Principle 1). Create an `InferredDevice(device_type="hidden")`. All remaining MACs are devices behind this hidden switch. Classify port as `aggregation-point`.

### Phase 3: Build Topology Connections

After Phase 2, each MAC in the network is in exactly one of these states:
- It's in a port's `connected_interfaces` (it's the device on that port)
- It's in a port's `moved_macs` (it was moved to a more specific location)
- It's in an InferredDevice's `interfaces_behind` (it's behind a hidden switch or AP)
- It's in a VirtualDevice's `interfaces_behind` (it's a container/VM)

Build a `TopologyConnection` for each host by iterating:
1. All ports' `connected_interfaces` — these are direct connections
2. All InferredDevices' `interfaces_behind` — these are via-hidden or via-wireless connections

Since each MAC was either moved (and doesn't appear as connected_interface) or placed exactly once, no priority resolution is needed. Each MAC has one unambiguous home.

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

MAC_X → known host "desktop" in inventory
```

**Step "Identify from LLDP"**: No LLDP. Skip.
**Step "Move downstream"**: No managed switch identified. Skip.
**Step "Move LAA"**: MAC_X is not LAA. Skip.
**Step "Move wireless"**: No AP. Skip.
**Step "Detect BMC"**: Only 1 MAC. Skip.
**Step "Classify remaining"**: 1 remaining → `access`.

Result: `gi1` is `access`, connected device is `desktop`.

### Example 2: Uplink to Managed Switch

```
Switch A, port gi24:
  FDB: {MAC_B, MAC_X, MAC_Y}
  LLDP: [(gi24, sysname="manage-sw-B", chassis_mac=MAC_B)]

MAC_B → known host "sw-B" (managed switch) in inventory
  sw-B's FDB contains: MAC_X on port 1, MAC_Y on port 5
MAC_X → known host "server1"
MAC_Y → known host "server2"
```

**Step "Identify from LLDP"**: 1 LLDP neighbor. Resolve chassis MAC_B → `sw-B`. `sw-B` is a managed switch → uplink.

**Step "Move downstream"**: Downstream switch is `sw-B`.
- MAC_B is sw-B's own MAC → `moved_macs[MAC_B] = "switch-identity:sw-B"`
- MAC_X is in sw-B's FDB → `moved_macs[MAC_X] = "downstream:sw-B"`
- MAC_Y is in sw-B's FDB → `moved_macs[MAC_Y] = "downstream:sw-B"`
- 0 remaining.

Result: `gi24` is `uplink`, connected device is `sw-B`. All 3 MACs accounted for.

When processing `sw-B`, MAC_X resolves to port 1 (access) and MAC_Y resolves to port 5 (access). The cascading naturally gives each MAC its most specific port.

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
```

**Processing Switch A, gi1:**
- LLDP → sw-B (managed switch) → uplink
- Move downstream: MAC_B (identity), MAC_C (in B's FDB), MAC_X (in B's FDB) → all moved
- Result: `uplink` to sw-B

**Processing Switch B, gi5:**
- LLDP → sw-C (managed switch) → uplink
- Move downstream: MAC_C (identity), MAC_X (in C's FDB) → all moved
- Result: `uplink` to sw-C

**Processing Switch C, gi3:**
- No LLDP, 1 MAC → `access`
- Result: `access`, connected device is host X

**TopologyConnection for host X**: Switch C, port gi3, connection_type="direct". The MAC was moved downstream at each level, and only surfaces as a `connected_interface` at its most specific port.

### Example 4: Hidden Switch via Multi-LLDP

```
Switch A, port gi27:
  FDB: {MAC_B, MAC_X, MAC_D, MAC_E}
  LLDP: [
    (gi27, chassis_mac=MAC_B),   → sw-B is managed switch
    (gi27, chassis_mac=MAC_X),   → "server1" is regular host
  ]

sw-B's FDB contains: MAC_D on port 3, MAC_E on port 8
MAC_X → "server1" (not a switch)
MAC_D → "laptop1"
MAC_E → "printer1"
```

**Step "Identify from LLDP"**: 2 LLDP neighbors → hidden device (Principle 2).

Create hidden switch `hidden-A-gi27`.

**Step "Move downstream"**: LLDP neighbor sw-B is a managed switch:
- MAC_B (sw-B's own MAC) → `moved_macs[MAC_B] = "switch-identity:sw-B"`
- MAC_D (in sw-B's FDB) → `moved_macs[MAC_D] = "downstream:sw-B"`
- MAC_E (in sw-B's FDB) → `moved_macs[MAC_E] = "downstream:sw-B"`
- MAC_X is NOT in sw-B's FDB → stays in remaining (it's another device behind the hidden switch)

**Step "Classify remaining"**: 1 remaining (MAC_X) → but we already created the hidden switch, so MAC_X is a device behind the hidden switch.

Result: `gi27` is `aggregation-point`. Hidden switch `hidden-A-gi27` has: sw-B and server1 behind it. MAC_D and MAC_E were moved downstream — they'll be resolved to sw-B's specific ports (3 and 8) when processing sw-B.

### Example 5: Hidden Switch via MAC Analysis (No LLDP)

```
Switch A, port gi1:
  FDB: {MAC_X, MAC_Y}
  LLDP: (none)

MAC_X → "fritz-box" (regular host)
MAC_Y → "laptop" (regular host)
```

**Step "Identify from LLDP"**: No LLDP. Skip.
**Steps "Move downstream/LAA/wireless/BMC"**: None apply.
**Step "Classify remaining"**: 2 remaining → hidden switch (Principle 1).

Create hidden switch `hidden-A-gi1` with fritz-box and laptop behind it.

Result: `gi1` is `aggregation-point`. Both devices are behind the hidden switch.

### Example 6: Wireless Access Point

```
Switch A, port gi5:
  FDB: {MAC_AP, MAC_W1, MAC_W2}
  LLDP: [(gi5, chassis_mac=MAC_AP)]  → "ubiquiti-ap" with hardware_type="access-point"

MAC_W1 → "phone1" with interface name "wlan0"
MAC_W2 → "laptop2" with interface name "wlp3s0"
```

**Step "Identify from LLDP"**: 1 LLDP neighbor. Resolve chassis MAC → `ubiquiti-ap`. It's an AP → AP port.

Move wireless clients:
- `moved_macs[MAC_W1] = "wireless-client:ubiquiti-ap"`
- `moved_macs[MAC_W2] = "wireless-client:ubiquiti-ap"`

Result: `gi5` is `aggregation-point`, connected device is ubiquiti-ap. Wireless clients are behind the AP.

### Example 7: Docker Containers (LAA MACs)

```
Switch A, port gi8:
  FDB: {MAC_HOST, MAC_C1, MAC_C2}
  LLDP: (none)

MAC_HOST = 00:11:22:33:44:55  → "docker-server" (physical host)
MAC_C1 = 02:42:AC:11:00:02    → LAA (Docker container, not in inventory)
MAC_C2 = 02:42:AC:11:00:03    → LAA (Docker container, not in inventory)
```

**Step "Identify from LLDP"**: No LLDP. Skip.
**Step "Move downstream"**: No managed switch. Skip.
**Step "Move LAA"**: MAC_C1 and MAC_C2 are LAA. Physical MAC MAC_HOST found → docker-server is the host.
- `moved_macs[MAC_C1] = "container:docker-server"`
- `moved_macs[MAC_C2] = "container:docker-server"`
- Create VirtualDevice for the containers

**Step "Classify remaining"**: 1 remaining (MAC_HOST) → `access`.

Result: `gi8` is `access`, connected device is docker-server. Two containers running inside it.

### Example 8: BMC Piggy-backing

```
Switch A, port gi12:
  FDB: {MAC_H, MAC_B}
  LLDP: (none)

MAC_H → "big-storage" (server)
MAC_B → "bmc.big-storage" (BMC)
```

**Step "Identify from LLDP"**: No LLDP. Skip.
**Steps "Move downstream/LAA/wireless"**: None apply.
**Step "Detect BMC"**: 2 remaining, `bmc.big-storage` and `big-storage` → BMC pair.

Result: `gi12` is `access-shared`, both big-storage and bmc.big-storage are connected.

### Example 9: Uplink with Unexplained MAC

```
Switch A, port gi24:
  FDB: {MAC_B, MAC_X, MAC_MYSTERY}
  LLDP: [(gi24, chassis_mac=MAC_B)]  → sw-B is managed switch

sw-B's FDB contains: MAC_X on port 3
sw-B's own MACs: {MAC_B}
MAC_MYSTERY is NOT in sw-B's FDB and NOT one of sw-B's MACs
```

**Step "Identify from LLDP"**: 1 LLDP neighbor → sw-B (managed switch) → uplink.

**Step "Move downstream"**:
- MAC_B → `"switch-identity:sw-B"`
- MAC_X → `"downstream:sw-B"` (in B's FDB)
- MAC_MYSTERY → not in B's FDB, not B's own MAC. But this is an uplink — one device per port means the switch is the only device. Move: `"downstream:sw-B"` + warning.

Result: `gi24` is `uplink`. MAC_MYSTERY is accounted for (with a warning for investigation).

### Example 10: Hidden Switch with Cascading Resolution

```
Switch A, port gi27:
  FDB: {MAC_B, MAC_X, MAC_C, MAC_Z}
  LLDP: [
    (gi27, chassis_mac=MAC_B),  → sw-B is managed switch
    (gi27, chassis_mac=MAC_X),  → "server1" is regular host
  ]

sw-B's own MACs: {MAC_B}
sw-B's FDB: {MAC_C on port gi1, MAC_Z on port gi1}

Switch B, port gi1:
  LLDP: [(gi1, chassis_mac=MAC_C)]  → sw-C is managed switch
  sw-C's FDB: {MAC_Z on port 5}
```

**Processing Switch A, gi27:**
- Multi-LLDP → hidden switch `hidden-A-gi27`
- Downstream resolution for sw-B:
  - MAC_B → `"switch-identity:sw-B"`
  - MAC_C → `"downstream:sw-B"` (in B's FDB)
  - MAC_Z → `"downstream:sw-B"` (in B's FDB)
  - MAC_X → not in B's FDB → stays in remaining (it's server1, behind the hidden switch)
- Hidden switch has sw-B and server1 behind it

**Processing Switch B, gi1:**
- LLDP → sw-C (managed switch) → uplink
- MAC_C → `"switch-identity:sw-C"`
- MAC_Z → `"downstream:sw-C"` (in C's FDB)

**Processing Switch C, port 5:**
- MAC_Z, no LLDP → `access`, connected device is host Z

**Final result for host Z**: TopologyConnection to Switch C, port 5. The MAC cascaded through hidden-switch → sw-B → sw-C to its most specific port.
