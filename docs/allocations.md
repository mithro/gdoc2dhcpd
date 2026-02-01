# Network Allocations

## Overview

This document describes the IP address allocation scheme used across multiple sites. The scheme maintains visual consistency between IPv4 and IPv6 addresses using a mapping format.

## Sites

| Site                | IPv4 Range   | IPv4 CIDR | IPv6 Range (Launtel) | IPv6 Range (HE)     | IPv6 CIDR | Domain             |
|---------------------|--------------|-----------|----------------------|---------------------|-----------|---------------------|
| Public IP Addresses | 87.121.95.37 | /32       | 2404:e80:a137:100::  | 2001:470:82b3:100:: | /48       | -                   |
| Welland             | 10.1.X.X     | /16       | 2404:e80:a137:1XX::X | 2001:470:82b3:1XX::X| /56       | welland.mithis.com  |
| Monarto             | 10.2.X.X     | /16       | 2404:e80:a137:2XX::X | 2001:470:82b3:2X::X | /56       | monarto.mithis.com  |
| Pumping Station 1   | -            | -         | -                    | -                   | -         | ps1.mithis.com      |
| Hetzner             | -            | -         | -                    | -                   | -         | hetzner.mithis.com  |

## VLANs

| VLAN | Name               | IPv4 Range   | Description                              |
|------|--------------------|--------------|------------------------------------------|
| 1    | Quarantine         | 10.1.1.X     | Temporary/quarantine network             |
| 5    | Network Management | 10.1.5.X     | Switches, config interfaces              |
| 6    | Power Management   | 10.1.6.X     | UPSs, etc.                               |
| 7    | Internal Storage   | 10.1.7.X     | NVMe over Ethernet, RDMA                 |
| 10   | Internal Wired     | 10.1.10-16.X | Simple hosts, complex hosts, switches    |
| 20   | Roaming            | 10.1.20.X    | WiFi roaming (personal, friends, work)   |
| 31   | FPGA Test          | 10.31.0.X    | FPGA test network                        |
| 41   | Supermicro Test    | 10.41.0.X    | Supermicro test network                  |
| 90   | IoT                | 10.1.90.X    | IoT devices                              |
| 99   | Guest              | 10.1.99.X    | Guest network                            |

## IPv4 to IPv6 Mapping Scheme

The mapping maintains visual consistency between IPv4 and IPv6 addresses:

```
IPv4:  10.AA.BB.CCC
IPv6:  {prefix}AABB::CCC
```

### Constraints

- **A (site)**: 00-99  (99 sites/networks)
- **B (net)** : 00-99  (99 segments per network)
- **C (host)**: 00-256 (256 hosts per segment)

> Note: IPv6 uses hex `:XXYY:` format while IPv4 uses decimal `.ZZZ` format. Limiting to 00-99 keeps the visual numbers consistent.

### Allocation Types

| Type                    | IPv4           | Netmask         | CIDR | IPv6 (Launtel)           | IPv6 CIDR | Description                                      |
|-------------------------|----------------|-----------------|------|--------------------------|-----------|--------------------------------------------------|
| Site                    | 10.AA.X.X      | 255.255.0.0     | /16  | 2404:e80:a137:AA00::     | /56       | A site needs /56 (256x /64 segments)             |
| Segment                 | 10.AA.BB.X     | 255.255.255.0   | /24  | 2404:e80:a137:AABB::     | /64       | Segment needs /64 for SLAAC                      |
| Simple Host             | 10.AA.BB.CCC   | 255.255.255.255 | /32  | 2404:e80:a137:AABB::CCC  | /128      | Single IP host                                   |
| Complex Host            | 10.AA.BB.CCD   | 255.255.255.255 | /32  | 2404:e80:a137:AABB::CCD  | /128      | Host with multiple interfaces (D=0-9)            |
| Complex Host VM Network | 10.CC.X.X      | 255.255.0.0     | /16  | 2404:e80:a137:CC00::     | /56       | VM networks on a complex host                    |

### Site Number Ranges

- **00-09**: Physical sites
- **10-25**: VMs on machines
- **26-99**: Special networks

## Special Networks

| Network                 | VLAN | IPv4 Range | IPv4 CIDR | IPv6 (Launtel)       | IPv6 CIDR | Domain                   |
|-------------------------|------|------------|-----------|----------------------|-----------|--------------------------|
| Guest Network           | 99   | 10.99.99.X | /24       | 2404:e80:a137:9999:: | /56       | guest.welland.mithis.com |
| FPGA Test Network       | 31   | 10.31.0.X  | /24       | 2404:e80:a137:3100:: | /56       | fpgas.welland.mithis.com |
| Supermicro Test Network | 41   | 10.41.0.X  | /24       | 2404:e80:a137:4100:: | /56       | sm.welland.mithis.com    |

## Virtual Machine Allocations

| Host        | IPv4 Range | IPv4 CIDR | IPv6 (Launtel)       | IPv6 CIDR | Domain                         |
|-------------|------------|-----------|----------------------|-----------|--------------------------------|
| Ten64       | 10.10.X.X  | /16       | 2404:e80:a137:1000:: | /56       | ten64.welland.mithis.com       |
| Desktop     | 10.12.X.X  | /16       | 2404:e80:a137:1200:: | /56       | desktop.welland.mithis.com     |
| big-storage | 10.15.X.X  | /16       | 2404:e80:a137:1500:: | /56       | big-storage.welland.mithis.com |
| gpu         | 10.16.X.X  | /16       | 2404:e80:a137:1600:: | /56       | gpu.welland.mithis.com         |

## Welland Site Configuration

### Core Networks

+------------------------------+------+------------+-----------+---------------------+-----------+-----------+-------------------------------+
| Network                      | VLAN | IPv4 Range | IPv4 CIDR | IPv6 (Launtel)      | IPv6 CIDR | Subdomain | Description                   |
|------------------------------+------+------------+-----------+---------------------+-----------+-----------+-------------------------------|
| Internal Network             | -    | 10.1.X.X   | /16       | 2404:e80:a137:100:: | /56       | -         | Main internal network         |
|------------------------------+------+------------+-----------+---------------------+-----------+-----------+-------------------------------|
| Quarantine Network           | 1    | 10.1.1.X   | /24       | 2404:e80:a137:101:: | /64       | tmp       | Temporary/quarantine          |
|------------------------------+------+------------+-----------+---------------------+-----------+-----------+-------------------------------|
| Network Management           | 5    | 10.1.5.X   | /24       | 2404:e80:a137:105:: | /64       | net       | Switches, config interfaces   |
| Power Management             | 6    | 10.1.6.X   | /24       | 2404:e80:a137:106:: | /64       | pwr       | UPSs, etc.                    |
| Internal Storage             | 7    | 10.1.7.X   | /24       | 2404:e80:a137:107:: | /64       | -         | NVMe over Ethernet, RDMA      |
|------------------------------|------|------------|-----------|---------------------|-----------|-----------|-------------------------------|
| Internal Wired Simple Hosts  | 10   | 10.1.10.X  | /21       | 2404:e80:a137:110:: | /60       | int       | Simple wired hosts            |
| Internal Wired Complex Hosts | 10   | 10.1.11.X  | /21       | 2404:e80:a137:111:: | /60       | -         | Complex hosts with interfaces |
| 25G Backbone Switch          | 10   | 10.1.15.X  | /21       | 2404:e80:a137:115:: | /60       | 25g       | Mellanox SN2410               |
| 100G Backbone Switch         | 10   | 10.1.16.X  | /21       | 2404:e80:a137:116:: | /60       | 100g      | Mellanox SN2700               |
+------------------------------+------+------------+-----------+---------------------+-----------+-----------+-------------------------------+

### Wireless Networks

+-----------------+------+-------------+-----------+------------------------+-----------+-----------+-----------+
| Network         | VLAN | IPv4 Range  | IPv4 CIDR | IPv6 (Launtel)         | IPv6 CIDR | Subdomain | Interface |
|-----------------+------+-------------+-----------+------------------------+-----------+-----------+-----------|
| Roaming Network | 20   | 10.1.20.X   | /24       | 2404:e80:a137:120::    | /64       | roam      | wlan1     |
| - Personal      | 20   | 10.1.20.1X  | /24       | 2404:e80:a137:120::1X  | /128      | -         | -         |
| - Friends       | 20   | 10.1.20.3X  | /24       | 2404:e80:a137:120::3X  | /128      | -         | -         |
| - Work          | 20   | 10.1.20.5X  | /24       | 2404:e80:a137:120::5X  | /128      | -         | -         |
|-----------------|------|-------------|-----------|------------------------|-----------|-----------|-----------|
| IoT Network     | 90   | 10.1.90.X   | /24       | 2404:e80:a137:190::    | /64       | iot       | wlan0     |
|-----------------|------|-------------|-----------|------------------------|-----------|-----------|-----------|
| Guest Network   | 99   | 10.1.99.X   | /24       | 2404:e80:a137:199::    | /64       | guest     | -         |
+-----------------+------+-------------+-----------+------------------------+-----------+-----------+-----------+

### Complex Host Interfaces (Welland)

| Host        | VLAN | IPv4 Interfaces | IPv4 CIDR | IPv6 Interfaces        | IPv6 CIDR | Subdomain   |
|-------------|------|-----------------|-----------|------------------------|-----------|-------------|
| ten64       | 10   | 10.1.11.10X     | /21       | 2404:e80:a137:111::10X | /128      | ten64       |
| desktop     | 10   | 10.1.11.12X     | /21       | 2404:e80:a137:111::12X | /128      | desktop     |
| big-storage | 10   | 10.1.11.15X     | /21       | 2404:e80:a137:111::15X | /128      | big-storage |
| gpu         | 10   | 10.1.11.16X     | /21       | 2404:e80:a137:111::16X | /128      | gpu         |

## VPN Networks

| VPN             | IPv4 Range    | IPv4 CIDR | Config File                         |
|-----------------|---------------|-----------|-------------------------------------|
| VPN K207        | 192.168.176.X | /24       | fritzbox_k207_mithis_com.cfg        |
| VPN Monarto     | 192.168.177.X | /24       | fritzbox_monarto_mithis_com.cfg     |
| VPN 38Arlington | 192.168.179.X | /24       | fritzbox_38arlington_mithis_com.cfg |

## Other Networks (Non-routed)

| Network           | IPv4 Range   | IPv4 CIDR |
|-------------------|--------------|-----------|
| Google WiFi       | 192.168.86.X | /24       |
| Docker on Desktop | 172.17.0.X   | /24       |

## Examples

### Simple Host

```
IPv4:  10.1.10.12
IPv6:  2404:e80:a137:110::12
```

### Complex Host with Multiple Interfaces

```
Interface 0: 10.1.10.120 → 2404:e80:a137:110::120
Interface 4: 10.1.10.124 → 2404:e80:a137:110::124
```

### Complex Host VM Networks

```
VM Networks:  10.12.X.X   → 2404:e80:a137:1200::/56
VM Net 1:     10.12.1.X   → 2404:e80:a137:1201::/64
VM Net 11:    10.12.11.X  → 2404:e80:a137:1211::/64
VM on Net 1:  10.12.1.3   → 2404:e80:a137:1201::3
```
