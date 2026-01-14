#!/usr/bin/env python3
"""
Generate Cisco SG300 MAC-based VLAN configuration

Usage:
    ./cisco-sg300-vlan.py              # Show configuration to stdout
    ./cisco-sg300-vlan.py --deploy     # Write to /srv/tftp/cisco/sg300-config.txt
"""

import json
import sys
import os

# IP subnet to VLAN mapping
VLAN_NAMES = {
    1: 'tmp',
    5: 'net',
    6: 'pwr',
    10: 'int',
    20: 'roam',
    31: 'sm',
    41: 'fpgas',
    90: 'iot',
    99: 'guest',
}

def ip_to_vlan(ip_str):
    """Convert IP address to VLAN ID."""
    parts = [int(x) for x in ip_str.split('.')]
    if len(parts) != 4:
        return None

    a, b, c, d = parts

    if a != 10:
        return None

    # Check for non-1 second octet (sm, fpgas)
    if b == 31:
        return 31
    if b == 41:
        return 41

    if b != 1:
        return None

    # 10.1.X.Y - check third octet
    if c == 1:
        return 1   # tmp
    if c == 5:
        return 5   # net
    if c == 6:
        return 6   # pwr
    if c == 20:
        return 20  # roam
    if c == 90:
        return 90  # iot
    if c == 99:
        return 99  # guest

    # 10.1.10-17.x = br-int (VLAN 10)
    if 10 <= c <= 17:
        return 10

    return None

def load_macs():
    """Load MAC addresses from macs.json."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    macs_file = os.path.join(script_dir, 'macs.json')

    with open(macs_file) as f:
        return json.load(f)

def get_mac_vlan_mappings():
    """Get all MAC to VLAN mappings."""
    macs_data = load_macs()
    seen_macs = {}  # mac -> first occurrence info
    duplicates = []
    mappings = []

    for ip, mac_list in macs_data.items():
        vlan = ip_to_vlan(ip)
        if vlan is None:
            continue

        for mac_info in mac_list:
            mac = mac_info[0].lower()
            name = mac_info[1] if len(mac_info) > 1 else ''

            # Skip bridge MACs (these are our own interfaces)
            if mac.startswith('02:00:0a:01:'):
                continue

            # Check for duplicates
            if mac in seen_macs:
                duplicates.append({
                    'mac': mac,
                    'ip': ip,
                    'name': name,
                    'first_ip': seen_macs[mac]['ip'],
                    'first_name': seen_macs[mac]['name'],
                })
                continue

            entry = {
                'mac': mac,
                'ip': ip,
                'vlan': vlan,
                'vlan_name': VLAN_NAMES.get(vlan, str(vlan)),
                'name': name,
            }
            seen_macs[mac] = entry
            mappings.append(entry)

    # Error on duplicates
    if duplicates:
        print(f"ERROR: {len(duplicates)} duplicate MAC(s) in macs.json:", file=sys.stderr)
        for d in duplicates:
            print(f"  {d['mac']}: {d['ip']} ({d['name']}) duplicates {d['first_ip']} ({d['first_name']})", file=sys.stderr)
        sys.exit(1)

    return mappings

def mac_to_cisco_format(mac):
    """Convert MAC address to Cisco SG300 running-config format (xx:xx:xx:xx:xx:xx)."""
    # SG300 running-config uses colon-separated lowercase format
    return mac.lower()

def mac_to_int(mac):
    """Convert MAC address to integer for prefix calculations."""
    clean = mac.replace(':', '').lower()
    return int(clean, 16)

def int_to_mac(val):
    """Convert integer back to MAC address format."""
    hex_str = f'{val:012x}'
    return ':'.join(hex_str[i:i+2] for i in range(0, 12, 2))

def get_prefix(mac, prefix_bits):
    """Get the prefix of a MAC address at given bit length."""
    mac_int = mac_to_int(mac)
    # Mask off the lower bits
    mask = (0xffffffffffff << (48 - prefix_bits)) & 0xffffffffffff
    return mac_int & mask

def optimize_mac_entries(mappings):
    """Find common prefixes within each VLAN to reduce MAC entry count.

    Returns list of (mac, prefix_bits, vlan, names) tuples.
    """
    # Group by VLAN first
    by_vlan = {}
    for m in mappings:
        vlan = m['vlan']
        if vlan not in by_vlan:
            by_vlan[vlan] = []
        by_vlan[vlan].append(m)

    # Collect all MACs across all VLANs for conflict checking
    all_macs = {m['mac']: m['vlan'] for m in mappings}

    optimized = []

    for vlan, macs in by_vlan.items():
        # Try to find common prefixes at different lengths
        # 40 bits = 5 octets, 32 bits = 4 octets, 24 bits = 3 octets (OUI)
        remaining = set(m['mac'] for m in macs)
        mac_to_entry = {m['mac']: m for m in macs}

        for prefix_bits in [40, 32, 24]:
            if not remaining:
                break

            # Group remaining MACs by their prefix at this length
            prefix_groups = {}
            for mac in remaining:
                prefix = get_prefix(mac, prefix_bits)
                if prefix not in prefix_groups:
                    prefix_groups[prefix] = []
                prefix_groups[prefix].append(mac)

            # Use prefixes that match 2+ MACs and don't conflict with other VLANs
            for prefix, group_macs in prefix_groups.items():
                if len(group_macs) < 2:
                    continue

                # Check if this prefix would match any MAC from a different VLAN
                conflict = False
                for other_mac, other_vlan in all_macs.items():
                    if other_vlan != vlan:
                        if get_prefix(other_mac, prefix_bits) == prefix:
                            conflict = True
                            break

                if conflict:
                    continue

                # Use this prefix - it matches multiple MACs in same VLAN only
                prefix_mac = int_to_mac(prefix)
                names = [mac_to_entry[m]['name'] for m in sorted(group_macs)]
                optimized.append({
                    'mac': prefix_mac,
                    'prefix_bits': prefix_bits,
                    'vlan': vlan,
                    'names': names,
                    'count': len(group_macs),
                })
                remaining -= set(group_macs)

        # Add remaining MACs as individual /48 entries
        for mac in sorted(remaining):
            entry = mac_to_entry[mac]
            optimized.append({
                'mac': mac,
                'prefix_bits': 48,
                'vlan': vlan,
                'names': [entry['name']],
                'count': 1,
            })

    return optimized

def generate_cisco_config(mappings, interfaces=None, clear_first=True):
    """Generate Cisco SG300 MAC-based VLAN configuration.

    SG300 MAC-based VLAN requires:
    1. Create MAC-to-group mappings in vlan database mode
    2. Map groups to VLANs on each interface in general mode

    We use VLAN ID as group ID for simplicity.

    If clear_first=True, generates 'no map mac' commands to remove all
    existing MAC entries before adding optimized ones.
    """
    if interfaces is None:
        # Default: all gigabit ports
        interfaces = [f'gi{i}' for i in range(1, 29)]

    # Optimize MAC entries by finding common prefixes
    optimized = optimize_mac_entries(mappings)

    lines = [
        '! Cisco SG300 MAC-based VLAN configuration',
        '! Generated by cisco-sg300-vlan.py',
        f'! {len(mappings)} MACs optimized to {len(optimized)} entries',
        '!',
    ]

    # Group optimized entries by VLAN
    by_vlan = {}
    for entry in optimized:
        vlan = entry['vlan']
        if vlan not in by_vlan:
            by_vlan[vlan] = []
        by_vlan[vlan].append(entry)

    # Step 1: Create VLANs and MAC-to-group mappings in vlan database
    lines.append('vlan database')

    # First create all needed VLANs (just the number, no name parameter)
    lines.append('! Create VLANs')
    for vlan in sorted(by_vlan.keys()):
        lines.append(f'vlan {vlan}')

    # Clear all existing MAC-to-group mappings before adding new ones
    # This is needed because the switch has a 256 entry limit
    if clear_first:
        lines.append('')
        lines.append('! Clear all existing MAC mappings (original /48 entries)')
        for m in sorted(mappings, key=lambda x: x['mac']):
            mac = mac_to_cisco_format(m['mac'])
            lines.append(f'no map mac {mac} 48')

    lines.append('')
    lines.append('! MAC-to-group mappings (prefix/48=exact, /32=4 octets, /24=OUI)')
    for vlan in sorted(by_vlan.keys()):
        vlan_name = VLAN_NAMES.get(vlan, f'vlan{vlan}')
        lines.append(f'! Group {vlan} = VLAN {vlan} ({vlan_name})')

        for entry in sorted(by_vlan[vlan], key=lambda x: x['mac']):
            mac = mac_to_cisco_format(entry['mac'])
            prefix_bits = entry['prefix_bits']
            lines.append(f'map mac {mac} {prefix_bits} macs-group {vlan}')

    lines.append('exit')
    lines.append('')

    # Step 2: Map groups to VLANs on interfaces
    lines.append('! Interface configuration - map macs-groups to VLANs')
    lines.append('! Interfaces must be in general mode')

    for iface in interfaces:
        lines.append(f'interface {iface}')
        lines.append('switchport mode general')
        # First add interface to all VLANs as tagged member
        for vlan in sorted(by_vlan.keys()):
            lines.append(f'switchport general allowed vlan add {vlan} tagged')
        # Then map macs-groups to VLANs
        for vlan in sorted(by_vlan.keys()):
            lines.append(f'switchport general map macs-group {vlan} vlan {vlan}')
        lines.append('exit')

    lines.append('')
    lines.append('end')
    lines.append('!')
    lines.append('! To save permanently: write memory')

    return '\n'.join(lines)

def main():
    mappings = get_mac_vlan_mappings()
    optimized = optimize_mac_entries(mappings)
    config = generate_cisco_config(mappings)

    # SG300 has a 256 MAC-to-group mapping limit
    MAC_LIMIT = 256
    entry_count = len(optimized)

    if entry_count > MAC_LIMIT:
        print(f"WARNING: {entry_count} entries exceeds SG300 limit of {MAC_LIMIT}", file=sys.stderr)
        print(f"         Last {entry_count - MAC_LIMIT} entries will be dropped by switch", file=sys.stderr)

    if '--deploy' in sys.argv:
        deploy_path = '/srv/tftp/cisco/sg300-config.txt'
        os.makedirs(os.path.dirname(deploy_path), exist_ok=True)
        with open(deploy_path, 'w') as f:
            f.write(config)
        print(f"Configuration written to {deploy_path}")
        print(f"Total: {len(mappings)} MACs -> {entry_count} entries (saved {len(mappings) - entry_count})")

        # Show prefix usage stats
        prefix_stats = {}
        for e in optimized:
            bits = e['prefix_bits']
            prefix_stats[bits] = prefix_stats.get(bits, 0) + 1
        for bits in sorted(prefix_stats.keys()):
            print(f"  /{bits}: {prefix_stats[bits]} entries")
    else:
        print(config)

if __name__ == '__main__':
    main()
