#!/bin/bash
# Apply MAC-based VLAN rules from gdoc2dhcpd data
# This script generates tc rules from macs.json and applies them

set -e

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
TC_RULES="$SCRIPT_DIR/mac-vlan-tc.sh"

# Generate tc rules
"$SCRIPT_DIR/tc-mac-vlan.py" --tc > "$TC_RULES"
chmod +x "$TC_RULES"

# Apply tc rules
"$TC_RULES"

echo "MAC-based VLAN rules applied from $TC_RULES"
