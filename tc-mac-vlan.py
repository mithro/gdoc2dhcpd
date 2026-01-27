#!/usr/bin/env python3
"""Legacy shim — delegates to gdoc2netcfg package.

Usage:
    ./tc-mac-vlan.py                    # Generate tc rules (stdout)

Equivalent to: uv run gdoc2netcfg generate tc_mac_vlan --stdout
"""

import sys

from gdoc2netcfg.cli.main import main

if __name__ == "__main__":
    sys.exit(main(["generate", "--stdout", "tc_mac_vlan"]))
