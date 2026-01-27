#!/usr/bin/env python3
"""Legacy shim — delegates to gdoc2netcfg package.

Usage:
    ./cisco-sg300-vlan.py              # Show configuration to stdout
    ./cisco-sg300-vlan.py --deploy     # Write to /srv/tftp/cisco/sg300-config.txt

Equivalent to: uv run gdoc2netcfg generate cisco_sg300
"""

import sys

from gdoc2netcfg.cli.main import main

if __name__ == "__main__":
    args = ["generate"]
    if "--deploy" in sys.argv:
        args.append("cisco_sg300")
    else:
        args.extend(["--stdout", "cisco_sg300"])
    sys.exit(main(args))
