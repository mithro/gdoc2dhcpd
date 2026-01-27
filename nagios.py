#!/usr/bin/env python3
"""Legacy shim — delegates to gdoc2netcfg package.

Usage: ./nagios.py
  Generates Nagios monitoring configuration for switches.
  Equivalent to: uv run gdoc2netcfg generate nagios --stdout
"""

import sys

from gdoc2netcfg.cli.main import main

if __name__ == "__main__":
    sys.exit(main(["generate", "--stdout", "nagios"]))
