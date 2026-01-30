#!/usr/bin/env python3
"""Legacy shim — delegates to gdoc2netcfg package.

Usage: ./dnsmasq.py
  Fetches data from Google Sheets and generates dnsmasq internal config.
  Equivalent to: uv run gdoc2netcfg fetch && uv run gdoc2netcfg generate dnsmasq_internal
"""

import sys

from gdoc2netcfg.cli.main import main

if __name__ == "__main__":
    # First fetch fresh data, then generate dnsmasq config
    result = main(["fetch"])
    if result != 0:
        sys.exit(result)
    sys.exit(main(["generate", "dnsmasq_internal"]))
