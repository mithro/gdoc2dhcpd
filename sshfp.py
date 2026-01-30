#!/usr/bin/env python3
"""Legacy shim — delegates to gdoc2netcfg package.

Usage: ./sshfp.py [--force]
  Scans hosts for SSH fingerprints and regenerates dnsmasq internal config.
  Equivalent to: uv run gdoc2netcfg sshfp [--force] && uv run gdoc2netcfg generate dnsmasq_internal
"""

import sys

from gdoc2netcfg.cli.main import main

if __name__ == "__main__":
    args = ["sshfp"]
    if "--force" in sys.argv:
        args.append("--force")
    result = main(args)
    if result != 0:
        sys.exit(result)
    # Regenerate dnsmasq config with updated SSHFP data
    sys.exit(main(["generate", "dnsmasq_internal"]))
