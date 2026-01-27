# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Test Commands

```bash
uv run pytest                           # Run all tests (235 tests)
uv run pytest tests/test_models/        # Run tests for a specific module
uv run pytest tests/test_models/test_addressing.py::test_mac_parse  # Run single test
uv run pytest -x                        # Stop on first failure
uv run ruff check src/ tests/           # Lint
uv run gdoc2netcfg fetch                # Download CSVs from Google Sheets
uv run gdoc2netcfg generate dnsmasq     # Generate dnsmasq config
uv run gdoc2netcfg sshfp --force        # Scan SSH fingerprints
uv run gdoc2netcfg validate             # Run constraint validation
```

Always use `uv run` to execute Python commands. Never use bare `python` or `pip`.

## Architecture

`gdoc2netcfg` reads network device data from a Google Spreadsheet and generates configuration files for network infrastructure services (dnsmasq, Cisco SG300, Linux tc, Nagios).

### Pipeline

The system is a six-stage data pipeline in `src/gdoc2netcfg/`:

```
Sources (sources/)     Fetch CSV from Google Sheets, cache locally, parse into DeviceRecord
    │
Derivations (derivations/)  Pure functions: IPv4→IPv6, IP→VLAN, hostname, DHCP name, default IP
    │                        host_builder.py orchestrates these into Host objects
Supplements (supplements/)  External enrichment: SSHFP scanning via ssh-keyscan (cached)
    │
Constraints (constraints/)  Validation: field presence, BMC placement, MAC uniqueness
    │
Generators (generators/)    Output: dnsmasq, dnsmasq_external, cisco_sg300, tc_mac_vlan, nagios
    │
Config files               dnsmasq.static.conf, dnsmasq.external.conf, etc.
```

The CLI (`cli/main.py`) wires the pipeline via `_build_pipeline()` which returns `(records, hosts, inventory, validation_result)`. Generators receive a `NetworkInventory` — the fully enriched model with all derivations applied.

### Key Data Flow

1. `sources/parser.py` parses CSV rows into `DeviceRecord` (machine, mac, ip, interface)
2. `derivations/host_builder.py::build_hosts()` groups records by machine name into `Host` objects, each with multiple `NetworkInterface` entries
3. `build_inventory()` creates `NetworkInventory` with precomputed `ip_to_hostname` and `ip_to_macs` indexes
4. Generators consume `NetworkInventory` to produce config text

### BMC Handling

BMCs (Baseboard Management Controllers) are physically separate machines attached to a primary host. When a spreadsheet row has interface="bmc" on machine="big-storage", `build_hosts()` creates a separate host `bmc.big-storage` — not a sub-interface. The BMC gets its own hostname, DNS records, DHCP binding, and PTR entry.

### IPv4→IPv6 Mapping

Dual-stack addressing uses the scheme: `10.AA.BB.CCC` → `{prefix}AABB::CCC` where AA is unpadded and BB is zero-padded to 2 digits. Prefixes are configured in `gdoc2netcfg.toml` under `[ipv6]`.

### Split-Horizon DNS

The dnsmasq generator has internal and external variants. External (`dnsmasq_external.py`) replaces RFC 1918 IPs with the site's public IPv4 address for external-facing DNS.

### Configuration

`gdoc2netcfg.toml` defines site topology (domain, VLANs, IPv6 prefixes, network subdomains), sheet URLs, cache directory, and generator settings. Loaded by `config.py` into a `PipelineConfig` dataclass containing a `Site` object.

### Models

- `MACAddress`, `IPv4Address`, `IPv6Address` — frozen, validated, normalized value types in `models/addressing.py`
- `Host` — groups `NetworkInterface` entries for one machine, with default IP selection
- `NetworkInventory` — the complete enriched model passed to generators

### Legacy Shims

Root-level scripts (`dnsmasq.py`, `sshfp.py`, `nagios.py`, `tc-mac-vlan.py`, `cisco-sg300-vlan.py`) are thin wrappers that delegate to the CLI. They exist for backward compatibility with production scripts.

## Production Deployment

This runs on `ten64.welland.mithis.com` at `/etc/gdoc2dhcpd/`. Generated configs are symlinked into `/etc/dnsmasq.d/internal/` and `/etc/dnsmasq.d/external/`. The SSHFP cache lives at `.cache/sshfp.json`.
