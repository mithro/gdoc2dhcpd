# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Test Commands

```bash
uv run pytest                           # Run all tests (423 tests)
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

`gdoc2netcfg` reads network device data from a Google Spreadsheet and generates configuration files for network infrastructure services (dnsmasq, Nagios, nginx).

### Pipeline

The system is a six-stage data pipeline in `src/gdoc2netcfg/`:

```
Sources (sources/)     Fetch CSV from Google Sheets, cache locally, parse into DeviceRecord
    │
Derivations (derivations/)  Pure functions: IPv4→IPv6, IP→VLAN, hostname, DHCP name, DNS names, default IP
    │                        host_builder.py orchestrates these into Host objects
Supplements (supplements/)  External enrichment: SSHFP scanning via ssh-keyscan, SSL cert scanning (cached)
    │
Constraints (constraints/)  Validation: field presence, BMC placement, MAC uniqueness, IPv6 consistency
    │
Generators (generators/)    Output: dnsmasq_internal, dnsmasq_external, nagios, nginx
    │
Config files               Per-host .conf files in output directories
```

The CLI (`cli/main.py`) wires the pipeline via `_build_pipeline()` which returns `(records, hosts, inventory, validation_result)`. Generators receive a `NetworkInventory` — the fully enriched model with all derivations applied.

### Key Data Flow

1. `sources/parser.py` parses CSV rows into `DeviceRecord` (machine, mac, ip, interface)
2. `derivations/host_builder.py::build_hosts()` groups records by machine name into `Host` objects, each with multiple `NetworkInterface` entries
3. `derivations/dns_names.py::derive_all_dns_names()` computes all DNS name variants per host (hostname, interface, subdomain, ipv4/ipv6 prefix variants)
4. `build_inventory()` creates `NetworkInventory` with precomputed `ip_to_hostname` and `ip_to_macs` indexes
5. Generators consume `NetworkInventory` to produce config files

### BMC Handling

BMCs (Baseboard Management Controllers) are physically separate machines attached to a primary host. When a spreadsheet row has interface="bmc" on machine="big-storage", `build_hosts()` creates a separate host `bmc.big-storage` — not a sub-interface. The BMC gets its own hostname, DNS records, DHCP binding, and PTR entry.

### IPv4→IPv6 Mapping

Dual-stack addressing uses the scheme: `10.AA.BB.CCC` → `{prefix}AABB::CCC` where AA is unpadded and BB is zero-padded to 2 digits. Prefixes are configured in `gdoc2netcfg.toml` under `[ipv6]`.

### Split-Horizon DNS

The dnsmasq generator has internal and external variants. External (`dnsmasq_external.py`) replaces RFC 1918 IPs with the site's public IPv4 address for external-facing DNS.

### Nginx Reverse Proxy

The nginx generator (`nginx.py`) produces per-host reverse proxy server blocks under `sites-available/`. Each host gets four config file variants: `{fqdn}-http-public`, `{fqdn}-http-private`, `{fqdn}-https-public`, `{fqdn}-https-private`.

Multi-interface hosts get a combined config file (per variant) containing an `upstream` block listing all interface IPs for round-robin failover with `proxy_next_upstream`, a root server block using the upstream, and per-interface server blocks with direct `proxy_pass`. Single-interface hosts produce simple direct `proxy_pass` configs.

### Configuration

`gdoc2netcfg.toml` defines site topology (domain, VLANs, IPv6 prefixes, network subdomains), sheet URLs, cache directory, and generator settings. Loaded by `config.py` into a `PipelineConfig` dataclass containing a `Site` object.

### Models

- `MACAddress`, `IPv4Address`, `IPv6Address` — frozen, validated, normalized value types in `models/addressing.py`
- `Host` — groups `NetworkInterface` entries for one machine, with default IP selection
- `NetworkInventory` — the complete enriched model passed to generators

### Legacy Shims

Root-level scripts (`dnsmasq.py`, `sshfp.py`, `nagios.py`) are thin wrappers that delegate to the CLI. They exist for backward compatibility with production scripts.

## Production Deployment

This runs on `ten64.welland.mithis.com` at `/opt/gdoc2netcfg/`. Generated dnsmasq configs are symlinked into `/etc/dnsmasq.d/internal/` and `/etc/dnsmasq.d/external/`. Generated nginx configs are written to `/etc/nginx/sites-available/` and activated via symlinks in `/etc/nginx/sites-enabled/`. The SSHFP cache lives at `.cache/sshfp.json`.
