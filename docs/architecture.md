# Architecture

`gdoc2netcfg` is a six-stage data pipeline that transforms Google Spreadsheet device records into network infrastructure configuration files.

## Pipeline stages

```
Sources (sources/)          Fetch CSV from Google Sheets, cache locally, parse into DeviceRecord
    │
Derivations (derivations/)  Pure functions: IPv4→IPv6, IP→VLAN, hostname, DHCP name, DNS names, default IP
    │                        host_builder.py orchestrates these into Host objects
Supplements (supplements/)  External enrichment: SSHFP scanning via ssh-keyscan, SSL cert scanning (cached)
    │
Constraints (constraints/)  Validation: field presence, BMC placement, MAC uniqueness, IPv6 consistency
    │
Generators (generators/)    Output: dnsmasq_internal, dnsmasq_external, nagios, nginx, letsencrypt
    │
Config files                Per-host .conf files in output directories
```

## Data flow

1. `sources/parser.py` parses CSV rows into `DeviceRecord` (machine, mac, ip, interface)
2. `derivations/host_builder.py::build_hosts()` groups records by machine name into `Host` objects, each with multiple `NetworkInterface` entries
3. `derivations/dns_names.py::derive_all_dns_names()` computes all DNS name variants per host (hostname, interface, subdomain, ipv4/ipv6 prefix variants)
4. `build_inventory()` creates `NetworkInventory` with precomputed `ip_to_hostname` and `ip_to_macs` indexes
5. Generators consume `NetworkInventory` to produce config files

## Key models

All models live in `src/gdoc2netcfg/models/`:

- **`MACAddress`, `IPv4Address`, `IPv6Address`** -- frozen, validated, normalised value types (`models/addressing.py`)
- **`NetworkInterface`** -- a single interface on a host (MAC, IPv4, IPv6 addresses, VLAN, DHCP name)
- **`Host`** -- groups `NetworkInterface` entries for one machine, with default IP, DNS names, SSHFP records
- **`NetworkInventory`** -- the complete enriched model passed to generators, with precomputed lookup indexes
- **`Site`** -- site topology (domain, VLANs, IPv6 prefixes, network subdomains)

## BMC handling

BMCs (Baseboard Management Controllers) are physically separate machines attached to a primary host. When a spreadsheet row has `interface="bmc"` on `machine="big-storage"`, `build_hosts()` creates a separate host `bmc.big-storage` -- not a sub-interface. The BMC gets its own hostname, DNS records, DHCP binding, and PTR entry.

## IPv4 to IPv6 mapping

Dual-stack addressing uses the scheme:

```
10.AA.BB.CCC  →  {prefix}AABB::CCC
```

Where `AA` is unpadded and `BB` is zero-padded to 2 digits. Prefixes are configured in `gdoc2netcfg.toml` under `[ipv6]`. See [ipv4-to-ipv6.md](ipv4-to-ipv6.md) for the full specification.

## Split-horizon DNS

The dnsmasq generator has internal and external variants:

- **Internal** (`dnsmasq.py`) -- produces DHCP bindings, PTR records, forward DNS records, CAA records, and SSHFP records using internal RFC 1918 addresses
- **External** (`dnsmasq_external.py`) -- replaces RFC 1918 IPs with the site's public IPv4 address for external-facing DNS. Does not emit DHCP or PTR records (internal IPs aren't routable externally)

Both generators produce per-host `.conf` files (one file per host).

## Configuration

`gdoc2netcfg.toml` defines site topology (domain, VLANs, IPv6 prefixes, network subdomains), sheet URLs, cache directory, and generator settings. Loaded by `config.py` into a `PipelineConfig` dataclass containing a `Site` object.

## Source layout

```
src/gdoc2netcfg/
├── cli/            CLI entry point and subcommands
├── config.py       TOML config loader
├── models/         Data models (addressing, host, network)
├── sources/        CSV fetching, caching, parsing
├── derivations/    Pure derivation functions
├── supplements/    External data enrichment (SSHFP, SSL)
├── constraints/    Validation checks
├── generators/     Output generators
├── utils/          Shared utilities (IP helpers, DNS utils)
└── audit/          Audit trail utilities
```
