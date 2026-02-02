"""CLI entry point for gdoc2netcfg.

Subcommands:
    fetch      Download CSVs from Google Sheets to local cache.
    generate   Run the pipeline and produce output config files.
    validate   Run constraint checks on the data.
    info       Show pipeline configuration.
    sshfp      Scan hosts for SSH fingerprints.
    snmp       Scan hosts for SNMP data.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _load_config(args: argparse.Namespace):
    """Load pipeline config, handling errors."""
    from gdoc2netcfg.config import load_config

    config_path = getattr(args, "config", None)
    try:
        return load_config(config_path)
    except FileNotFoundError:
        path = config_path or "gdoc2netcfg.toml"
        print(f"Error: config file not found: {path}", file=sys.stderr)
        sys.exit(1)


def _fetch_or_load_csvs(config, use_cache: bool = False):
    """Fetch CSVs from sheets or read from cache.

    Returns list of (name, csv_text) tuples.
    """
    from gdoc2netcfg.sources.cache import CSVCache
    from gdoc2netcfg.sources.sheets import fetch_sheet

    cache = CSVCache(config.cache.directory)
    results = []

    for sheet in config.sheets:
        if use_cache and cache.has(sheet.name):
            csv_text = cache.read(sheet.name)
            results.append((sheet.name, csv_text))
        else:
            try:
                data = fetch_sheet(sheet.name, sheet.url)
                cache.write(sheet.name, data.csv_text)
                results.append((sheet.name, data.csv_text))
            except Exception as e:
                print(f"Warning: failed to fetch sheet {sheet.name!r}: {e}", file=sys.stderr)
                if cache.has(sheet.name):
                    print(f"  Using cached version of {sheet.name!r}", file=sys.stderr)
                    csv_text = cache.read(sheet.name)
                    results.append((sheet.name, csv_text))

    return results


def _enrich_site_from_vlan_sheet(config, csv_data: list[tuple[str, str]]) -> None:
    """Parse the VLAN Allocations sheet and populate site VLANs/subdomains.

    Finds the 'vlan_allocations' CSV in csv_data, parses it, builds
    VLAN objects and network_subdomains, and updates config.site in place.
    """
    from gdoc2netcfg.derivations.vlan import build_network_subdomains, build_vlans_from_definitions
    from gdoc2netcfg.sources.vlan_parser import parse_vlan_allocations

    vlan_csv = None
    for name, text in csv_data:
        if name == "vlan_allocations":
            vlan_csv = text
            break

    if vlan_csv is None:
        print("Warning: no vlan_allocations sheet found, VLANs not configured", file=sys.stderr)
        return

    definitions = parse_vlan_allocations(vlan_csv)
    if not definitions:
        print("Warning: vlan_allocations sheet is empty", file=sys.stderr)
        return

    vlans = build_vlans_from_definitions(definitions, config.site.site_octet)
    subdomains = build_network_subdomains(vlans)

    config.site.vlans = vlans
    config.site.network_subdomains = subdomains


def _build_pipeline(config):
    """Run the full build pipeline: parse → derive → validate → enrich.

    Returns (records, hosts, inventory, validation_result).
    """
    from gdoc2netcfg.constraints.validators import validate_all
    from gdoc2netcfg.derivations.host_builder import build_hosts, build_inventory
    from gdoc2netcfg.sources.parser import parse_csv
    from gdoc2netcfg.supplements.snmp import enrich_hosts_with_snmp, load_snmp_cache
    from gdoc2netcfg.supplements.sshfp import enrich_hosts_with_sshfp, load_sshfp_cache
    from gdoc2netcfg.supplements.ssl_certs import enrich_hosts_with_ssl_certs, load_ssl_cert_cache

    # Fetch or load CSVs
    csv_data = _fetch_or_load_csvs(config, use_cache=True)

    # Enrich site config from VLAN Allocations sheet
    _enrich_site_from_vlan_sheet(config, csv_data)

    # Parse device records (exclude vlan_allocations — not a device sheet)
    all_records = []
    for name, csv_text in csv_data:
        if name == "vlan_allocations":
            continue
        records = parse_csv(csv_text, name)
        all_records.extend(records)

    if not all_records:
        print("Error: no device records found in any sheet.", file=sys.stderr)
        sys.exit(1)

    # Build hosts (applies all derivations)
    hosts = build_hosts(all_records, config.site)

    # Build inventory (aggregate derivations)
    inventory = build_inventory(hosts, config.site)

    # Load SSHFP cache and enrich (don't scan — that's a separate subcommand)
    sshfp_cache = Path(config.cache.directory) / "sshfp.json"
    sshfp_data = load_sshfp_cache(sshfp_cache)
    enrich_hosts_with_sshfp(hosts, sshfp_data)

    # Load SSL cert cache and enrich (don't scan — that's a separate subcommand)
    ssl_cache = Path(config.cache.directory) / "ssl_certs.json"
    ssl_data = load_ssl_cert_cache(ssl_cache)
    enrich_hosts_with_ssl_certs(hosts, ssl_data)

    # Load SNMP cache and enrich (don't scan — that's a separate subcommand)
    snmp_cache = Path(config.cache.directory) / "snmp.json"
    snmp_data = load_snmp_cache(snmp_cache)
    enrich_hosts_with_snmp(hosts, snmp_data)

    # Load bridge cache and enrich (don't scan — that's a separate subcommand)
    from gdoc2netcfg.supplements.bridge import enrich_hosts_with_bridge_data
    from gdoc2netcfg.supplements.snmp_common import load_json_cache

    bridge_cache_path = Path(config.cache.directory) / "bridge.json"
    bridge_cache = load_json_cache(bridge_cache_path)
    enrich_hosts_with_bridge_data(hosts, bridge_cache)

    # Validate
    result = validate_all(all_records, hosts, inventory)

    return all_records, hosts, inventory, result


# ---------------------------------------------------------------------------
# Subcommand: fetch
# ---------------------------------------------------------------------------

def cmd_fetch(args: argparse.Namespace) -> int:
    """Download CSVs from Google Sheets to local cache."""
    config = _load_config(args)

    from gdoc2netcfg.sources.cache import CSVCache
    from gdoc2netcfg.sources.sheets import fetch_sheet

    cache = CSVCache(config.cache.directory)
    ok = 0
    fail = 0

    for sheet in config.sheets:
        try:
            data = fetch_sheet(sheet.name, sheet.url)
            cache.write(sheet.name, data.csv_text)
            print(f"  {sheet.name}: fetched ({len(data.csv_text)} bytes)")
            ok += 1
        except Exception as e:
            print(f"  {sheet.name}: FAILED ({e})", file=sys.stderr)
            fail += 1

    print(f"\nFetched {ok} sheets, {fail} failures.")
    return 1 if fail > 0 else 0


# ---------------------------------------------------------------------------
# Subcommand: generate
# ---------------------------------------------------------------------------

def _get_generator(name: str):
    """Get a generator function by name."""
    generators = {
        "dnsmasq_internal": ("gdoc2netcfg.generators.dnsmasq", "generate_dnsmasq_internal"),
        "dnsmasq_external": (
            "gdoc2netcfg.generators.dnsmasq_external",
            "generate_dnsmasq_external",
        ),
        "nagios": ("gdoc2netcfg.generators.nagios", "generate_nagios"),
        "letsencrypt": ("gdoc2netcfg.generators.letsencrypt", "generate_letsencrypt"),
        "nginx": ("gdoc2netcfg.generators.nginx", "generate_nginx"),
    }
    if name not in generators:
        return None
    module_path, func_name = generators[name]
    import importlib
    mod = importlib.import_module(module_path)
    return getattr(mod, func_name)


def _resolve_output_path(output_path: str, args: argparse.Namespace) -> Path:
    """Resolve an output path, prepending --output-dir for relative paths."""
    p = Path(output_path)
    output_dir = getattr(args, "output_dir", None)
    if output_dir and not p.is_absolute():
        return Path(output_dir) / p
    return p


def _write_multi_file_output(name, file_dict, gen_config, args):
    """Write a multi-file generator output (dict[str, str]).

    Each key is a relative path, written under the generator's output_dir.
    """
    if args.stdout:
        for rel_path, content in sorted(file_dict.items()):
            print(f"# === {name}: {rel_path} ===")
            print(content)
        return

    output_dir = gen_config.output_dir if gen_config and gen_config.output_dir else name
    base = _resolve_output_path(output_dir, args).resolve()
    total_bytes = 0
    for rel_path, content in sorted(file_dict.items()):
        file_path = (base / rel_path).resolve()
        if not str(file_path).startswith(str(base)):
            print(
                f"  {name}: skipping path traversal: {rel_path}",
                file=sys.stderr,
            )
            continue
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content, encoding="utf-8")
        total_bytes += len(content)
    print(f"  {name}: wrote {len(file_dict)} files to {output_dir}/ ({total_bytes} bytes)")


def cmd_generate(args: argparse.Namespace) -> int:
    """Run the pipeline and produce output config files."""
    config = _load_config(args)
    _, _, inventory, validation = _build_pipeline(config)

    if validation.has_errors:
        print("Validation errors found:", file=sys.stderr)
        print(validation.report(), file=sys.stderr)
        if not args.force:
            print("Use --force to generate despite errors.", file=sys.stderr)
            return 1

    if validation.warnings:
        print(f"Validation: {len(validation.warnings)} warning(s)", file=sys.stderr)

    # Determine which generators to run
    if args.generators:
        gen_names = args.generators
    else:
        gen_names = list(config.generators.keys())

    generated = 0
    for name in gen_names:
        gen_func = _get_generator(name)
        if gen_func is None:
            print(f"Warning: unknown generator {name!r}", file=sys.stderr)
            continue

        gen_config = config.generators.get(name)

        # Build kwargs for generators that accept extra parameters
        kwargs = {}
        if name == "dnsmasq_external" and gen_config and gen_config.params.get("public_ipv4"):
            kwargs["public_ipv4"] = gen_config.params["public_ipv4"]
        elif name == "dnsmasq_external":
            kwargs["public_ipv4"] = config.site.public_ipv4
        elif name == "letsencrypt" and gen_config:
            for key in ("auth_hook", "dnsmasq_conf_dir", "dnsmasq_conf", "dnsmasq_service"):
                if gen_config.params.get(key):
                    kwargs[key] = gen_config.params[key]
        elif name == "nginx" and gen_config:
            if gen_config.params.get("acme_webroot"):
                kwargs["acme_webroot"] = gen_config.params["acme_webroot"]
            if gen_config.params.get("htpasswd_file"):
                kwargs["htpasswd_file"] = gen_config.params["htpasswd_file"]

        output = gen_func(inventory, **kwargs)

        # Write output: single file (str) or multiple files (dict)
        if isinstance(output, dict):
            _write_multi_file_output(name, output, gen_config, args)
        else:
            output_path = gen_config.output if gen_config and gen_config.output else None
            if output_path and not args.stdout:
                resolved = _resolve_output_path(output_path, args)
                resolved.parent.mkdir(parents=True, exist_ok=True)
                resolved.write_text(output, encoding="utf-8")
                print(f"  {name}: wrote {resolved} ({len(output)} bytes)")
            else:
                if len(gen_names) > 1:
                    print(f"# === {name} ===")
                print(output)

        generated += 1

    if not args.stdout:
        print(f"\nGenerated {generated} config file(s).")
    return 0


# ---------------------------------------------------------------------------
# Subcommand: validate
# ---------------------------------------------------------------------------

def cmd_validate(args: argparse.Namespace) -> int:
    """Run constraint validation on the data."""
    config = _load_config(args)
    records, hosts, inventory, result = _build_pipeline(config)

    print(f"Records: {len(records)}")
    print(f"Hosts:   {len(hosts)}")
    print()
    print(result.report())

    return 1 if result.has_errors else 0


# ---------------------------------------------------------------------------
# Subcommand: info
# ---------------------------------------------------------------------------

def cmd_info(args: argparse.Namespace) -> int:
    """Show pipeline configuration info."""
    config = _load_config(args)

    # Load VLANs from sheet if available
    csv_data = _fetch_or_load_csvs(config, use_cache=True)
    _enrich_site_from_vlan_sheet(config, csv_data)

    print(f"Site:   {config.site.name} (site_octet={config.site.site_octet})")
    print(f"Domain: {config.site.domain}")
    print()

    print("Sheets:")
    for sheet in config.sheets:
        print(f"  {sheet.name}: {sheet.url[:60]}...")
    print()

    print("IPv6 prefixes:")
    for prefix in config.site.ipv6_prefixes:
        status = "enabled" if prefix.enabled else "DISABLED"
        print(f"  {prefix.prefix} ({status})")
    print()

    print("VLANs:")
    for vid, vlan in sorted(config.site.vlans.items()):
        print(f"  {vid:>3d}: {vlan.name} (subdomain: {vlan.subdomain})")
    print()

    print("Generators:")
    for name, gen in config.generators.items():
        status = "enabled" if gen.enabled else "disabled"
        output = gen.output or "(stdout)"
        print(f"  {name}: {status}, output={output}")

    return 0


# ---------------------------------------------------------------------------
# Subcommand: sshfp
# ---------------------------------------------------------------------------

def cmd_sshfp(args: argparse.Namespace) -> int:
    """Scan hosts for SSH fingerprints."""
    config = _load_config(args)

    from gdoc2netcfg.derivations.host_builder import build_hosts
    from gdoc2netcfg.sources.parser import parse_csv
    from gdoc2netcfg.supplements.sshfp import (
        enrich_hosts_with_sshfp,
        scan_sshfp,
    )

    # We need a minimal pipeline to get hosts with IPs
    csv_data = _fetch_or_load_csvs(config, use_cache=True)
    _enrich_site_from_vlan_sheet(config, csv_data)
    all_records = []
    for name, csv_text in csv_data:
        if name == "vlan_allocations":
            continue
        records = parse_csv(csv_text, name)
        all_records.extend(records)

    hosts = build_hosts(all_records, config.site)

    cache_path = Path(config.cache.directory) / "sshfp.json"
    sshfp_data = scan_sshfp(
        hosts,
        cache_path=cache_path,
        force=args.force,
        verbose=True,
    )

    enrich_hosts_with_sshfp(hosts, sshfp_data)

    # Report
    hosts_with_fp = sum(1 for h in hosts if h.sshfp_records)
    print(f"\nSSHFP records for {hosts_with_fp}/{len(hosts)} hosts.")

    return 0


# ---------------------------------------------------------------------------
# Subcommand: ssl-certs
# ---------------------------------------------------------------------------

def cmd_ssl_certs(args: argparse.Namespace) -> int:
    """Scan hosts for SSL/TLS certificates."""
    config = _load_config(args)

    from gdoc2netcfg.constraints.ssl_validation import (
        format_ssl_validation_report,
        validate_ssl_certificates,
    )
    from gdoc2netcfg.derivations.dns_names import derive_all_dns_names
    from gdoc2netcfg.derivations.host_builder import build_hosts
    from gdoc2netcfg.sources.parser import parse_csv
    from gdoc2netcfg.supplements.ssl_certs import (
        enrich_hosts_with_ssl_certs,
        scan_ssl_certs,
    )

    # Minimal pipeline to get hosts with IPs
    csv_data = _fetch_or_load_csvs(config, use_cache=True)
    _enrich_site_from_vlan_sheet(config, csv_data)
    all_records = []
    for name, csv_text in csv_data:
        if name == "vlan_allocations":
            continue
        records = parse_csv(csv_text, name)
        all_records.extend(records)

    hosts = build_hosts(all_records, config.site)

    # Derive DNS names for validation comparison
    for host in hosts:
        derive_all_dns_names(host, config.site)

    cache_path = Path(config.cache.directory) / "ssl_certs.json"
    cert_data = scan_ssl_certs(
        hosts,
        cache_path=cache_path,
        force=args.force,
        verbose=True,
    )

    enrich_hosts_with_ssl_certs(hosts, cert_data)

    # Report scan results
    hosts_with_cert = sum(1 for h in hosts if h.ssl_cert_info is not None)
    print(f"SSL certificates for {hosts_with_cert}/{len(hosts)} hosts.")

    # Run validation and print report
    validation_result = validate_ssl_certificates(hosts)
    if validation_result.violations:
        print()
        print(format_ssl_validation_report(validation_result))

    return 0


# ---------------------------------------------------------------------------
# Subcommand: snmp
# ---------------------------------------------------------------------------

def cmd_snmp(args: argparse.Namespace) -> int:
    """Scan hosts for SNMP data."""
    config = _load_config(args)

    from gdoc2netcfg.constraints.snmp_validation import validate_snmp_availability
    from gdoc2netcfg.derivations.host_builder import build_hosts
    from gdoc2netcfg.sources.parser import parse_csv
    from gdoc2netcfg.supplements.reachability import check_all_hosts_reachability
    from gdoc2netcfg.supplements.snmp import (
        enrich_hosts_with_snmp,
        scan_snmp,
    )

    # Minimal pipeline to get hosts with IPs
    csv_data = _fetch_or_load_csvs(config, use_cache=True)
    _enrich_site_from_vlan_sheet(config, csv_data)
    all_records = []
    for name, csv_text in csv_data:
        if name == "vlan_allocations":
            continue
        records = parse_csv(csv_text, name)
        all_records.extend(records)

    hosts = build_hosts(all_records, config.site)

    # Run shared reachability pass
    print("Checking host reachability...", file=sys.stderr)
    reachability = check_all_hosts_reachability(hosts, verbose=True)

    cache_path = Path(config.cache.directory) / "snmp.json"
    print("\nScanning SNMP...", file=sys.stderr)
    snmp_data = scan_snmp(
        hosts,
        cache_path=cache_path,
        force=args.force,
        verbose=True,
        reachability=reachability,
    )

    enrich_hosts_with_snmp(hosts, snmp_data)

    # Run validation
    validation_result = validate_snmp_availability(hosts, reachability)

    # Report
    hosts_with_snmp = sum(1 for h in hosts if h.snmp_data is not None)
    hosts_up = sum(1 for r in reachability.values() if r.is_up)
    print(f"\nSNMP data for {hosts_with_snmp}/{len(hosts)} hosts "
          f"({hosts_up} reachable).")

    if validation_result.violations:
        print()
        print(validation_result.report())

    return 1 if validation_result.has_errors else 0


# ---------------------------------------------------------------------------
# Subcommand: bridge
# ---------------------------------------------------------------------------

def cmd_bridge(args: argparse.Namespace) -> int:
    """Scan switches for bridge/topology data."""
    config = _load_config(args)

    from gdoc2netcfg.derivations.host_builder import build_hosts
    from gdoc2netcfg.sources.parser import parse_csv
    from gdoc2netcfg.supplements.bridge import (
        enrich_hosts_with_bridge_data,
        scan_bridge,
    )
    from gdoc2netcfg.supplements.reachability import check_all_hosts_reachability

    # Minimal pipeline to get hosts with IPs
    csv_data = _fetch_or_load_csvs(config, use_cache=True)
    _enrich_site_from_vlan_sheet(config, csv_data)
    all_records = []
    for name, csv_text in csv_data:
        if name == "vlan_allocations":
            continue
        records = parse_csv(csv_text, name)
        all_records.extend(records)

    hosts = build_hosts(all_records, config.site)

    # Run shared reachability pass
    print("Checking host reachability...", file=sys.stderr)
    reachability = check_all_hosts_reachability(hosts, verbose=True)

    cache_path = Path(config.cache.directory) / "bridge.json"
    print("\nScanning bridge data...", file=sys.stderr)
    bridge_data = scan_bridge(
        hosts,
        cache_path=cache_path,
        force=args.force,
        verbose=True,
        reachability=reachability,
    )

    enrich_hosts_with_bridge_data(hosts, bridge_data)

    # Report
    switches_with_data = sum(1 for h in hosts if h.bridge_data is not None)
    total_macs = sum(
        len(h.bridge_data.mac_table) for h in hosts if h.bridge_data is not None
    )
    print(f"\nBridge data for {switches_with_data} switches "
          f"({total_macs} MAC table entries).")

    return 0


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="gdoc2netcfg",
        description="Generate network config files from Google Spreadsheet data.",
    )
    parser.add_argument(
        "-c", "--config",
        help="Path to gdoc2netcfg.toml (default: ./gdoc2netcfg.toml)",
    )

    subparsers = parser.add_subparsers(dest="command")

    # fetch
    subparsers.add_parser("fetch", help="Download CSVs from Google Sheets to cache")

    # generate
    gen_parser = subparsers.add_parser("generate", help="Generate config files")
    gen_parser.add_argument(
        "generators", nargs="*",
        help="Generator names to run (default: all enabled)",
    )
    gen_parser.add_argument(
        "--output-dir",
        help="Base directory to prepend to all relative output paths",
    )
    gen_parser.add_argument(
        "--stdout", action="store_true",
        help="Print output to stdout instead of writing files",
    )
    gen_parser.add_argument(
        "--force", action="store_true",
        help="Generate even if validation errors exist",
    )

    # validate
    subparsers.add_parser("validate", help="Run constraint validation")

    # info
    subparsers.add_parser("info", help="Show pipeline configuration")

    # sshfp
    sshfp_parser = subparsers.add_parser("sshfp", help="Scan hosts for SSH fingerprints")
    sshfp_parser.add_argument(
        "--force", action="store_true",
        help="Force re-scan even if cache is fresh",
    )

    # ssl-certs
    ssl_parser = subparsers.add_parser("ssl-certs", help="Scan hosts for SSL/TLS certificates")
    ssl_parser.add_argument(
        "--force", action="store_true",
        help="Force re-scan even if cache is fresh",
    )

    # snmp
    snmp_parser = subparsers.add_parser("snmp", help="Scan hosts for SNMP data")
    snmp_parser.add_argument(
        "--force", action="store_true",
        help="Force re-scan even if cache is fresh",
    )

    # bridge
    bridge_parser = subparsers.add_parser("bridge", help="Scan switches for bridge/topology data")
    bridge_parser.add_argument(
        "--force", action="store_true",
        help="Force re-scan even if cache is fresh",
    )

    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    commands = {
        "fetch": cmd_fetch,
        "generate": cmd_generate,
        "validate": cmd_validate,
        "info": cmd_info,
        "sshfp": cmd_sshfp,
        "ssl-certs": cmd_ssl_certs,
        "snmp": cmd_snmp,
        "bridge": cmd_bridge,
    }

    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
