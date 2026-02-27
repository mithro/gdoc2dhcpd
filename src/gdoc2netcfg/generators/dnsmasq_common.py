"""Shared dnsmasq DNS record generation logic.

Contains the DNS record sections (host-record, CAA, SSHFP) that are
common to both internal and external generators. The only difference
between internal and external is the IPv4 transform applied:

- Internal: identity (uses addresses as-is)
- External: RFC 1918 → public IP substitution

This is a generator parameter (who is asking), not a derivation
(the data itself doesn't change).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from typing import TYPE_CHECKING

from gdoc2netcfg.models.host import Host, NetworkInventory
from gdoc2netcfg.utils.ip import ip_sort_key

if TYPE_CHECKING:
    from gdoc2netcfg.constraints.errors import ValidationResult

Ipv4Transform = Callable[[str], str]


def identity_ipv4(ip: str) -> str:
    """Identity transform: return the IP address unchanged."""
    return ip


def host_record_config(
    host: Host, inventory: NetworkInventory, ipv4_transform: Ipv4Transform,
) -> list[str]:
    """Generate host-record entries for forward DNS for a single host.

    Uses the precomputed host.dns_names list from the DNS name derivation
    pipeline, which includes:
    - Hostname and interface FQDNs
    - Subdomain variants
    - ipv4./ipv6. prefix variants for all dual-stack names

    The ipv4_transform is applied to each IPv4 address before output.
    Addresses are deduplicated after transform (important for external
    DNS where all RFC 1918 IPs map to the same public IP).
    """
    if not host.dns_names:
        return []

    domain = inventory.site.domain
    output: list[str] = []

    for dns_name in host.dns_names:
        # Skip short names except for the bare hostname
        if not dns_name.is_fqdn and dns_name.name != host.hostname:
            continue

        # Skip wildcard names (dnsmasq doesn't support wildcard host-records)
        if "*" in dns_name.name:
            continue

        # Skip FQDNs outside our authoritative zone
        if dns_name.is_fqdn and not dns_name.name.endswith(f".{domain}"):
            continue

        addrs: list[str] = []
        seen: set[str] = set()
        for ipv4_addr in dns_name.ipv4_addresses:
            transformed = ipv4_transform(str(ipv4_addr))
            if transformed not in seen:
                addrs.append(transformed)
                seen.add(transformed)
        for ipv6_addr in dns_name.ipv6_addresses:
            addr_str = str(ipv6_addr)
            if addr_str not in seen:
                addrs.append(addr_str)
                seen.add(addr_str)

        if not addrs:
            continue

        output.append(f"host-record={dns_name.name},{','.join(addrs)}")

    return output


def host_caa_config(host: Host, inventory: NetworkInventory) -> list[str]:
    """Generate CAA record for Let's Encrypt on the primary FQDN."""
    domain = inventory.site.domain
    return [
        f"dns-rr={host.hostname}.{domain},"
        f"257,000569737375656C657473656E63727970742E6F7267"
    ]


def host_sshfp_records(
    host: Host, inventory: NetworkInventory, ipv4_transform: Ipv4Transform,
) -> list[str]:
    """Generate SSHFP DNS records (RR type 44) for a single host.

    Emits SSHFP for the hostname FQDN, each named interface FQDN,
    and each interface's IPv4 PTR name. The ipv4_transform is applied
    to the PTR addresses.
    """
    if not host.sshfp_records:
        return []

    domain = inventory.site.domain
    output: list[str] = []

    def _records(dnsname: str) -> None:
        output.append(f"# sshfp for {dnsname}")
        for line in host.sshfp_records:
            if line.startswith(";"):
                continue
            parts = line.split()
            if len(parts) >= 6:
                _, a, b, c, d, e = parts[:6]
                output.append(f"dns-rr={dnsname},44,{c}:{d}:{e}")

    _records(f"{host.hostname}.{domain}")

    for iface in host.interfaces:
        if iface.name:
            _records(f"{iface.name}.{host.hostname}.{domain}")

    for vi in host.virtual_interfaces:
        ip_str = ipv4_transform(str(vi.ipv4))
        ptr = ".".join(ip_str.split(".")[::-1]) + ".in-addr.arpa"
        _records(ptr)

    return output


def _most_specific_fqdn(
    host: Host, ip: str, domain: str, *, is_ipv6: bool = False,
) -> str | None:
    """Find the most-specific FQDN from host.dns_names for an IP address.

    Most specific = FQDN with the most labels (dots) that contains the
    target IP, excluding alt names, within the authoritative zone.

    Args:
        host: The host whose dns_names to search.
        ip: The IP address string to match against.
        domain: The authoritative DNS zone (e.g. 'welland.mithis.com').
        is_ipv6: If True, match against IPv6 addresses; otherwise IPv4.

    Returns:
        The most-specific FQDN string, or None if no match found.
    """
    alt_names = set(host.alt_names) if host.alt_names else set()

    best: str | None = None
    best_dots = -1

    for dns_name in host.dns_names:
        if not dns_name.is_fqdn:
            continue
        # Must be within our authoritative zone
        if not dns_name.name.endswith(f".{domain}"):
            continue
        # Exclude alt names
        if dns_name.name in alt_names:
            continue
        # Must contain the target IP
        if is_ipv6:
            if not any(str(a) == ip for a in dns_name.ipv6_addresses):
                continue
        else:
            if not any(str(a) == ip for a in dns_name.ipv4_addresses):
                continue

        dots = dns_name.name.count(".")
        if dots > best_dots:
            best = dns_name.name
            best_dots = dots

    return best


def host_ptr_config(host: Host, inventory: NetworkInventory) -> list[str]:
    """Generate ptr-record entries (IPv4 and IPv6) for a single host.

    Uses the most-specific FQDN from host.dns_names for each IP address.
    IPv4 and IPv6 PTRs may get different names (e.g., ipv4.X vs ipv6.X).

    Uses original (non-transformed) IPs for both internal and external:
    IPv4 PTR records use RFC 1918 addresses (the in-addr.arpa name is
    derived from the actual IP), and IPv6 addresses are already public.
    """
    domain = inventory.site.domain
    output: list[str] = []

    for vi in sorted(host.virtual_interfaces, key=lambda v: ip_sort_key(str(v.ipv4))):
        ip = str(vi.ipv4)

        # IPv4 PTR — most-specific FQDN for this IPv4
        fqdn = _most_specific_fqdn(host, ip, domain, is_ipv6=False)
        if fqdn:
            output.append(f"ptr-record=/{fqdn}/{ip}")

        # IPv6 PTRs — most-specific FQDN for each IPv6
        for ipv6_addr in vi.ipv6_addresses:
            ipv6_str = str(ipv6_addr)
            ipv6_fqdn = _most_specific_fqdn(host, ipv6_str, domain, is_ipv6=True)
            if ipv6_fqdn:
                ptr = _ipv6_to_ptr(ipv6_str)
                output.append(f"ptr-record={ptr},{ipv6_fqdn}")

    return output


def _ipv6_for_ip(ip: str, inventory: NetworkInventory) -> list[str]:
    """Get IPv6 address strings for an IPv4 address."""
    from gdoc2netcfg.derivations.ipv6 import ipv4_to_ipv6_list
    from gdoc2netcfg.models.addressing import IPv4Address

    try:
        ipv4 = IPv4Address(ip)
    except ValueError:
        return []
    addrs = ipv4_to_ipv6_list(ipv4, inventory.site.active_ipv6_prefixes)
    return [str(a) for a in addrs]


def _ipv6_to_ptr(ipv6_str: str) -> str:
    """Convert IPv6 address string to PTR format."""
    addr = ipaddress.IPv6Address(ipv6_str)
    full_hex = addr.exploded.replace(":", "")
    return ".".join(reversed(full_hex)) + ".ip6.arpa"


def shared_dns_sections(
    host: Host, inventory: NetworkInventory, ipv4_transform: Ipv4Transform,
) -> list[list[str]]:
    """Return the DNS record sections common to all dnsmasq generators.

    Returns [host_records, ptr, caa, sshfp] — a list of sections where each
    section is a list of config lines.

    host-record is emitted BEFORE ptr-record because dnsmasq auto-generates
    PTR entries from host-record directives. Explicit ptr-record lines after
    host-record override the auto-generated PTRs with more-specific names.
    """
    return [
        host_record_config(host, inventory, ipv4_transform),
        host_ptr_config(host, inventory),
        host_caa_config(host, inventory),
        host_sshfp_records(host, inventory, ipv4_transform),
    ]


def sections_to_text(sections: list[list[str]]) -> str:
    """Format sections into a single config file string.

    Filters out empty sections and joins with blank line separators.
    """
    non_empty = [s for s in sections if s]
    if not non_empty:
        return ""
    return "\n\n".join("\n".join(s) for s in non_empty) + "\n"


def validate_dnsmasq_output(files: dict[str, str]) -> ValidationResult:
    """Validate that every PTR record name has a matching host-record.

    Parses all generated dnsmasq config files and checks that every forward
    name referenced by a ptr-record also appears as a name in a host-record
    line. This catches bugs in the DNS name derivation pipeline or generator
    code that would break forward-confirmed reverse DNS (FCrDNS).

    Args:
        files: Dict mapping filename to config file content (as returned
            by generate_dnsmasq_internal / generate_dnsmasq_external).

    Returns:
        ValidationResult with ERROR-severity violations for any PTR name
        that lacks a matching host-record.
    """
    from gdoc2netcfg.constraints.errors import (
        ConstraintViolation,
        Severity,
        ValidationResult,
    )

    result = ValidationResult()

    # Collect all names from host-record lines across all files.
    host_record_names: set[str] = set()
    for content in files.values():
        for line in content.splitlines():
            if line.startswith("host-record="):
                # host-record=NAME,ADDR[,ADDR...]
                after_eq = line[len("host-record="):]
                name = after_eq.split(",", 1)[0]
                host_record_names.add(name)

    # Check every PTR forward name has a matching host-record.
    for filename, content in sorted(files.items()):
        for line in content.splitlines():
            if not line.startswith("ptr-record="):
                continue

            after_eq = line[len("ptr-record="):]

            if after_eq.startswith("/"):
                # IPv4 format: ptr-record=/FQDN/IP
                parts = after_eq.strip("/").split("/")
                if len(parts) >= 1:
                    ptr_name = parts[0]
                else:
                    continue
            else:
                # IPv6 format: ptr-record=ARPA,FQDN
                parts = after_eq.split(",", 1)
                if len(parts) == 2:
                    ptr_name = parts[1]
                else:
                    continue

            if ptr_name not in host_record_names:
                result.add(ConstraintViolation(
                    severity=Severity.ERROR,
                    code="ptr_without_forward",
                    message=(
                        f"PTR record references '{ptr_name}' but no "
                        f"host-record exists for that name"
                    ),
                    record_id=filename,
                    field="ptr-record",
                ))

    return result
