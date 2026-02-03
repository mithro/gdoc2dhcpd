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

from gdoc2netcfg.models.host import Host, NetworkInventory
from gdoc2netcfg.utils.ip import ip_sort_key

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
    """
    if not host.dns_names:
        return []

    output: list[str] = []

    for dns_name in host.dns_names:
        # Skip short names except for the bare hostname
        if not dns_name.is_fqdn and dns_name.name != host.hostname:
            continue

        # Skip wildcard names (dnsmasq doesn't support wildcard host-records)
        if "*" in dns_name.name:
            continue

        addrs: list[str] = []
        if dns_name.ipv4:
            addrs.append(ipv4_transform(str(dns_name.ipv4)))
        addrs.extend(str(a) for a in dns_name.ipv6_addresses)

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

    for iface in host.interfaces:
        ip_str = ipv4_transform(str(iface.ipv4))
        ptr = ".".join(ip_str.split(".")[::-1]) + ".in-addr.arpa"
        _records(ptr)

    return output


def host_ptr_config(host: Host, inventory: NetworkInventory) -> list[str]:
    """Generate ptr-record entries (IPv4 and IPv6) for a single host.

    Uses original (non-transformed) IPs for both internal and external:
    IPv4 PTR records use RFC 1918 addresses (the in-addr.arpa name is
    derived from the actual IP), and IPv6 addresses are already public.
    """
    domain = inventory.site.domain
    output: list[str] = []

    for iface in sorted(host.interfaces, key=lambda i: ip_sort_key(str(i.ipv4))):
        ip = str(iface.ipv4)
        hostname = inventory.ip_to_hostname.get(ip)
        if not hostname:
            continue

        # IPv4 PTR
        output.append(f"ptr-record=/{hostname}.{domain}/{ip}")

        # IPv6 PTR
        for ipv6_str in _ipv6_for_ip(ip, inventory):
            ptr = _ipv6_to_ptr(ipv6_str)
            output.append(f"ptr-record={ptr},{hostname}.{domain}")

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

    Returns [ptr, host_records, caa, sshfp] — a list of sections where each
    section is a list of config lines.
    """
    return [
        host_ptr_config(host, inventory),
        host_record_config(host, inventory, ipv4_transform),
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
