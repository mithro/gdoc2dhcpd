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

from collections.abc import Callable

from gdoc2netcfg.models.host import Host, NetworkInventory

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


def shared_dns_sections(
    host: Host, inventory: NetworkInventory, ipv4_transform: Ipv4Transform,
) -> list[list[str]]:
    """Return the DNS record sections common to all dnsmasq generators.

    Returns [host_records, caa, sshfp] — a list of sections where each
    section is a list of config lines.
    """
    return [
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
