"""Dnsmasq internal configuration generator.

Produces per-host dnsmasq config files, each containing:
- DHCP host bindings (dhcp-host)
- Reverse DNS PTR records (ptr-record) for IPv4 and IPv6
- Forward DNS records (host-record) with dual-stack IPv6
- SSHFP records (dns-rr type 44)
- CAA records (dns-rr type 257)

The DNS record sections (host-record, CAA, SSHFP) use the shared code
path in dnsmasq_common with an identity IPv4 transform. DHCP and PTR
are internal-only sections.
"""

from __future__ import annotations

from collections import defaultdict

from gdoc2netcfg.derivations.dns_names import common_suffix
from gdoc2netcfg.generators.dnsmasq_common import (
    identity_ipv4,
    sections_to_text,
    shared_dns_sections,
)
from gdoc2netcfg.models.host import Host, NetworkInventory
from gdoc2netcfg.utils.ip import ip_sort_key


def generate_dnsmasq_internal(inventory: NetworkInventory) -> dict[str, str]:
    """Generate internal dnsmasq configuration as per-host files.

    Returns a dict mapping "{hostname}.conf" to config content.
    """
    files: dict[str, str] = {}
    for host in inventory.hosts_sorted():
        content = _generate_host_internal(host, inventory)
        if content:
            files[f"{host.hostname}.conf"] = content
    return files


def _generate_host_internal(host: Host, inventory: NetworkInventory) -> str:
    """Generate all dnsmasq config sections for a single host."""
    sections = [
        _host_dhcp_config(host, inventory),
        _host_ptr_config(host, inventory),
    ] + shared_dns_sections(host, inventory, identity_ipv4)
    return sections_to_text(sections)


def _host_dhcp_config(host: Host, inventory: NetworkInventory) -> list[str]:
    """Generate dhcp-host entries for a single host."""
    if not host.interfaces:
        return []

    # Group MACs by IP within this host
    ip_to_macs: dict[str, list[tuple]] = defaultdict(list)
    for iface in host.interfaces:
        ip_str = str(iface.ipv4)
        ip_to_macs[ip_str].append((iface.mac, iface.dhcp_name))

    output: list[str] = []
    output.append(f"# {host.hostname} — DHCP")
    for ip, macs in sorted(ip_to_macs.items(), key=lambda x: ip_sort_key(x[0])):
        dhcp_names = set(name for _, name in macs)
        dhcp_name = common_suffix(*dhcp_names).strip("-")

        ipv6_strs = _ipv6_for_ip(ip, inventory)
        mac_str = ",".join(str(mac) for mac, _ in macs)

        if ipv6_strs:
            ipv6_brackets = ",".join(f"[{addr}]" for addr in ipv6_strs)
            output.append(f"dhcp-host={mac_str},{ip},{ipv6_brackets},{dhcp_name}")
        else:
            output.append(f"dhcp-host={mac_str},{ip},{dhcp_name}")

    return output


def _host_ptr_config(host: Host, inventory: NetworkInventory) -> list[str]:
    """Generate ptr-record entries (IPv4 and IPv6) for a single host."""
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


# --- Helper functions (not derivations — output-format specific) ---

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
    import ipaddress

    addr = ipaddress.IPv6Address(ipv6_str)
    full_hex = addr.exploded.replace(":", "")
    return ".".join(reversed(full_hex)) + ".ip6.arpa"
