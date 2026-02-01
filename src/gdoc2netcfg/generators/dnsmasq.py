"""Dnsmasq internal configuration generator.

Produces per-host dnsmasq config files, each containing:
- DHCP host bindings (dhcp-host)
- Reverse DNS PTR records (ptr-record) for IPv4 and IPv6
- Forward DNS records (host-record) with dual-stack IPv6
- SSHFP records (dns-rr type 44)
- CAA records (dns-rr type 257)

The DNS record sections (PTR, host-record, CAA, SSHFP) use the shared
code path in dnsmasq_common with an identity IPv4 transform. DHCP
bindings are the only internal-only section.
"""

from __future__ import annotations

from collections import defaultdict

from gdoc2netcfg.derivations.dns_names import common_suffix
from gdoc2netcfg.generators.dnsmasq_common import (
    _ipv6_for_ip,
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
