"""Dnsmasq external (split-horizon) DNS generator.

Produces per-host dnsmasq configuration files for the external-facing
DNS server. Uses the same shared DNS record sections as the internal
generator (host-record, CAA, SSHFP) but with an IPv4 transform that
replaces RFC 1918 addresses with the site's public IP.

This is a generator parameter (who is asking), not a derivation
(the data itself doesn't change).
"""

from __future__ import annotations

from gdoc2netcfg.generators.dnsmasq_common import (
    sections_to_text,
    shared_dns_sections,
)
from gdoc2netcfg.models.host import Host, NetworkInventory
from gdoc2netcfg.utils.ip import is_rfc1918


def generate_dnsmasq_external(
    inventory: NetworkInventory,
    public_ipv4: str | None = None,
) -> dict[str, str]:
    """Generate external dnsmasq DNS configuration as per-host files.

    Returns a dict mapping "{hostname}.conf" to config content.
    If no public_ipv4 is available, returns an empty dict.
    """
    public_ip = public_ipv4 or inventory.site.public_ipv4
    if not public_ip:
        return {}

    def ipv4_transform(ip: str) -> str:
        return public_ip if is_rfc1918(ip) else ip

    files: dict[str, str] = {}
    for host in inventory.hosts_sorted():
        content = _generate_host_external(host, inventory, ipv4_transform)
        if content:
            files[f"{host.hostname}.conf"] = content
    return files


def _generate_host_external(
    host: Host, inventory: NetworkInventory, ipv4_transform,
) -> str:
    """Generate external dnsmasq config for a single host."""
    sections = shared_dns_sections(host, inventory, ipv4_transform)
    return sections_to_text(sections)
