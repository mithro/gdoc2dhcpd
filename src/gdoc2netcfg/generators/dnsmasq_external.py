"""Dnsmasq external (split-horizon) DNS generator.

Produces per-host dnsmasq configuration files for the external-facing
DNS server. When public_ipv4 is configured, RFC 1918 addresses in
host-records are replaced with the site's public IP. This implements
split-horizon DNS where internal clients see private IPs and external
clients see the public IP.

This is a generator parameter (who is asking), not a derivation
(the data itself doesn't change).
"""

from __future__ import annotations

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

    files: dict[str, str] = {}
    for host in inventory.hosts_sorted():
        content = _generate_host_external(host, inventory, public_ip)
        if content:
            files[f"{host.hostname}.conf"] = content
    return files


def _generate_host_external(
    host: Host, inventory: NetworkInventory, public_ip: str
) -> str:
    """Generate external dnsmasq config for a single host."""
    sections = [
        _host_record_external(host, inventory, public_ip),
        _host_sshfp_records(host, inventory),
    ]
    # Filter out empty sections, join with blank line separators
    non_empty = [s for s in sections if s]
    if not non_empty:
        return ""
    return "\n\n".join("\n".join(s) for s in non_empty) + "\n"


def _host_record_external(
    host: Host, inventory: NetworkInventory, public_ip: str
) -> list[str]:
    """Generate host-record with RFC1918→public IP substitution."""
    domain = inventory.site.domain
    dip = host.default_ipv4
    if dip is None:
        return []

    ip_str = str(dip)
    external_ip = public_ip if is_rfc1918(ip_str) else ip_str
    return [f"host-record={host.hostname}.{domain},{external_ip}"]


def _host_sshfp_records(host: Host, inventory: NetworkInventory) -> list[str]:
    """Generate SSHFP DNS records (RR type 44) for external DNS.

    Unlike the internal generator, this does NOT emit PTR records
    since internal IPs aren't routable from external networks.
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

    return output
