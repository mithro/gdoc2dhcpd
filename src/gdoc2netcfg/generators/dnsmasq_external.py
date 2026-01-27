"""Dnsmasq external (split-horizon) DNS generator.

Produces dnsmasq configuration for the external-facing DNS server.
When public_ipv4 is configured, RFC 1918 addresses in host-records
are replaced with the site's public IP. This implements split-horizon
DNS where internal clients see private IPs and external clients see
the public IP.

This is a generator parameter (who is asking), not a derivation
(the data itself doesn't change).
"""

from __future__ import annotations

from gdoc2netcfg.models.host import NetworkInventory
from gdoc2netcfg.utils.ip import is_rfc1918


def generate_dnsmasq_external(
    inventory: NetworkInventory,
    public_ipv4: str | None = None,
) -> str:
    """Generate external dnsmasq DNS configuration.

    Args:
        inventory: The enriched network inventory.
        public_ipv4: Public IPv4 to substitute for RFC 1918 addresses.
            If None, uses the site's public_ipv4. If neither is set,
            the generator produces no output.
    """
    public_ip = public_ipv4 or inventory.site.public_ipv4
    if not public_ip:
        return "# No public_ipv4 configured — external DNS not generated.\n"

    domain = inventory.site.domain
    output: list[str] = []
    output.append("# External (split-horizon) DNS configuration")
    output.append(f"# Public IPv4: {public_ip}")
    output.append("")

    for host in inventory.hosts_sorted():
        dip = host.default_ipv4
        if dip is None:
            continue

        ip_str = str(dip)
        # Replace RFC 1918 addresses with public IP
        external_ip = public_ip if is_rfc1918(ip_str) else ip_str

        output.append(f"host-record={host.hostname}.{domain},{external_ip}")

    output.append("")
    return "\n".join(output)
