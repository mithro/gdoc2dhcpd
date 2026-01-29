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
    output.extend(_sshfp_records(inventory))
    output.append("")
    return "\n".join(output)


def _sshfp_records(inventory: NetworkInventory) -> list[str]:
    """Generate SSHFP DNS records (RR type 44) for external DNS.

    Unlike the internal generator, this does NOT emit PTR records
    since internal IPs aren't routable from external networks.
    """
    domain = inventory.site.domain
    output: list[str] = []
    output.append("# " + "=" * 70)
    output.append("# SSHFP Records")
    output.append("# " + "=" * 70)

    for host in inventory.hosts_sorted():
        if not host.sshfp_records:
            continue

        def _records(dnsname: str) -> None:
            output.append("")
            output.append(f"# sshfp for {dnsname}")
            for line in host.sshfp_records:
                if line.startswith(";"):
                    continue
                parts = line.split()
                if len(parts) >= 6:
                    _, a, b, c, d, e = parts[:6]
                    output.append(f"dns-rr={dnsname},44,{c}:{d}:{e}")

        output.append("")
        output.append("# " + "-" * 70)
        output.append(f"# {host.hostname}")
        output.append("# " + "-" * 70)
        _records(f"{host.hostname}.{domain}")

        # Include interface-specific FQDNs
        for iface in host.interfaces:
            if iface.name:
                _records(f"{iface.name}.{host.hostname}.{domain}")

        output.append("# " + "-" * 70)

    return output
