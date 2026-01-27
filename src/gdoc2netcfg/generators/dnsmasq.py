"""Dnsmasq internal configuration generator.

Produces the combined dnsmasq.static.conf with:
- DHCP host bindings (dhcp-host)
- Reverse DNS PTR records (ptr-record) for IPv4 and IPv6
- Forward DNS records (host-record) with dual-stack IPv6
- SSHFP records (dns-rr type 44)
- CAA records (dns-rr type 257)

Extracted from dnsmasq.py.
"""

from __future__ import annotations

from gdoc2netcfg.derivations.dns_names import common_suffix
from gdoc2netcfg.models.host import NetworkInventory
from gdoc2netcfg.utils.ip import ip_sort_key


def generate_dnsmasq(inventory: NetworkInventory) -> str:
    """Generate internal dnsmasq configuration.

    This is the primary generator that produces the full dnsmasq.static.conf.
    """
    output: list[str] = []
    output.extend(_dhcp_host_config(inventory))
    output.extend(_ptr_config(inventory))
    output.extend(_host_record_config(inventory))
    output.extend(_sshfp_records(inventory))
    output.append("")
    return "\n".join(output)


def _dhcp_host_config(inventory: NetworkInventory) -> list[str]:
    """Generate dhcp-host entries."""
    output: list[str] = []
    output.append("")
    output.append("# " + "-" * 70)
    output.append("# DHCP Host Configuration")
    output.append("# " + "-" * 70)

    current_group = None
    for ip, macs in sorted(inventory.ip_to_macs.items(), key=lambda x: ip_sort_key(x[0])):
        # Add comment when IP group changes (first 3 octets)
        ip_group = ".".join(ip.split(".")[:3])
        if ip_group != current_group:
            if current_group is not None:
                output.append("")
            output.append(f"# {ip_group}.X")
            current_group = ip_group

        dhcp_names = set(name for _, name in macs)
        dhcp_name = common_suffix(*dhcp_names).strip("-")

        # Compute IPv6 addresses from the inventory's prefixes
        ipv6_strs = _ipv6_for_ip(ip, inventory)
        mac_str = ",".join(str(mac) for mac, _ in macs)

        if ipv6_strs:
            ipv6_brackets = ",".join(f"[{addr}]" for addr in ipv6_strs)
            output.append(f"dhcp-host={mac_str},{ip},{ipv6_brackets},{dhcp_name}")
        else:
            output.append(f"dhcp-host={mac_str},{ip},{dhcp_name}")

    output.append("# " + "-" * 70)
    output.append("")
    return output


def _ptr_config(inventory: NetworkInventory) -> list[str]:
    """Generate ptr-record entries for IPv4 and IPv6."""
    domain = inventory.site.domain
    output: list[str] = []

    # IPv4 PTR records
    output.append("")
    output.append("# " + "-" * 70)
    output.append("# Reverse names for IP addresses (IPv4)")
    output.append("# " + "-" * 70)
    for ip, hostname in sorted(inventory.ip_to_hostname.items(), key=lambda x: ip_sort_key(x[0])):
        output.append(f"ptr-record=/{hostname}.{domain}/{ip}")
    output.append("# " + "-" * 70)
    output.append("")

    # IPv6 PTR records
    output.append("# " + "-" * 70)
    output.append("# Reverse names for IP addresses (IPv6)")
    output.append("# " + "-" * 70)
    for ip, hostname in sorted(inventory.ip_to_hostname.items(), key=lambda x: ip_sort_key(x[0])):
        for ipv6_str in _ipv6_for_ip(ip, inventory):
            ptr = _ipv6_to_ptr(ipv6_str)
            output.append(f"ptr-record={ptr},{hostname}.{domain}")
    output.append("# " + "-" * 70)
    output.append("")
    return output


def _host_record_config(inventory: NetworkInventory) -> list[str]:
    """Generate host-record entries for forward DNS."""
    domain = inventory.site.domain
    output: list[str] = []
    output.append("")
    output.append("# " + "-" * 70)
    output.append("# Forward names")
    output.append("# " + "-" * 70)

    for host in inventory.hosts_sorted():
        ips = host.all_ipv4
        output.append("")
        output.append(f"# {host.hostname}")

        # Interface-specific records
        for iface in sorted(host.interfaces, key=lambda i: (i.name or "")):
            if iface.name:
                ip_str = str(iface.ipv4)
                ipv6_strs = [str(a) for a in iface.ipv6_addresses]
                if ipv6_strs:
                    ipv6_joined = ",".join(ipv6_strs)
                    output.append(
                        f"host-record={iface.name}.{host.hostname}.{domain},"
                        f"{ip_str},{ipv6_joined}"
                    )
                else:
                    output.append(
                        f"host-record={iface.name}.{host.hostname}.{domain},{ip_str}"
                    )
                # Subdomain variant for interface records
                subdomain = _subdomain_for_ip(ip_str, inventory)
                if subdomain:
                    if ipv6_strs:
                        output.append(
                            f"host-record={iface.name}.{host.hostname}.{subdomain}.{domain},"
                            f"{ip_str},{ipv6_joined}"
                        )
                    else:
                        output.append(
                            f"host-record={iface.name}.{host.hostname}.{subdomain}.{domain},"
                            f"{ip_str}"
                        )

        # Default host records
        dip = host.default_ipv4
        if dip is None:
            continue
        dip_str = str(dip)
        ipv6_strs = _ipv6_for_ip(dip_str, inventory)

        if ipv6_strs:
            ipv6_joined = ",".join(ipv6_strs)
            output.append(f"host-record={host.hostname}.{domain},{dip_str},{ipv6_joined}")
            output.append(f"host-record={host.hostname},{dip_str},{ipv6_joined}")
        else:
            output.append(f"host-record={host.hostname}.{domain},{dip_str}")
            output.append(f"host-record={host.hostname},{dip_str}")

        # Subdomain variant for default records
        subdomain = _subdomain_for_ip(dip_str, inventory)
        if subdomain:
            if ipv6_strs:
                output.append(
                    f"host-record={host.hostname}.{subdomain}.{domain},"
                    f"{dip_str},{ipv6_joined}"
                )
            else:
                output.append(
                    f"host-record={host.hostname}.{subdomain}.{domain},{dip_str}"
                )

        # IPv4-only and IPv6-only prefixed records
        output.append(f"host-record=ipv4.{host.hostname}.{domain},{dip_str}")
        if ipv6_strs:
            output.append(
                f"host-record=ipv6.{host.hostname}.{domain},{','.join(ipv6_strs)}"
            )

        # CAA record for Let's Encrypt
        output.append(
            f"dns-rr={host.hostname}.{domain},"
            f"257,000569737375656C657473656E63727970742E6F7267"
        )

    output.append("# " + "-" * 70)
    output.append("")
    return output


def _sshfp_records(inventory: NetworkInventory) -> list[str]:
    """Generate SSHFP DNS records (RR type 44)."""
    domain = inventory.site.domain
    output: list[str] = []
    output.append("")
    output.append("# " + "=" * 70)
    output.append("# SSHFP Records")
    output.append("# " + "=" * 70)

    for host in inventory.hosts_sorted():
        if not host.sshfp_records:
            continue

        ips = host.all_ipv4

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

        for iface in host.interfaces:
            if iface.name:
                _records(f"{iface.name}.{host.hostname}.{domain}")

        for iface in host.interfaces:
            ip_str = str(iface.ipv4)
            ptr = ".".join(ip_str.split(".")[::-1]) + ".in-addr.arpa"
            _records(ptr)

        output.append("# " + "-" * 70)

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


def _subdomain_for_ip(ip: str, inventory: NetworkInventory) -> str | None:
    """Get subdomain for an IPv4 address string."""
    parts = ip.split(".")
    if parts[0] != "10" or parts[1] != "1":
        return None
    return inventory.site.network_subdomains.get(int(parts[2]))


def _ipv6_to_ptr(ipv6_str: str) -> str:
    """Convert IPv6 address string to PTR format."""
    import ipaddress

    addr = ipaddress.IPv6Address(ipv6_str)
    full_hex = addr.exploded.replace(":", "")
    return ".".join(reversed(full_hex)) + ".ip6.arpa"
