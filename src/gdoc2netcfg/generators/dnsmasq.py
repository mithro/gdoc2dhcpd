"""Dnsmasq internal configuration generator.

Produces the internal dnsmasq config with:
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


def generate_dnsmasq_internal(inventory: NetworkInventory) -> str:
    """Generate internal dnsmasq configuration.

    This is the primary generator that produces the internal dnsmasq config.
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
    """Generate host-record entries for forward DNS.

    Uses the precomputed host.dns_names list from the DNS name derivation
    pipeline, which includes:
    - Hostname and interface FQDNs
    - Subdomain variants
    - ipv4./ipv6. prefix variants for all dual-stack names
    """
    domain = inventory.site.domain
    output: list[str] = []
    output.append("")
    output.append("# " + "-" * 70)
    output.append("# Forward names")
    output.append("# " + "-" * 70)

    for host in inventory.hosts_sorted():
        if not host.dns_names:
            continue
        output.append("")
        output.append(f"# {host.hostname}")

        # Emit host-record for each DNS name
        for dns_name in host.dns_names:
            # Skip short names except for the bare hostname
            if not dns_name.is_fqdn and dns_name.name != host.hostname:
                continue

            # Build the address list
            addrs: list[str] = []
            if dns_name.ipv4:
                addrs.append(str(dns_name.ipv4))
            addrs.extend(str(a) for a in dns_name.ipv6_addresses)

            if not addrs:
                continue

            output.append(f"host-record={dns_name.name},{','.join(addrs)}")

        # CAA record for Let's Encrypt (on the primary FQDN)
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


def _ipv6_to_ptr(ipv6_str: str) -> str:
    """Convert IPv6 address string to PTR format."""
    import ipaddress

    addr = ipaddress.IPv6Address(ipv6_str)
    full_hex = addr.exploded.replace(":", "")
    return ".".join(reversed(full_hex)) + ".ip6.arpa"
