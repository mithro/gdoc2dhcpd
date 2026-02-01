"""Dnsmasq internal configuration generator.

Produces per-host dnsmasq config files, each containing:
- DHCP host bindings (dhcp-host)
- Reverse DNS PTR records (ptr-record) for IPv4 and IPv6
- Forward DNS records (host-record) with dual-stack IPv6
- SSHFP records (dns-rr type 44)
- CAA records (dns-rr type 257)

Extracted from dnsmasq.py.
"""

from __future__ import annotations

from collections import defaultdict

from gdoc2netcfg.derivations.dns_names import common_suffix
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
    output: list[str] = []
    output.extend(_host_dhcp_config(host, inventory))
    output.extend(_host_ptr_config(host, inventory))
    output.extend(_host_record_config(host, inventory))
    output.extend(_host_sshfp_records(host, inventory))
    if not output:
        return ""
    output.append("")
    return "\n".join(output)


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


def _host_record_config(host: Host, inventory: NetworkInventory) -> list[str]:
    """Generate host-record entries for forward DNS for a single host.

    Uses the precomputed host.dns_names list from the DNS name derivation
    pipeline, which includes:
    - Hostname and interface FQDNs
    - Subdomain variants
    - ipv4./ipv6. prefix variants for all dual-stack names
    """
    domain = inventory.site.domain
    if not host.dns_names:
        return []

    output: list[str] = []

    for dns_name in host.dns_names:
        # Skip short names except for the bare hostname
        if not dns_name.is_fqdn and dns_name.name != host.hostname:
            continue

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

    return output


def _host_sshfp_records(host: Host, inventory: NetworkInventory) -> list[str]:
    """Generate SSHFP DNS records (RR type 44) for a single host."""
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
        ip_str = str(iface.ipv4)
        ptr = ".".join(ip_str.split(".")[::-1]) + ".in-addr.arpa"
        _records(ptr)

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
