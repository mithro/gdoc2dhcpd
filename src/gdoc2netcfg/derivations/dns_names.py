"""DNS name derivations: hostname, DHCP name, common suffix, subdomain variants.

Includes five composable DNS name derivation passes:
  Pass 1 — Hostname: base hostname names ({hostname}.{domain}, {hostname})
  Pass 2 — Interface: per-interface names ({iface}.{hostname}.{domain}, ...)
  Pass 3 — Subdomain: subdomain variants ({hostname}.{subdomain}.{domain}, ...)
  Pass 4 — IPv4/IPv6 prefix: ipv4.{name}, ipv6.{name} for dual-stack names
  Pass 5 — Alt names: alternative FQDNs from the spreadsheet's Alt Names column
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from gdoc2netcfg.models.host import DNSName

if TYPE_CHECKING:
    from gdoc2netcfg.models.addressing import IPv4Address, IPv6Address
    from gdoc2netcfg.models.host import Host
    from gdoc2netcfg.models.network import Site


def compute_hostname(machine_name: str, sheet_type: str) -> str:
    """Compute the hostname from a machine name and sheet type.

    IoT devices get a '.iot' suffix appended. Network devices use the
    machine name directly (lowercased).

    >>> compute_hostname('thermostat', 'IoT')
    'thermostat.iot'
    >>> compute_hostname('Desktop', 'Network')
    'desktop'
    """
    hostname = machine_name.lower().strip()
    if sheet_type == "IoT":
        hostname += ".iot"
    elif sheet_type == "Test":
        hostname += ".test"
    return hostname


def compute_dhcp_name(machine_name: str, interface: str, sheet_type: str) -> str:
    """Compute the DHCP name from a machine name and interface.

    If an interface is specified, it's prepended with a dash separator.
    IoT devices get a '.iot' suffix.

    >>> compute_dhcp_name('desktop', 'eth0', 'Network')
    'eth0-desktop'
    >>> compute_dhcp_name('desktop', '', 'Network')
    'desktop'
    >>> compute_dhcp_name('thermostat', '', 'IoT')
    'thermostat.iot'
    >>> compute_dhcp_name('camera', 'eth0', 'IoT')
    'eth0-camera.iot'
    """
    dhcp_name = machine_name.lower().strip()
    if interface and interface.strip():
        dhcp_name = interface.lower().strip() + "-" + dhcp_name
    if sheet_type == "IoT":
        dhcp_name += ".iot"
    return dhcp_name


def common_suffix(a: str, *others: str) -> str:
    """Find the longest common suffix of two or more strings.

    Used to determine the canonical hostname when multiple interfaces
    share a machine. For example, eth1.ten64 and eth2.ten64 → ten64.

    >>> common_suffix('a', 'a')
    'a'
    >>> common_suffix('a', 'a', 'a')
    'a'
    >>> common_suffix('a', 'a', 'b')
    ''
    >>> common_suffix('aa', 'a')
    'a'
    >>> common_suffix('ab', 'a')
    ''
    >>> common_suffix('aba', 'aa')
    'a'
    >>> common_suffix('abca', 'aca')
    'ca'
    >>> common_suffix('abca')
    'abca'
    """
    if not others:
        return a

    lengths = [len(b) for b in others]
    lengths.append(len(a))
    min_len = min(lengths)

    i = 1
    while i < (min_len + 1):
        if not all(a[-i:] == b[-i:] for b in others):
            break
        i += 1
    i -= 1

    if i == 0:
        return ""
    return a[-i:]


# ---------------------------------------------------------------------------
# DNS name derivation passes
# ---------------------------------------------------------------------------

def _make_dns_name(
    name: str,
    ipv4: "IPv4Address | None",
    ipv6_addresses: "tuple[IPv6Address, ...] | list[IPv6Address]",
    is_fqdn: bool,
    *,
    ipv4_addresses: "tuple[IPv4Address, ...] | None" = None,
) -> DNSName:
    """Create a DNSName with unified ip_addresses tuple.

    When ipv4_addresses is provided, it takes precedence over the
    single ipv4 parameter — used for multi-homed hosts where bare
    hostnames resolve to ALL interface IPs.
    """
    ips: list["IPv4Address | IPv6Address"] = []
    if ipv4_addresses is not None:
        ips.extend(ipv4_addresses)
    elif ipv4 is not None:
        ips.append(ipv4)
    ips.extend(ipv6_addresses)
    return DNSName(
        name=name,
        ip_addresses=tuple(ips),
        is_fqdn=is_fqdn,
    )


def derive_dns_names_hostname(host: "Host", domain: str) -> list[DNSName]:
    """Pass 1 — Hostname: add base hostname DNS names.

    Adds:
      - {hostname}.{domain}  (FQDN)
      - {hostname}           (short name)

    Uses the host's default IP and its IPv6 addresses.
    """
    if host.default_ipv4 is None:
        return []

    # Find IPv6 addresses for the default IP
    ipv6_addrs: tuple["IPv6Address", ...] = ()
    for iface in host.interfaces:
        if iface.ipv4 == host.default_ipv4:
            ipv6_addrs = tuple(iface.ipv6_addresses)
            break

    return [
        _make_dns_name(
            f"{host.hostname}.{domain}",
            host.default_ipv4,
            ipv6_addrs,
            is_fqdn=True,
        ),
        _make_dns_name(
            host.hostname,
            host.default_ipv4,
            ipv6_addrs,
            is_fqdn=False,
        ),
    ]


def derive_dns_names_interface(host: "Host", domain: str) -> list[DNSName]:
    """Pass 2 — Interface: add per-interface DNS names.

    For each named interface, adds:
      - {iface}.{hostname}.{domain}  (FQDN)
      - {iface}.{hostname}           (short name)
    """
    names: list[DNSName] = []
    for iface in host.interfaces:
        if not iface.name:
            continue
        names.append(
            _make_dns_name(
                f"{iface.name}.{host.hostname}.{domain}",
                iface.ipv4,
                iface.ipv6_addresses,
                is_fqdn=True,
            )
        )
        names.append(
            _make_dns_name(
                f"{iface.name}.{host.hostname}",
                iface.ipv4,
                iface.ipv6_addresses,
                is_fqdn=False,
            )
        )
    return names


def derive_dns_names_subdomain(
    host: "Host", domain: str, site: "Site",
) -> list[DNSName]:
    """Pass 3 — Subdomain: add subdomain variants for existing FQDN names.

    For each existing FQDN name {x}.{domain}, adds:
      - {x}.{subdomain}.{domain}

    Uses ip_to_subdomain from vlan.py for subdomain lookup.
    """
    from gdoc2netcfg.derivations.vlan import ip_to_subdomain

    names: list[DNSName] = []
    for dns_name in list(host.dns_names):
        if not dns_name.is_fqdn:
            continue
        if dns_name.ipv4 is None:
            continue
        subdomain = ip_to_subdomain(dns_name.ipv4, site)
        if not subdomain:
            continue
        # Replace .{domain} with .{subdomain}.{domain}
        base = dns_name.name
        if base.endswith(f".{domain}"):
            prefix = base[: -len(f".{domain}")]
            new_name = f"{prefix}.{subdomain}.{domain}"
            names.append(
                _make_dns_name(
                    new_name,
                    dns_name.ipv4,
                    dns_name.ipv6_addresses,
                    is_fqdn=True,
                )
            )
    return names


def derive_dns_names_ip_prefix(host: "Host", domain: str) -> list[DNSName]:
    """Pass 4 — IPv4/IPv6 prefix: add ipv4.{name} and ipv6.{name} variants.

    Scans ALL existing names. For any FQDN name that resolves to both IPv4
    and IPv6, adds:
      - ipv4.{name}  (IPv4 only)
      - ipv6.{name}  (IPv6 only)
    """
    names: list[DNSName] = []
    for dns_name in list(host.dns_names):
        if not dns_name.is_fqdn:
            continue
        if dns_name.ipv4 is None:
            continue
        if not dns_name.ipv6_addresses:
            continue
        names.append(
            _make_dns_name(
                f"ipv4.{dns_name.name}",
                dns_name.ipv4,
                (),
                is_fqdn=True,
            )
        )
        names.append(
            _make_dns_name(
                f"ipv6.{dns_name.name}",
                None,
                dns_name.ipv6_addresses,
                is_fqdn=True,
            )
        )
    return names


def derive_dns_names_alt_names(host: "Host") -> list[DNSName]:
    """Pass 5 — Alt names: add DNS names from the spreadsheet's Alt Names column.

    Each alt name is treated as a FQDN pointing to the host's default
    IPv4 and its associated IPv6 addresses.
    """
    if not host.alt_names or host.default_ipv4 is None:
        return []

    # Find IPv6 addresses for the default IP
    ipv6_addrs: tuple["IPv6Address", ...] = ()
    for iface in host.interfaces:
        if iface.ipv4 == host.default_ipv4:
            ipv6_addrs = tuple(iface.ipv6_addresses)
            break

    names: list[DNSName] = []
    for alt_name in host.alt_names:
        names.append(
            _make_dns_name(
                alt_name,
                host.default_ipv4,
                ipv6_addrs,
                is_fqdn=True,
            )
        )
    return names


def derive_all_dns_names(host: "Host", site: "Site") -> None:
    """Run all five DNS name derivation passes on a host (in-place).

    Order matters: Pass 4 must run after Passes 1-3 since it scans
    all names from previous passes. Pass 5 runs independently.
    """
    domain = site.domain

    # Pass 1 — Hostname
    host.dns_names = derive_dns_names_hostname(host, domain)

    # Pass 2 — Interface
    host.dns_names.extend(derive_dns_names_interface(host, domain))

    # Pass 3 — Subdomain
    host.dns_names.extend(derive_dns_names_subdomain(host, domain, site))

    # Pass 4 — IPv4/IPv6 prefix
    host.dns_names.extend(derive_dns_names_ip_prefix(host, domain))

    # Pass 5 — Alt names
    host.dns_names.extend(derive_dns_names_alt_names(host))
