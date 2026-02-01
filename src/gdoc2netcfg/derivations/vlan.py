"""IP → VLAN derivation and VLAN builder.

Determines VLAN assignment based on IP address subnet.
Also provides builder functions to convert VLANDefinition records
(from the VLAN Allocations sheet) into VLAN model objects.
"""

from __future__ import annotations

import ipaddress

from gdoc2netcfg.models.addressing import IPv4Address
from gdoc2netcfg.models.network import VLAN, Site
from gdoc2netcfg.sources.vlan_parser import VLANDefinition


def ip_to_vlan_id(ipv4: IPv4Address, site: Site) -> int | None:
    """Determine the VLAN ID for an IPv4 address.

    Uses the site's VLAN definitions. The mapping rules:
    - 10.31.x.x → VLAN 31 (sm)
    - 10.41.x.x → VLAN 41 (fpgas)
    - 10.1.1.x → VLAN 1 (tmp)
    - 10.1.5.x → VLAN 5 (net)
    - 10.1.6.x → VLAN 6 (pwr)
    - 10.1.10-17.x → VLAN 10 (int)
    - 10.1.20.x → VLAN 20 (roam)
    - 10.1.90.x → VLAN 90 (iot)
    - 10.1.99.x → VLAN 99 (guest)

    Returns None if the IP doesn't map to a known VLAN.
    """
    a, b, c, d = ipv4.octets

    if a != 10:
        return None

    # Check for non-1 second octet (sm, fpgas)
    if b == 31:
        return 31
    if b == 41:
        return 41

    if b != 1:
        return None

    # 10.1.X.Y - check third octet
    if c == 1:
        return 1   # tmp
    if c == 5:
        return 5   # net
    if c == 6:
        return 6   # pwr
    if c == 20:
        return 20  # roam
    if c == 90:
        return 90  # iot
    if c == 99:
        return 99  # guest

    # 10.1.10-17.x = br-int (VLAN 10)
    if 10 <= c <= 17:
        return 10

    return None


def ip_to_subdomain(ipv4: IPv4Address, site: Site) -> str | None:
    """Get the network subdomain for an IP address.

    Uses the site's network_subdomains mapping (third octet → subdomain).
    Only applies to addresses in the 10.1.x.x range.

    Returns None if no subdomain mapping exists.
    """
    a, b, c, d = ipv4.octets
    if a != 10 or b != 1:
        return None
    return site.network_subdomains.get(c)


# ---------------------------------------------------------------------------
# VLAN builder: VLANDefinition → VLAN model objects
# ---------------------------------------------------------------------------

def _compute_third_octets(ip_range: str, cidr: str, site_octet: int) -> tuple[int, ...]:
    """Compute which third-octet values a VLAN covers from its IP range and CIDR.

    Uses ipaddress.ip_network to determine the full range. For example,
    IP range '10.1.10.X' with CIDR '/21' gives network 10.1.8.0/21,
    which covers third octets 8-15.

    For /24 ranges, returns a single-element tuple with the third octet.
    """
    # Build a concrete network address from the IP range pattern
    # Replace 'X' placeholders with '0' to form a valid address
    base_ip = ip_range.replace("X", "0")
    prefix_len = cidr.lstrip("/")
    try:
        network = ipaddress.ip_network(f"{base_ip}/{prefix_len}", strict=False)
    except ValueError:
        # Fallback: extract third octet from IP range directly
        parts = ip_range.split(".")
        if len(parts) >= 3:
            try:
                return (int(parts[2]),)
            except ValueError:
                pass
        return ()

    # Enumerate all third-octet values the network covers
    first_ip = int(network.network_address)
    last_ip = int(network.broadcast_address)
    first_third = (first_ip >> 8) & 0xFF
    last_third = (last_ip >> 8) & 0xFF
    return tuple(range(first_third, last_third + 1))


def _is_global_vlan(ip_range: str, site_octet: int) -> bool:
    """Determine if a VLAN is global (second octet != site_octet).

    Global VLANs like 10.31.X.X match on the second octet rather than
    the third octet within the site's address space.
    """
    parts = ip_range.split(".")
    if len(parts) < 2:
        return False
    try:
        second_octet = int(parts[1])
    except ValueError:
        return False
    return second_octet != site_octet


def build_vlans_from_definitions(
    definitions: list[VLANDefinition],
    site_octet: int,
) -> dict[int, VLAN]:
    """Convert VLANDefinition records into VLAN model objects.

    Computes third_octets from IP Range + CIDR, and detects global VLANs
    where the second octet differs from the site_octet.
    """
    vlans: dict[int, VLAN] = {}
    for defn in definitions:
        is_global = _is_global_vlan(defn.ip_range, site_octet)

        if is_global:
            third_octets: tuple[int, ...] = ()
        else:
            third_octets = _compute_third_octets(defn.ip_range, defn.cidr, site_octet)

        vlans[defn.id] = VLAN(
            id=defn.id,
            name=defn.name,
            subdomain=defn.name,
            third_octets=third_octets,
            is_global=is_global,
        )
    return vlans


def build_network_subdomains(vlans: dict[int, VLAN]) -> dict[int, str]:
    """Derive third-octet → subdomain mapping from VLAN definitions.

    For each non-global VLAN, maps all its covered third octets to
    the VLAN's name (used as the subdomain).
    """
    mapping: dict[int, str] = {}
    for vlan in vlans.values():
        if vlan.is_global:
            continue
        for octet in vlan.covered_third_octets:
            mapping[octet] = vlan.name
    return mapping
