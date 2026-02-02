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

    Uses the site's VLAN definitions to match:
    1. Global VLANs: second octet matches a global VLAN's ID (e.g. 10.31.X.X → VLAN 31)
    2. Site VLANs: second octet matches site_octet, third octet falls within
       a VLAN's covered_third_octets (e.g. 10.1.10.X → VLAN 10 for site_octet=1)

    Returns None if the IP doesn't map to a known VLAN.
    """
    a, b, c, d = ipv4.octets

    if a != 10:
        return None

    # Check global VLANs first (match on second octet)
    for vlan in site.vlans.values():
        if vlan.is_global and b == vlan.id:
            return vlan.id

    # Check site-local VLANs (second octet must match site_octet)
    if b != site.site_octet:
        return None

    for vlan in site.vlans.values():
        if not vlan.is_global and c in vlan.covered_third_octets:
            return vlan.id

    return None


def ip_to_subdomain(ipv4: IPv4Address, site: Site) -> str | None:
    """Get the network subdomain for an IP address.

    Uses the site's network_subdomains mapping (third octet → subdomain).
    Only applies to addresses in the site's address space (10.{site_octet}.X.Y).

    Returns None if no subdomain mapping exists.
    """
    a, b, c, d = ipv4.octets
    if a != 10 or b != site.site_octet:
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


def _is_global_vlan(cidr: str) -> bool:
    """Determine if a VLAN is global based on its CIDR prefix length.

    Global VLANs use /16 or larger prefixes (e.g. 10.31.0.0/16) and are
    addressed by second octet rather than third octet within a site's
    address space.  Site-local VLANs use narrower prefixes (/17 or
    smaller, e.g. /21, /24).

    This makes VLAN classification site-agnostic: the same spreadsheet
    definitions work for any site regardless of which site's IP ranges
    appear in the IP Range column.
    """
    prefix_len = cidr.lstrip("/")
    try:
        return int(prefix_len) <= 16
    except ValueError:
        return False


def build_vlans_from_definitions(
    definitions: list[VLANDefinition],
    site_octet: int,
) -> dict[int, VLAN]:
    """Convert VLANDefinition records into VLAN model objects.

    Computes third_octets from IP Range + CIDR, and detects global VLANs
    by CIDR prefix length (/16 or larger = global).
    """
    vlans: dict[int, VLAN] = {}
    for defn in definitions:
        is_global = _is_global_vlan(defn.cidr)

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
