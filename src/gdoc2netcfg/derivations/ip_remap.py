"""IPv4 site remapping: translate addresses to the current site's address space.

When multiple sites share a single VLAN Allocations spreadsheet, device
IPs may be recorded with one site's second octet (e.g. 10.1.X.X for
welland).  This module remaps site-local addresses to the current site
(e.g. 10.2.X.X for monarto) while leaving global VLAN addresses
(e.g. 10.31.X.X) untouched.
"""

from __future__ import annotations

from gdoc2netcfg.models.addressing import IPv4Address
from gdoc2netcfg.models.network import Site


def remap_ipv4_to_site(ipv4: IPv4Address, site: Site) -> IPv4Address:
    """Remap a site-local IPv4 address to the current site's address space.

    Site-local addresses (10.{any_site_octet}.Y.Z) are remapped to
    10.{site.site_octet}.Y.Z.  Global VLAN addresses where the second
    octet is a global VLAN ID (e.g. 10.31.X.X) are not remapped.

    Args:
        ipv4: The original IPv4 address from the spreadsheet.
        site: The current site configuration (provides site_octet and VLANs).

    Returns:
        The remapped IPv4Address, or the original if no remapping needed.
    """
    a, b, c, d = ipv4.octets

    if a != 10:
        return ipv4

    # Already matches this site — no remapping needed
    if b == site.site_octet:
        return ipv4

    # Don't remap global VLAN addresses (second octet = VLAN ID)
    for vlan in site.vlans.values():
        if vlan.is_global and b == vlan.id:
            return ipv4

    # Remap site-local address to this site
    return IPv4Address(f"10.{site.site_octet}.{c}.{d}")
