"""IPv4 site remapping: translate addresses to the current site's address space.

When multiple sites share a single spreadsheet, device IPs may be recorded
with one site's second octet (e.g. 10.1.X.X for welland).  This module
remaps site-local addresses to the current site (e.g. 10.2.X.X for monarto)
while leaving global VLAN addresses (e.g. 10.31.X.X) untouched.

Site-specific devices may appear in the shared sheet with their own site's
IPs (e.g. monarto's gateway at 10.2.10.1).  When generating for that site,
records from other sites whose IPs would remap to an already-present native
IP are skipped to avoid collisions.
"""

from __future__ import annotations

from gdoc2netcfg.models.addressing import IPv4Address
from gdoc2netcfg.models.network import Site
from gdoc2netcfg.sources.parser import DeviceRecord


def _is_global_ip(ipv4_octets: tuple[int, ...], site: Site) -> bool:
    """Check if an IP belongs to a global VLAN (second octet = VLAN ID)."""
    b = ipv4_octets[1]
    for vlan in site.vlans.values():
        if vlan.is_global and b == vlan.id:
            return True
    return False


def collect_native_ips(records: list[DeviceRecord], site: Site) -> frozenset[str]:
    """Collect IPs that already match the current site's address space.

    These are IPs where the second octet equals site_octet — they don't
    need remapping and represent the "ground truth" for this site.
    """
    native: set[str] = set()
    for record in records:
        if not record.ip:
            continue
        parts = record.ip.split(".")
        if len(parts) != 4:
            continue
        try:
            if int(parts[0]) == 10 and int(parts[1]) == site.site_octet:
                native.add(record.ip)
        except ValueError:
            continue
    return frozenset(native)


def remap_ipv4_to_site(
    ipv4: IPv4Address,
    site: Site,
    *,
    native_ips: frozenset[str] = frozenset(),
) -> IPv4Address | None:
    """Remap a site-local IPv4 address to the current site's address space.

    Site-local addresses (10.{any_site_octet}.Y.Z) are remapped to
    10.{site.site_octet}.Y.Z.  Global VLAN addresses where the second
    octet is a global VLAN ID (e.g. 10.31.X.X) are not remapped.

    If the remapped IP would collide with a native IP (one already at
    the correct site_octet in the raw data), returns None to signal
    that this record should be skipped — it's a site-specific duplicate
    from another site.

    Args:
        ipv4: The original IPv4 address from the spreadsheet.
        site: The current site configuration (provides site_octet and VLANs).
        native_ips: Set of IP strings already at the correct site_octet.

    Returns:
        The remapped IPv4Address, the original if no remapping needed,
        or None if the record should be skipped (collision with native IP).
    """
    a, b, c, d = ipv4.octets

    if a != 10:
        return ipv4

    # Already matches this site — no remapping needed
    if b == site.site_octet:
        return ipv4

    # Don't remap global VLAN addresses (second octet = VLAN ID)
    if _is_global_ip((a, b, c, d), site):
        return ipv4

    # Check if remapping would collide with a native IP
    remapped = f"10.{site.site_octet}.{c}.{d}"
    if native_ips and remapped in native_ips:
        return None

    return IPv4Address(remapped)
