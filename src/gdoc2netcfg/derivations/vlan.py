"""IP → VLAN derivation.

Determines VLAN assignment based on IP address subnet.
"""

from __future__ import annotations

from gdoc2netcfg.models.addressing import IPv4Address
from gdoc2netcfg.models.network import Site


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
