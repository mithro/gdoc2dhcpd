"""Default IP selection for multi-interface hosts.

When a host has multiple network interfaces, this determines which IPv4
address should be used for the bare hostname (e.g. 'desktop.welland.mithis.com'
without an interface prefix).

Priority:
1. Public IP (non-local) — if a host has a public IP, use it
2. Interface with no name (None) — the "default" interface
3. First private IP by numeric sort — fallback
"""

from __future__ import annotations

from gdoc2netcfg.models.addressing import IPv4Address
from gdoc2netcfg.utils.ip import ip_sort_key


def select_default_ip(interface_ips: dict[str | None, IPv4Address]) -> IPv4Address:
    """Select the default IPv4 address for a host.

    Args:
        interface_ips: Map of interface name → IPv4 address.
            None key means the default/only interface.

    Returns:
        The selected default IPv4 address.

    Raises:
        ValueError: If interface_ips is empty.
    """
    if not interface_ips:
        raise ValueError("No interfaces to select from")

    # Priority 1: Public IP
    public_ips = [ip for ip in interface_ips.values() if not ip.is_local()]
    if public_ips:
        return public_ips[0]

    # Priority 2: No-name interface (default)
    if None in interface_ips:
        return interface_ips[None]

    # Priority 3: First private IP by numeric sort
    sorted_ips = sorted(interface_ips.values(), key=lambda ip: ip_sort_key(ip.address))
    return sorted_ips[0]
