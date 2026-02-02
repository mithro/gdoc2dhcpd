"""Hardware type detection via MAC OUI prefix matching.

Classifies hosts by hardware type based on the first 3 bytes (OUI) of
their MAC addresses. Used by generators to apply hardware-specific
configuration (e.g. certbot deploy hooks for Supermicro BMCs).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gdoc2netcfg.models.host import Host

# Hardware type constants — use these in generators for matching
HARDWARE_SUPERMICRO_BMC = "supermicro-bmc"
HARDWARE_NETGEAR_SWITCH = "netgear-switch"
HARDWARE_NETGEAR_SWITCH_PLUS = "netgear-switch-plus"

# Netgear Plus/unmanaged models that lack SNMP support.
# Matched case-insensitively against the hostname.
NETGEAR_PLUS_MODELS: set[str] = {
    "gs110emx",
}

# IEEE OUI prefixes registered to Super Micro Computer, Inc.
# Source: https://maclookup.app/vendors/super-micro-computer-inc
SUPERMICRO_OUIS: set[str] = {
    "00:25:90",
    "00:30:48",
    "0c:c4:7a",
    "3c:ec:ef",
    "7c:c2:55",
    "90:5a:08",
    "ac:1f:6b",
}

# IEEE OUI prefixes registered to NETGEAR.
# Source: https://maclookup.app/vendors/netgear
NETGEAR_OUIS: set[str] = {
    "00:09:5b", "00:0f:b5", "00:14:6c", "00:18:4d", "00:1b:2f",
    "00:1e:2a", "00:1f:33", "00:22:3f", "00:24:b2", "00:26:f2",
    "00:8e:f2", "04:a1:51", "08:02:8e", "08:36:c9", "08:bd:43",
    "10:0c:6b", "10:0d:7f", "10:da:43", "14:59:c0", "20:0c:c8",
    "20:4e:7f", "20:e5:2a", "28:80:88", "28:94:01", "28:c6:8e",
    "2c:30:33", "2c:b0:5d", "30:46:9a", "34:98:b5", "38:94:ed",
    "3c:37:86", "40:5d:82", "44:94:fc", "44:a5:6e", "4c:60:de",
    "50:4a:6e", "50:6a:03", "54:07:7d", "6c:b0:ce", "6c:cd:d6",
    "74:44:01", "78:d2:94", "80:37:73", "80:cc:9c", "84:1b:5e",
    "8c:3b:ad", "94:18:65", "94:3b:22", "94:a6:7e", "9c:3d:cf",
    "9c:c9:eb", "9c:d3:6d", "a0:04:60", "a0:21:b7", "a0:40:a0",
    "a0:63:91", "a4:2b:8c", "b0:39:56", "b0:7f:b9", "b0:b9:8a",
    "bc:a5:11", "c0:3f:0e", "c0:ff:d4", "c4:04:15", "c4:3d:c7",
    "c8:10:2f", "c8:9e:43", "cc:40:d0", "dc:ef:09", "e0:46:9a",
    "e0:46:ee", "e0:91:f5", "e0:c2:50", "e4:f4:c6", "e8:fc:af",
    "f8:73:94",
}


def _mac_oui(mac_address: str) -> str:
    """Extract the OUI prefix (first 3 octets) from a MAC address."""
    return mac_address[:8].lower()


def detect_hardware_type(host: "Host") -> str | None:
    """Classify host by MAC OUI prefix.

    Returns:
        "supermicro-bmc" if host has a BMC hostname AND a Supermicro OUI.
        "netgear-switch-plus" if any interface has a Netgear OUI and hostname
            matches a known Plus/unmanaged model.
        "netgear-switch" if any interface has a Netgear OUI.
        None if no match.

    Supermicro detection requires the hostname to contain 'bmc' (indicating
    a BMC host) AND a MAC OUI match. This avoids classifying regular
    Supermicro server NICs as BMCs.
    """
    ouis = {_mac_oui(str(mac)) for mac in host.all_macs}

    # Supermicro BMC: must be a BMC host with a Supermicro OUI
    is_bmc_host = "bmc" in host.hostname.lower()
    if is_bmc_host and ouis & SUPERMICRO_OUIS:
        return HARDWARE_SUPERMICRO_BMC

    # Netgear switch: any interface with a Netgear OUI
    # Plus/unmanaged models get a separate type (no SNMP, no cert deploy)
    if ouis & NETGEAR_OUIS:
        hostname_lower = host.hostname.lower()
        for model in NETGEAR_PLUS_MODELS:
            if model in hostname_lower:
                return HARDWARE_NETGEAR_SWITCH_PLUS
        return HARDWARE_NETGEAR_SWITCH

    return None
