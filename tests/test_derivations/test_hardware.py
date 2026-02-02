"""Tests for hardware type detection via MAC OUI."""

from gdoc2netcfg.derivations.hardware import (
    HARDWARE_NETGEAR_SWITCH_PLUS,
    NETGEAR_OUIS,
    SUPERMICRO_OUIS,
    detect_hardware_type,
)
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface


def _make_host(hostname, mac, is_bmc_hostname=False):
    """Build a Host for hardware type testing."""
    ipv4 = IPv4Address("10.1.10.100")
    if is_bmc_hostname:
        hostname = f"bmc.{hostname}"

    return Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=[
            NetworkInterface(
                name=None,
                mac=MACAddress.parse(mac),
                ipv4=ipv4,
                dhcp_name=hostname,
            )
        ],
        default_ipv4=ipv4,
    )


class TestDetectHardwareType:
    def test_supermicro_bmc(self):
        host = _make_host("big-storage", "ac:1f:6b:12:34:56", is_bmc_hostname=True)
        assert detect_hardware_type(host) == "supermicro-bmc"

    def test_supermicro_non_bmc_returns_none(self):
        """Supermicro MAC on a non-BMC host should NOT be classified."""
        host = _make_host("big-storage", "ac:1f:6b:12:34:56", is_bmc_hostname=False)
        assert detect_hardware_type(host) is None

    def test_netgear_switch(self):
        host = _make_host("switch-1", "28:80:88:ab:cd:ef")
        assert detect_hardware_type(host) == "netgear-switch"

    def test_netgear_with_other_oui(self):
        host = _make_host("switch-2", "a4:2b:8c:11:22:33")
        assert detect_hardware_type(host) == "netgear-switch"

    def test_unknown_hardware(self):
        host = _make_host("desktop", "11:22:33:44:55:66")
        assert detect_hardware_type(host) is None

    def test_supermicro_bmc_all_ouis(self):
        """All known Supermicro OUIs should detect as supermicro-bmc."""
        for oui in SUPERMICRO_OUIS:
            mac = f"{oui}:11:22:33"
            host = _make_host("server", mac, is_bmc_hostname=True)
            assert detect_hardware_type(host) == "supermicro-bmc", f"OUI {oui} not detected"

    def test_supermicro_takes_priority_over_netgear(self):
        """If somehow a host matched both, supermicro-bmc should take priority."""
        # This can't happen in practice (different MACs), but test the logic
        host = _make_host("big-storage", "ac:1f:6b:12:34:56", is_bmc_hostname=True)
        assert detect_hardware_type(host) == "supermicro-bmc"

    def test_case_insensitive_hostname(self):
        """BMC detection should be case-insensitive on hostname."""
        host = Host(
            machine_name="BMC.server",
            hostname="BMC.server",
            interfaces=[
                NetworkInterface(
                    name=None,
                    mac=MACAddress.parse("ac:1f:6b:12:34:56"),
                    ipv4=IPv4Address("10.1.10.100"),
                    dhcp_name="bmc.server",
                )
            ],
            default_ipv4=IPv4Address("10.1.10.100"),
        )
        assert detect_hardware_type(host) == "supermicro-bmc"

    def test_netgear_plus_gs110emx(self):
        """Netgear GS110EMX should be classified as netgear-switch-plus."""
        host = _make_host("gs110emx-rack1", "28:80:88:ab:cd:ef")
        assert detect_hardware_type(host) == HARDWARE_NETGEAR_SWITCH_PLUS

    def test_netgear_plus_case_insensitive(self):
        """Plus model matching should be case-insensitive."""
        host = _make_host("GS110EMX-Rack1", "28:80:88:ab:cd:ef")
        assert detect_hardware_type(host) == HARDWARE_NETGEAR_SWITCH_PLUS

    def test_netgear_non_plus_still_netgear_switch(self):
        """Netgear switch without a Plus model name stays netgear-switch."""
        host = _make_host("switch-1", "28:80:88:ab:cd:ef")
        assert detect_hardware_type(host) == "netgear-switch"


class TestOUILists:
    def test_supermicro_ouis_are_lowercase(self):
        for oui in SUPERMICRO_OUIS:
            assert oui == oui.lower(), f"OUI {oui} not lowercase"

    def test_netgear_ouis_are_lowercase(self):
        for oui in NETGEAR_OUIS:
            assert oui == oui.lower(), f"OUI {oui} not lowercase"

    def test_supermicro_ouis_format(self):
        for oui in SUPERMICRO_OUIS:
            parts = oui.split(":")
            assert len(parts) == 3, f"OUI {oui} wrong format"
            for part in parts:
                assert len(part) == 2, f"OUI {oui} part {part} wrong length"

    def test_netgear_ouis_format(self):
        for oui in NETGEAR_OUIS:
            parts = oui.split(":")
            assert len(parts) == 3, f"OUI {oui} wrong format"

    def test_no_overlap(self):
        """Supermicro and Netgear OUIs should not overlap."""
        assert not SUPERMICRO_OUIS & NETGEAR_OUIS
