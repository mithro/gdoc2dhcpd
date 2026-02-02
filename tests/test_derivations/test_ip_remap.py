"""Tests for IPv4 site remapping."""

from gdoc2netcfg.derivations.ip_remap import collect_native_ips, remap_ipv4_to_site
from gdoc2netcfg.models.addressing import IPv4Address
from gdoc2netcfg.models.network import VLAN, Site
from gdoc2netcfg.sources.parser import DeviceRecord


def _site(site_octet: int) -> Site:
    """Build a minimal Site with typical VLANs for testing."""
    return Site(
        name="test",
        domain="test.mithis.com",
        site_octet=site_octet,
        vlans={
            5: VLAN(id=5, name="net", subdomain="net", third_octets=(5,)),
            10: VLAN(id=10, name="int", subdomain="int",
                     third_octets=(8, 9, 10, 11, 12, 13, 14, 15)),
            90: VLAN(id=90, name="iot", subdomain="iot", third_octets=(90,)),
            31: VLAN(id=31, name="fpgas", subdomain="fpgas",
                     third_octets=(), is_global=True),
            41: VLAN(id=41, name="sm", subdomain="sm",
                     third_octets=(), is_global=True),
        },
    )


class TestRemapIpv4ToSite:
    """Core remapping behaviour."""

    def test_welland_ip_remapped_to_monarto(self):
        """10.1.10.124 → 10.2.10.124 when site_octet=2."""
        site = _site(site_octet=2)
        result = remap_ipv4_to_site(IPv4Address("10.1.10.124"), site)
        assert str(result) == "10.2.10.124"

    def test_monarto_ip_unchanged_on_monarto(self):
        """10.2.10.124 stays 10.2.10.124 when site_octet=2."""
        site = _site(site_octet=2)
        result = remap_ipv4_to_site(IPv4Address("10.2.10.124"), site)
        assert str(result) == "10.2.10.124"

    def test_welland_ip_unchanged_on_welland(self):
        """10.1.10.124 stays 10.1.10.124 when site_octet=1."""
        site = _site(site_octet=1)
        result = remap_ipv4_to_site(IPv4Address("10.1.10.124"), site)
        assert str(result) == "10.1.10.124"

    def test_monarto_ip_remapped_to_welland(self):
        """10.2.90.5 → 10.1.90.5 when site_octet=1."""
        site = _site(site_octet=1)
        result = remap_ipv4_to_site(IPv4Address("10.2.90.5"), site)
        assert str(result) == "10.1.90.5"


class TestRemapPreservesGlobalVlans:
    """Global VLAN addresses must not be remapped."""

    def test_fpgas_vlan_untouched(self):
        """10.31.0.101 stays 10.31.0.101 regardless of site_octet."""
        site = _site(site_octet=2)
        result = remap_ipv4_to_site(IPv4Address("10.31.0.101"), site)
        assert str(result) == "10.31.0.101"

    def test_sm_vlan_untouched(self):
        """10.41.1.18 stays 10.41.1.18."""
        site = _site(site_octet=2)
        result = remap_ipv4_to_site(IPv4Address("10.41.1.18"), site)
        assert str(result) == "10.41.1.18"

    def test_fpgas_untouched_on_welland(self):
        site = _site(site_octet=1)
        result = remap_ipv4_to_site(IPv4Address("10.31.0.101"), site)
        assert str(result) == "10.31.0.101"


class TestRemapNonTenAddresses:
    """Non-10.X.X.X addresses pass through unchanged."""

    def test_private_172(self):
        site = _site(site_octet=2)
        result = remap_ipv4_to_site(IPv4Address("172.16.1.1"), site)
        assert str(result) == "172.16.1.1"

    def test_public_ip(self):
        site = _site(site_octet=2)
        result = remap_ipv4_to_site(IPv4Address("8.8.8.8"), site)
        assert str(result) == "8.8.8.8"

    def test_loopback(self):
        site = _site(site_octet=2)
        result = remap_ipv4_to_site(IPv4Address("127.0.0.1"), site)
        assert str(result) == "127.0.0.1"


class TestRemapPreservesThirdAndFourthOctets:
    """Remapping only changes the second octet."""

    def test_various_third_octets(self):
        site = _site(site_octet=2)
        for third in [1, 5, 6, 7, 10, 20, 90, 99]:
            result = remap_ipv4_to_site(
                IPv4Address(f"10.1.{third}.200"), site
            )
            assert str(result) == f"10.2.{third}.200"

    def test_fourth_octet_preserved(self):
        site = _site(site_octet=2)
        for fourth in [1, 100, 200, 254]:
            result = remap_ipv4_to_site(
                IPv4Address(f"10.1.90.{fourth}"), site
            )
            assert str(result) == f"10.2.90.{fourth}"


def _record(ip: str, mac: str = "00:11:22:33:44:55", machine: str = "dev") -> DeviceRecord:
    """Build a minimal DeviceRecord for testing."""
    return DeviceRecord(
        sheet_name="network",
        row_number=1,
        machine=machine,
        mac_address=mac,
        ip=ip,
    )


class TestCollectNativeIps:
    """Tests for collect_native_ips — finding IPs already at the site's octet."""

    def test_monarto_ips_native_on_monarto(self):
        """10.2.X.X IPs are native when site_octet=2."""
        site = _site(site_octet=2)
        records = [
            _record("10.2.10.11"),
            _record("10.2.90.5"),
        ]
        native = collect_native_ips(records, site)
        assert native == frozenset({"10.2.10.11", "10.2.90.5"})

    def test_welland_ips_not_native_on_monarto(self):
        """10.1.X.X IPs are not native when site_octet=2."""
        site = _site(site_octet=2)
        records = [_record("10.1.10.11"), _record("10.1.90.5")]
        native = collect_native_ips(records, site)
        assert native == frozenset()

    def test_mixed_sites(self):
        """Only IPs matching site_octet are collected."""
        site = _site(site_octet=2)
        records = [
            _record("10.1.10.11"),  # welland — not native
            _record("10.2.10.11"),  # monarto — native
            _record("10.31.0.101"),  # global — not native (octet 31 != 2)
            _record("10.2.90.5"),   # monarto — native
        ]
        native = collect_native_ips(records, site)
        assert native == frozenset({"10.2.10.11", "10.2.90.5"})

    def test_empty_records(self):
        site = _site(site_octet=2)
        assert collect_native_ips([], site) == frozenset()

    def test_records_with_missing_ip(self):
        """Records with empty IP are skipped."""
        site = _site(site_octet=2)
        records = [DeviceRecord(sheet_name="network", row_number=1, ip="")]
        assert collect_native_ips(records, site) == frozenset()

    def test_non_10_ips_ignored(self):
        """172.X and other non-10.X IPs are never native."""
        site = _site(site_octet=2)
        records = [_record("172.16.2.1"), _record("192.168.2.1")]
        assert collect_native_ips(records, site) == frozenset()


class TestRemapCollisionDetection:
    """Remap returns None when the target IP already exists natively."""

    def test_collision_returns_none(self):
        """10.1.10.11 → None when 10.2.10.11 is a native IP (site_octet=2)."""
        site = _site(site_octet=2)
        native = frozenset({"10.2.10.11"})
        result = remap_ipv4_to_site(
            IPv4Address("10.1.10.11"), site, native_ips=native
        )
        assert result is None

    def test_no_collision_still_remaps(self):
        """10.1.10.124 → 10.2.10.124 when 10.2.10.124 is NOT a native IP."""
        site = _site(site_octet=2)
        native = frozenset({"10.2.10.11"})  # different IP
        result = remap_ipv4_to_site(
            IPv4Address("10.1.10.124"), site, native_ips=native
        )
        assert str(result) == "10.2.10.124"

    def test_native_ip_passes_through(self):
        """10.2.10.11 stays 10.2.10.11 — it IS the native IP, not a collision."""
        site = _site(site_octet=2)
        native = frozenset({"10.2.10.11"})
        result = remap_ipv4_to_site(
            IPv4Address("10.2.10.11"), site, native_ips=native
        )
        assert str(result) == "10.2.10.11"

    def test_global_vlan_never_collides(self):
        """Global VLANs are not remapped, so collision check doesn't apply."""
        site = _site(site_octet=2)
        native = frozenset({"10.2.0.101"})  # irrelevant
        result = remap_ipv4_to_site(
            IPv4Address("10.31.0.101"), site, native_ips=native
        )
        assert str(result) == "10.31.0.101"

    def test_empty_native_ips_no_collision(self):
        """Default empty native_ips means no collision detection."""
        site = _site(site_octet=2)
        result = remap_ipv4_to_site(IPv4Address("10.1.10.11"), site)
        assert str(result) == "10.2.10.11"

    def test_multiple_collisions(self):
        """Multiple native IPs all cause collision returns."""
        site = _site(site_octet=2)
        native = frozenset({"10.2.10.11", "10.2.90.5", "10.2.5.1"})
        for welland_ip, expected_none in [
            ("10.1.10.11", True),   # collides with 10.2.10.11
            ("10.1.90.5", True),    # collides with 10.2.90.5
            ("10.1.5.1", True),     # collides with 10.2.5.1
            ("10.1.10.124", False), # no collision
        ]:
            result = remap_ipv4_to_site(
                IPv4Address(welland_ip), site, native_ips=native
            )
            if expected_none:
                assert result is None, f"{welland_ip} should collide"
            else:
                assert result is not None, f"{welland_ip} should not collide"
