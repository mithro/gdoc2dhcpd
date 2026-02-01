"""Tests for network topology models."""

from gdoc2netcfg.models.network import VLAN, IPv6Prefix, Site


class TestVLAN:
    def test_basic_construction(self):
        vlan = VLAN(id=10, name='int', subdomain='int')
        assert vlan.id == 10
        assert vlan.name == 'int'
        assert vlan.subdomain == 'int'
        assert vlan.third_octets == ()
        assert vlan.is_global is False

    def test_with_third_octets(self):
        vlan = VLAN(id=10, name='int', subdomain='int', third_octets=(8, 9, 10, 11, 12, 13, 14, 15))
        assert vlan.third_octets == (8, 9, 10, 11, 12, 13, 14, 15)

    def test_global_vlan(self):
        vlan = VLAN(id=31, name='fpgas', subdomain='fpgas', is_global=True)
        assert vlan.is_global is True

    def test_covered_third_octets_default(self):
        """Without explicit third_octets, falls back to (id,)."""
        vlan = VLAN(id=5, name='net', subdomain='net')
        assert vlan.covered_third_octets == (5,)

    def test_covered_third_octets_explicit(self):
        vlan = VLAN(id=10, name='int', subdomain='int', third_octets=(8, 9, 10, 11, 12, 13, 14, 15))
        assert vlan.covered_third_octets == (8, 9, 10, 11, 12, 13, 14, 15)

    def test_covered_third_octets_global(self):
        """Global VLANs return empty tuple (they match on second octet)."""
        vlan = VLAN(id=31, name='fpgas', subdomain='fpgas', is_global=True)
        assert vlan.covered_third_octets == ()

    def test_str(self):
        vlan = VLAN(id=10, name='int', subdomain='int')
        assert str(vlan) == 'VLAN 10 (int)'

    def test_frozen(self):
        import pytest

        vlan = VLAN(id=10, name='int', subdomain='int')
        with pytest.raises(AttributeError):
            vlan.id = 20  # type: ignore[misc]


class TestIPv6Prefix:
    def test_basic_construction(self):
        prefix = IPv6Prefix(prefix='2404:e80:a137:', name='Launtel')
        assert prefix.prefix == '2404:e80:a137:'
        assert prefix.name == 'Launtel'
        assert prefix.enabled is True

    def test_disabled(self):
        prefix = IPv6Prefix(prefix='2001:470:82b3:', name='HE.net', enabled=False)
        assert prefix.enabled is False

    def test_str_enabled(self):
        prefix = IPv6Prefix(prefix='2404:e80:a137:', name='Launtel')
        assert 'enabled' in str(prefix)

    def test_str_disabled(self):
        prefix = IPv6Prefix(prefix='2001:470:82b3:', name='HE.net', enabled=False)
        assert 'disabled' in str(prefix)


class TestSite:
    def test_basic_construction(self):
        site = Site(name='welland', domain='welland.mithis.com')
        assert site.name == 'welland'
        assert site.domain == 'welland.mithis.com'
        assert site.site_octet == 0
        assert site.vlans == {}
        assert site.ipv6_prefixes == []
        assert site.public_ipv4 is None

    def test_site_octet(self):
        site = Site(name='welland', domain='welland.mithis.com', site_octet=1)
        assert site.site_octet == 1

    def test_active_ipv6_prefixes(self):
        site = Site(
            name='welland',
            domain='welland.mithis.com',
            ipv6_prefixes=[
                IPv6Prefix(prefix='2404:e80:a137:', name='Launtel', enabled=True),
                IPv6Prefix(prefix='2001:470:82b3:', name='HE.net', enabled=False),
            ],
        )
        active = site.active_ipv6_prefixes
        assert len(active) == 1
        assert active[0].name == 'Launtel'

    def test_with_vlans(self):
        vlan = VLAN(id=10, name='int', subdomain='int')
        site = Site(
            name='welland',
            domain='welland.mithis.com',
            vlans={10: vlan},
        )
        assert 10 in site.vlans
        assert site.vlans[10].name == 'int'

    def test_vlan_by_name(self):
        site = Site(
            name='welland',
            domain='welland.mithis.com',
            vlans={
                5: VLAN(id=5, name='net', subdomain='net'),
                10: VLAN(id=10, name='int', subdomain='int'),
            },
        )
        assert site.vlan_by_name('net').id == 5
        assert site.vlan_by_name('int').id == 10
        assert site.vlan_by_name('nonexistent') is None

    def test_ip_prefix_for_vlan(self):
        site = Site(
            name='welland',
            domain='welland.mithis.com',
            site_octet=1,
            vlans={
                5: VLAN(id=5, name='net', subdomain='net'),
                31: VLAN(id=31, name='fpgas', subdomain='fpgas', is_global=True),
            },
        )
        assert site.ip_prefix_for_vlan('net') == '10.1.5.'
        assert site.ip_prefix_for_vlan('fpgas') is None  # global VLAN
        assert site.ip_prefix_for_vlan('nonexistent') is None

    def test_ip_prefix_for_vlan_monarto(self):
        site = Site(
            name='monarto',
            domain='monarto.mithis.com',
            site_octet=2,
            vlans={5: VLAN(id=5, name='net', subdomain='net')},
        )
        assert site.ip_prefix_for_vlan('net') == '10.2.5.'
