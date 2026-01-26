"""Tests for network topology models."""

from gdoc2netcfg.models.network import VLAN, IPv6Prefix, Site


class TestVLAN:
    def test_basic_construction(self):
        vlan = VLAN(id=10, name='int', subdomain='int')
        assert vlan.id == 10
        assert vlan.name == 'int'
        assert vlan.subdomain == 'int'

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
        assert site.vlans == {}
        assert site.ipv6_prefixes == []
        assert site.public_ipv4 is None

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
