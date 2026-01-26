"""Tests for IP utility functions.

Ported from the doctests in the original dnsmasq.py.
"""

from gdoc2netcfg.utils.ip import ip_sort_key, is_local, is_rfc1918


class TestIpSortKey:
    def test_numeric_ordering(self):
        """ip_sort should sort numerically, not lexicographically."""
        ips = ['10.1.10.104', '10.1.2.2']
        assert sorted(ips, key=ip_sort_key) == ['10.1.2.2', '10.1.10.104']

    def test_returns_tuple(self):
        assert ip_sort_key('10.1.10.104') == (10, 1, 10, 104)

    def test_sorting_across_subnets(self):
        ips = ['10.1.90.1', '10.1.5.1', '10.1.10.1']
        assert sorted(ips, key=ip_sort_key) == ['10.1.5.1', '10.1.10.1', '10.1.90.1']


class TestIsRfc1918:
    def test_10_network(self):
        assert is_rfc1918('10.0.0.1')
        assert is_rfc1918('10.1.10.124')
        assert is_rfc1918('10.255.255.255')

    def test_172_network(self):
        assert is_rfc1918('172.16.0.1')
        assert is_rfc1918('172.31.255.255')
        assert not is_rfc1918('172.32.0.0')
        assert not is_rfc1918('172.15.255.255')

    def test_192_168_network(self):
        assert is_rfc1918('192.168.0.1')
        assert is_rfc1918('192.168.255.255')

    def test_public(self):
        assert not is_rfc1918('8.8.8.8')
        assert not is_rfc1918('1.1.1.1')
        assert not is_rfc1918('203.0.113.1')


class TestIsLocal:
    def test_rfc1918(self):
        """All RFC 1918 addresses are local."""
        assert is_local('10.1.10.1')
        assert is_local('172.16.0.1')
        assert is_local('192.168.1.1')

    def test_link_local(self):
        assert is_local('169.254.1.1')

    def test_ietf_protocol(self):
        assert is_local('192.0.0.1')

    def test_benchmarking(self):
        assert is_local('198.18.0.1')
        assert is_local('198.19.255.255')

    def test_documentation_test_net_2(self):
        assert is_local('198.51.100.1')

    def test_public_addresses_not_local(self):
        assert not is_local('8.8.8.8')
        assert not is_local('1.1.1.1')
        assert not is_local('203.0.113.1')
