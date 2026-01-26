"""Tests for network address types."""

import pytest

from gdoc2netcfg.models.addressing import IPv4Address, IPv6Address, MACAddress


class TestMACAddress:
    def test_parse_colon_separated(self):
        mac = MACAddress.parse('AA:BB:CC:DD:EE:FF')
        assert mac.address == 'aa:bb:cc:dd:ee:ff'

    def test_parse_dash_separated(self):
        mac = MACAddress.parse('aa-bb-cc-dd-ee-ff')
        assert mac.address == 'aa:bb:cc:dd:ee:ff'

    def test_parse_dot_separated(self):
        mac = MACAddress.parse('aabb.ccdd.eeff')
        assert mac.address == 'aa:bb:cc:dd:ee:ff'

    def test_parse_strips_whitespace(self):
        mac = MACAddress.parse('  aa:bb:cc:dd:ee:ff  ')
        assert mac.address == 'aa:bb:cc:dd:ee:ff'

    def test_parse_invalid_too_short(self):
        with pytest.raises(ValueError, match="Invalid MAC"):
            MACAddress.parse('aa:bb:cc')

    def test_parse_invalid_chars(self):
        with pytest.raises(ValueError, match="Invalid MAC"):
            MACAddress.parse('gg:hh:ii:jj:kk:ll')

    def test_direct_construction_validates(self):
        with pytest.raises(ValueError, match="Invalid MAC"):
            MACAddress('not-a-mac')

    def test_frozen(self):
        mac = MACAddress.parse('aa:bb:cc:dd:ee:ff')
        with pytest.raises(AttributeError):
            mac.address = 'new'  # type: ignore[misc]

    def test_equality(self):
        mac1 = MACAddress.parse('AA:BB:CC:DD:EE:FF')
        mac2 = MACAddress.parse('aa:bb:cc:dd:ee:ff')
        assert mac1 == mac2

    def test_hashable(self):
        mac1 = MACAddress.parse('aa:bb:cc:dd:ee:ff')
        mac2 = MACAddress.parse('AA:BB:CC:DD:EE:FF')
        assert hash(mac1) == hash(mac2)
        assert len({mac1, mac2}) == 1

    def test_ordering(self):
        mac_low = MACAddress.parse('00:00:00:00:00:01')
        mac_high = MACAddress.parse('ff:ff:ff:ff:ff:ff')
        assert mac_low < mac_high

    def test_to_int(self):
        assert MACAddress.parse('00:00:00:00:00:01').to_int() == 1
        assert MACAddress.parse('ff:ff:ff:ff:ff:ff').to_int() == 281474976710655

    def test_from_int(self):
        mac = MACAddress.from_int(1)
        assert mac.address == '00:00:00:00:00:01'

    def test_to_int_roundtrip(self):
        mac = MACAddress.parse('aa:bb:cc:dd:ee:ff')
        assert MACAddress.from_int(mac.to_int()) == mac

    def test_prefix_24(self):
        mac = MACAddress.parse('aa:bb:cc:dd:ee:ff')
        assert mac.prefix(24) == 0xaabbcc000000

    def test_prefix_48(self):
        mac = MACAddress.parse('aa:bb:cc:dd:ee:ff')
        assert mac.prefix(48) == 0xaabbccddeeff

    def test_prefix_40(self):
        mac = MACAddress.parse('aa:bb:cc:dd:ee:ff')
        assert mac.prefix(40) == 0xaabbccddee00

    def test_str(self):
        mac = MACAddress.parse('AA:BB:CC:DD:EE:FF')
        assert str(mac) == 'aa:bb:cc:dd:ee:ff'


class TestIPv4Address:
    def test_basic_construction(self):
        ip = IPv4Address('10.1.10.124')
        assert ip.address == '10.1.10.124'

    def test_rejects_leading_zeros(self):
        """Leading zeros are ambiguous (octal?) and rejected by ipaddress."""
        with pytest.raises(ValueError):
            IPv4Address('010.001.010.001')

    def test_invalid_address(self):
        with pytest.raises(ValueError):
            IPv4Address('not.an.ip')

    def test_invalid_range(self):
        with pytest.raises(ValueError):
            IPv4Address('256.1.1.1')

    def test_octets(self):
        ip = IPv4Address('10.1.10.124')
        assert ip.octets == (10, 1, 10, 124)

    def test_is_local_rfc1918(self):
        assert IPv4Address('10.1.10.1').is_local()
        assert IPv4Address('172.16.0.1').is_local()
        assert IPv4Address('192.168.1.1').is_local()

    def test_is_local_link_local(self):
        assert IPv4Address('169.254.1.1').is_local()

    def test_is_local_public(self):
        assert not IPv4Address('8.8.8.8').is_local()
        assert not IPv4Address('203.0.113.1').is_local()

    def test_is_rfc1918(self):
        assert IPv4Address('10.1.10.1').is_rfc1918()
        assert not IPv4Address('8.8.8.8').is_rfc1918()

    def test_ordering(self):
        ip1 = IPv4Address('10.1.2.2')
        ip2 = IPv4Address('10.1.10.104')
        assert ip1 < ip2

    def test_frozen(self):
        ip = IPv4Address('10.1.10.1')
        with pytest.raises(AttributeError):
            ip.address = '10.1.10.2'  # type: ignore[misc]

    def test_equality(self):
        ip1 = IPv4Address('10.1.10.1')
        ip2 = IPv4Address('10.1.10.1')
        assert ip1 == ip2

    def test_str(self):
        ip = IPv4Address('10.1.10.124')
        assert str(ip) == '10.1.10.124'

    def test_repr(self):
        ip = IPv4Address('10.1.10.124')
        assert repr(ip) == "IPv4Address('10.1.10.124')"


class TestIPv6Address:
    def test_basic_construction(self):
        addr = IPv6Address('2404:e80:a137:110::124', '2404:e80:a137:')
        assert addr.address == '2404:e80:a137:110::124'
        assert addr.prefix == '2404:e80:a137:'

    def test_exploded(self):
        addr = IPv6Address('2404:e80:a137:110::124', '2404:e80:a137:')
        assert addr.exploded == '2404:0e80:a137:0110:0000:0000:0000:0124'

    def test_to_ptr(self):
        addr = IPv6Address('2404:e80:a137:110::124', '2404:e80:a137:')
        expected = '4.2.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.1.0.7.3.1.a.0.8.e.0.4.0.4.2.ip6.arpa'
        assert addr.to_ptr() == expected

    def test_str(self):
        addr = IPv6Address('2404:e80:a137:110::124', '2404:e80:a137:')
        assert str(addr) == '2404:e80:a137:110::124'
