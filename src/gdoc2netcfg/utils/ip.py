"""IP address utility functions shared across the package."""

from __future__ import annotations


def ip_sort_key(ip: str) -> tuple[int, ...]:
    """Return a sort key for an IPv4 address string.

    Sorts numerically by each octet rather than lexicographically.

    >>> ip_sort_key('10.1.10.104')
    (10, 1, 10, 104)
    >>> sorted(['10.1.10.104', '10.1.2.2'], key=ip_sort_key)
    ['10.1.2.2', '10.1.10.104']
    """
    return tuple(int(b) for b in ip.split('.'))


def is_rfc1918(ip: str) -> bool:
    """Check if an IPv4 address is in RFC 1918 private address space.

    Covers:
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16

    >>> is_rfc1918('10.1.10.1')
    True
    >>> is_rfc1918('172.16.0.1')
    True
    >>> is_rfc1918('172.31.255.255')
    True
    >>> is_rfc1918('172.32.0.0')
    False
    >>> is_rfc1918('192.168.1.1')
    True
    >>> is_rfc1918('8.8.8.8')
    False
    """
    if ip.startswith('10.'):
        return True
    if ip.startswith('192.168.'):
        return True
    if ip.startswith('172.'):
        second = int(ip.split('.')[1])
        return 16 <= second <= 31
    return False


def is_local(ip: str) -> bool:
    """Check if an IPv4 address is in a reserved/non-routable range.

    Covers RFC 1918 private, link-local (169.254.x.x), IETF protocol
    assignments (192.0.x.x), documentation networks, and benchmarking
    networks.

    >>> is_local('10.1.10.1')
    True
    >>> is_local('192.168.1.1')
    True
    >>> is_local('169.254.1.1')
    True
    >>> is_local('8.8.8.8')
    False
    >>> is_local('203.0.113.1')
    False
    """
    if is_rfc1918(ip):
        return True
    # IETF Protocol Assignments
    if ip.startswith('192.0.'):
        return True
    # Link-local
    if ip.startswith('169.254.'):
        return True
    # Benchmarking
    if ip.startswith('198.18.') or ip.startswith('198.19.'):
        return True
    # Documentation TEST-NET-2
    if ip.startswith('198.51.100.'):
        return True
    return False
