"""Tests for default IP selection logic."""

import pytest

from gdoc2netcfg.derivations.default_ip import select_default_ip
from gdoc2netcfg.models.addressing import IPv4Address


class TestSelectDefaultIp:
    def test_public_ip_preferred(self):
        """Public IP wins over any private IP."""
        ips = {
            "eth0": IPv4Address("10.1.10.1"),
            "eth1": IPv4Address("203.0.114.1"),  # Public
        }
        result = select_default_ip(ips)
        assert str(result) == "203.0.114.1"

    def test_none_interface_preferred(self):
        """No-name interface (default) wins over named private IPs."""
        ips = {
            "eth0": IPv4Address("10.1.10.1"),
            None: IPv4Address("10.1.10.2"),
        }
        result = select_default_ip(ips)
        assert str(result) == "10.1.10.2"

    def test_fallback_to_first_sorted(self):
        """When all named and private, use numerically first."""
        ips = {
            "eth0": IPv4Address("10.1.10.200"),
            "eth1": IPv4Address("10.1.10.100"),
        }
        result = select_default_ip(ips)
        assert str(result) == "10.1.10.100"

    def test_single_interface(self):
        """Single interface is always the default."""
        ips = {None: IPv4Address("10.1.10.1")}
        result = select_default_ip(ips)
        assert str(result) == "10.1.10.1"

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="No interfaces"):
            select_default_ip({})
