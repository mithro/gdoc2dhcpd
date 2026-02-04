"""Tests for the shared reachability module."""

import json
import os
import time
from unittest.mock import patch

from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface
from gdoc2netcfg.supplements.reachability import (
    HostReachability,
    PingResult,
    check_all_hosts_reachability,
    check_port_open,
    check_reachable,
    load_reachability_cache,
    save_reachability_cache,
)


class TestPingResult:
    def test_truthy_when_received(self):
        assert PingResult(5, 3, 1.2)
        assert PingResult(5, 1)

    def test_falsy_when_none_received(self):
        assert not PingResult(5, 0)
        assert not PingResult(0, 0)

    def test_immutable(self):
        pr = PingResult(5, 3)
        try:
            pr.received = 0
            assert False, "Should have raised FrozenInstanceError"
        except AttributeError:
            pass


class TestCheckReachable:
    @patch("gdoc2netcfg.supplements.reachability.subprocess.run")
    def test_reachable_host(self, mock_run):
        mock_run.return_value.stdout = (
            "PING 10.1.10.1 (10.1.10.1) 56(84) bytes of data.\n"
            "5 packets transmitted, 5 received, 0% packet loss\n"
            "rtt min/avg/max/mdev = 0.100/0.250/0.400/0.100 ms\n"
        )
        result = check_reachable("10.1.10.1")
        assert result
        assert result.transmitted == 5
        assert result.received == 5
        assert result.rtt_avg_ms == 0.250

    @patch("gdoc2netcfg.supplements.reachability.subprocess.run")
    def test_unreachable_host(self, mock_run):
        mock_run.return_value.stdout = (
            "PING 10.1.10.99 (10.1.10.99) 56(84) bytes of data.\n"
            "5 packets transmitted, 0 received, 100% packet loss\n"
        )
        result = check_reachable("10.1.10.99")
        assert not result
        assert result.transmitted == 5
        assert result.received == 0
        assert result.rtt_avg_ms is None

    @patch("gdoc2netcfg.supplements.reachability.subprocess.run")
    def test_custom_packet_count(self, mock_run):
        mock_run.return_value.stdout = "3 packets transmitted, 3 received"
        result = check_reachable("10.1.10.1", packets=3)
        assert result
        assert result.transmitted == 3
        assert result.received == 3
        args = mock_run.call_args[0][0]
        assert "-c" in args
        assert "3" in args

    @patch("gdoc2netcfg.supplements.reachability.subprocess.run")
    def test_partial_response_still_reachable(self, mock_run):
        mock_run.return_value.stdout = (
            "PING 10.1.10.1 (10.1.10.1) 56(84) bytes of data.\n"
            "5 packets transmitted, 2 received, 60% packet loss\n"
            "rtt min/avg/max/mdev = 0.500/1.200/1.900/0.500 ms\n"
        )
        result = check_reachable("10.1.10.1")
        assert result
        assert result.transmitted == 5
        assert result.received == 2
        assert result.rtt_avg_ms == 1.200

    @patch("gdoc2netcfg.supplements.reachability.subprocess.run")
    def test_ping_not_found(self, mock_run):
        mock_run.side_effect = FileNotFoundError
        result = check_reachable("10.1.10.1")
        assert not result
        assert result.transmitted == 0
        assert result.received == 0


class TestCheckPortOpen:
    @patch("gdoc2netcfg.supplements.reachability.socket.socket")
    def test_port_open(self, mock_socket_cls):
        mock_sock = mock_socket_cls.return_value
        mock_sock.connect_ex.return_value = 0
        assert check_port_open("10.1.10.1", 22) is True
        mock_sock.connect_ex.assert_called_once_with(("10.1.10.1", 22))
        mock_sock.close.assert_called_once()

    @patch("gdoc2netcfg.supplements.reachability.socket.socket")
    def test_port_closed(self, mock_socket_cls):
        mock_sock = mock_socket_cls.return_value
        mock_sock.connect_ex.return_value = 111  # Connection refused
        assert check_port_open("10.1.10.1", 443) is False
        mock_sock.connect_ex.assert_called_once_with(("10.1.10.1", 443))

    @patch("gdoc2netcfg.supplements.reachability.socket.socket")
    def test_custom_timeout(self, mock_socket_cls):
        mock_sock = mock_socket_cls.return_value
        mock_sock.connect_ex.return_value = 0
        check_port_open("10.1.10.1", 80, timeout=2.0)
        mock_sock.settimeout.assert_called_once_with(2.0)

    @patch("gdoc2netcfg.supplements.reachability.socket.socket")
    def test_socket_always_closed(self, mock_socket_cls):
        mock_sock = mock_socket_cls.return_value
        mock_sock.connect_ex.side_effect = OSError("network error")
        try:
            check_port_open("10.1.10.1", 22)
        except OSError:
            pass
        mock_sock.close.assert_called_once()


def _make_host(hostname, ip):
    return Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=[
            NetworkInterface(
                name=None,
                mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                ipv4=IPv4Address(ip),
            )
        ],
        default_ipv4=IPv4Address(ip),
    )


def _make_multi_iface_host(hostname, ips):
    ifaces = [
        NetworkInterface(
            name=f"eth{i}",
            mac=MACAddress.parse(f"aa:bb:cc:dd:ee:{i:02x}"),
            ipv4=IPv4Address(ip),
        )
        for i, ip in enumerate(ips)
    ]
    return Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=ifaces,
        default_ipv4=IPv4Address(ips[0]),
    )


class TestHostReachability:
    def test_with_active_ips(self):
        hr = HostReachability(hostname="server", active_ips=("10.1.10.1",))
        assert hr.hostname == "server"
        assert hr.active_ips == ("10.1.10.1",)
        assert hr.is_up is True

    def test_defaults(self):
        hr = HostReachability(hostname="server")
        assert hr.active_ips == ()
        assert hr.is_up is False

    def test_is_up_derived_from_active_ips(self):
        """is_up is a property derived from active_ips, not an independent field."""
        up = HostReachability(hostname="a", active_ips=("10.0.0.1",))
        down = HostReachability(hostname="b", active_ips=())
        assert up.is_up is True
        assert down.is_up is False

    def test_immutable(self):
        hr = HostReachability(hostname="server", active_ips=("10.1.10.1",))
        try:
            hr.hostname = "other"
            assert False, "Should have raised FrozenInstanceError"
        except AttributeError:
            pass


class TestCheckAllHostsReachability:
    @patch("gdoc2netcfg.supplements.reachability.check_reachable")
    def test_all_hosts_up(self, mock_reachable):
        mock_reachable.return_value = True
        hosts = [_make_host("server", "10.1.10.1"), _make_host("desktop", "10.1.10.2")]

        result = check_all_hosts_reachability(hosts)

        assert len(result) == 2
        assert result["server"].is_up is True
        assert result["server"].active_ips == ("10.1.10.1",)
        assert result["desktop"].is_up is True

    @patch("gdoc2netcfg.supplements.reachability.check_reachable")
    def test_host_down(self, mock_reachable):
        mock_reachable.return_value = False
        hosts = [_make_host("server", "10.1.10.1")]

        result = check_all_hosts_reachability(hosts)

        assert result["server"].is_up is False
        assert result["server"].active_ips == ()

    @patch("gdoc2netcfg.supplements.reachability.check_reachable")
    def test_multi_interface_partial(self, mock_reachable):
        """Only some IPs respond — active_ips should contain just those."""
        def side_effect(ip):
            return ip == "10.1.10.1"

        mock_reachable.side_effect = side_effect
        hosts = [_make_multi_iface_host("server", ["10.1.10.1", "10.1.10.2"])]

        result = check_all_hosts_reachability(hosts)

        assert result["server"].is_up is True
        assert result["server"].active_ips == ("10.1.10.1",)

    @patch("gdoc2netcfg.supplements.reachability.check_reachable")
    def test_empty_hosts(self, mock_reachable):
        result = check_all_hosts_reachability([])
        assert result == {}
        mock_reachable.assert_not_called()

    @patch("gdoc2netcfg.supplements.reachability.check_reachable")
    def test_sorted_by_reversed_hostname(self, mock_reachable):
        """Hosts are processed sorted by reversed hostname components."""
        mock_reachable.return_value = True
        hosts = [
            _make_host("zebra.example.com", "10.1.10.3"),
            _make_host("alpha.example.com", "10.1.10.1"),
        ]

        result = check_all_hosts_reachability(hosts)

        # Both should be present regardless of order
        assert "zebra.example.com" in result
        assert "alpha.example.com" in result


class TestReachabilityCache:
    def test_save_and_load_roundtrip(self, tmp_path):
        cache_path = tmp_path / "reachability.json"
        data = {
            "server": HostReachability(hostname="server", active_ips=("10.1.10.1",)),
            "desktop": HostReachability(hostname="desktop", active_ips=()),
        }

        save_reachability_cache(cache_path, data)
        result = load_reachability_cache(cache_path)

        assert result is not None
        loaded, age = result
        assert len(loaded) == 2
        assert loaded["server"].hostname == "server"
        assert loaded["server"].active_ips == ("10.1.10.1",)
        assert loaded["server"].is_up is True
        assert loaded["desktop"].active_ips == ()
        assert loaded["desktop"].is_up is False
        assert age < 2  # just written

    def test_load_missing_file_returns_none(self, tmp_path):
        cache_path = tmp_path / "nonexistent.json"
        assert load_reachability_cache(cache_path) is None

    def test_load_stale_file_returns_none(self, tmp_path):
        cache_path = tmp_path / "reachability.json"
        data = {
            "server": HostReachability(hostname="server", active_ips=("10.1.10.1",)),
        }
        save_reachability_cache(cache_path, data)

        # Backdate the file modification time by 600 seconds
        old_time = time.time() - 600
        os.utime(cache_path, (old_time, old_time))

        assert load_reachability_cache(cache_path, max_age=300) is None

    def test_fresh_file_within_max_age(self, tmp_path):
        cache_path = tmp_path / "reachability.json"
        data = {
            "server": HostReachability(hostname="server", active_ips=("10.1.10.1",)),
        }
        save_reachability_cache(cache_path, data)

        result = load_reachability_cache(cache_path, max_age=300)
        assert result is not None

    def test_corrupted_json_returns_none(self, tmp_path):
        cache_path = tmp_path / "reachability.json"
        cache_path.write_text("not valid json{{{")

        assert load_reachability_cache(cache_path) is None

    def test_empty_reachability_roundtrip(self, tmp_path):
        cache_path = tmp_path / "reachability.json"
        save_reachability_cache(cache_path, {})

        result = load_reachability_cache(cache_path)
        assert result is not None
        loaded, _ = result
        assert loaded == {}

    def test_creates_parent_directories(self, tmp_path):
        cache_path = tmp_path / "deep" / "nested" / "reachability.json"
        data = {"server": HostReachability(hostname="server", active_ips=())}

        save_reachability_cache(cache_path, data)

        assert cache_path.exists()

    def test_json_format_is_sorted(self, tmp_path):
        cache_path = tmp_path / "reachability.json"
        data = {
            "zebra": HostReachability(hostname="zebra", active_ips=("10.1.10.3",)),
            "alpha": HostReachability(hostname="alpha", active_ips=("10.1.10.1",)),
        }
        save_reachability_cache(cache_path, data)

        raw = json.loads(cache_path.read_text())
        assert list(raw.keys()) == ["alpha", "zebra"]


class TestSharedIPReachability:
    @patch("gdoc2netcfg.supplements.reachability.check_reachable")
    def test_shared_ip_pinged_once(self, mock_reachable):
        """Two NICs sharing the same IP should only produce one ping."""
        mock_reachable.return_value = PingResult(10, 10, 1.0)
        # Two interfaces, same IP, different MACs
        host = _make_multi_iface_host("roku", ["10.1.10.50", "10.1.10.50"])

        result = check_all_hosts_reachability([host])

        assert result["roku"].is_up is True
        assert result["roku"].active_ips == ("10.1.10.50",)
        # Should ping once, not twice
        mock_reachable.assert_called_once_with("10.1.10.50")
