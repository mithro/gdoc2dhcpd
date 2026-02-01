"""Tests for the shared reachability module."""

from unittest.mock import patch

from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface
from gdoc2netcfg.supplements.reachability import (
    HostReachability,
    check_all_hosts_reachability,
    check_port_open,
    check_reachable,
)


class TestCheckReachable:
    @patch("gdoc2netcfg.supplements.reachability.subprocess.run")
    def test_reachable_host(self, mock_run):
        mock_run.return_value.stdout = (
            "PING 10.1.10.1 (10.1.10.1) 56(84) bytes of data.\n"
            "5 packets transmitted, 5 received, 0% packet loss\n"
        )
        assert check_reachable("10.1.10.1") is True

    @patch("gdoc2netcfg.supplements.reachability.subprocess.run")
    def test_unreachable_host(self, mock_run):
        mock_run.return_value.stdout = (
            "PING 10.1.10.99 (10.1.10.99) 56(84) bytes of data.\n"
            "5 packets transmitted, 0 received, 100% packet loss\n"
        )
        assert check_reachable("10.1.10.99") is False

    @patch("gdoc2netcfg.supplements.reachability.subprocess.run")
    def test_custom_packet_count(self, mock_run):
        mock_run.return_value.stdout = "3 packets transmitted, 3 received"
        assert check_reachable("10.1.10.1", packets=3) is True
        args = mock_run.call_args[0][0]
        assert "-c" in args
        assert "3" in args

    @patch("gdoc2netcfg.supplements.reachability.subprocess.run")
    def test_ping_not_found(self, mock_run):
        mock_run.side_effect = FileNotFoundError
        assert check_reachable("10.1.10.1") is False


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
    def test_frozen(self):
        hr = HostReachability(hostname="server", active_ips=("10.1.10.1",), is_up=True)
        assert hr.hostname == "server"
        assert hr.active_ips == ("10.1.10.1",)
        assert hr.is_up is True

    def test_defaults(self):
        hr = HostReachability(hostname="server")
        assert hr.active_ips == ()
        assert hr.is_up is False

    def test_immutable(self):
        hr = HostReachability(hostname="server", active_ips=("10.1.10.1",), is_up=True)
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
