"""Tests for the shared reachability module."""

from unittest.mock import patch

from gdoc2netcfg.supplements.reachability import check_port_open, check_reachable


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
