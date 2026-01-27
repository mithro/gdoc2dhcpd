"""Tests for DNS name validation utilities."""

from gdoc2netcfg.utils.dns import is_safe_dns_name


class TestIsSafeDnsName:
    def test_simple_hostname(self):
        assert is_safe_dns_name("desktop") is True

    def test_fqdn(self):
        assert is_safe_dns_name("desktop.welland.mithis.com") is True

    def test_with_hyphens(self):
        assert is_safe_dns_name("big-storage.welland.mithis.com") is True

    def test_with_underscores(self):
        assert is_safe_dns_name("_dmarc.example.com") is True

    def test_interface_dotted_name(self):
        assert is_safe_dns_name("eth0.big-storage.int.welland.mithis.com") is True

    def test_ipv4_prefix(self):
        assert is_safe_dns_name("ipv4.desktop.welland.mithis.com") is True

    def test_wildcard(self):
        assert is_safe_dns_name("*.example.com") is True

    def test_empty_string(self):
        assert is_safe_dns_name("") is False

    def test_shell_semicolon(self):
        assert is_safe_dns_name("example.com; rm -rf /") is False

    def test_shell_pipe(self):
        assert is_safe_dns_name("example.com | cat /etc/passwd") is False

    def test_shell_subshell(self):
        assert is_safe_dns_name("foo$(whoami).com") is False

    def test_shell_backtick(self):
        assert is_safe_dns_name("foo`id`.com") is False

    def test_newline_injection(self):
        assert is_safe_dns_name("example.com\nmalicious") is False

    def test_braces(self):
        assert is_safe_dns_name("example.com{bad}") is False

    def test_ampersand(self):
        assert is_safe_dns_name("example.com & echo pwned") is False

    def test_quotes(self):
        assert is_safe_dns_name('example"com') is False
        assert is_safe_dns_name("example'com") is False
