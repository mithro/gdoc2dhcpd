"""Tests for DNS name and path validation utilities."""

from gdoc2netcfg.utils.dns import is_safe_dns_name, is_safe_path


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


class TestIsSafePath:
    def test_absolute_path(self):
        assert is_safe_path("/var/www/acme") is True

    def test_path_with_dots(self):
        assert is_safe_path("/etc/nginx/.htpasswd") is True

    def test_path_with_hyphens(self):
        assert is_safe_path("/usr/local/bin/certbot-hook") is True

    def test_path_with_spaces(self):
        assert is_safe_path("/path/with spaces/dir") is True

    def test_relative_path(self):
        assert is_safe_path("nginx/sites-available") is True

    def test_empty_string(self):
        assert is_safe_path("") is False

    def test_semicolon_injection(self):
        assert is_safe_path("/etc/passwd; rm -rf /") is False

    def test_newline_injection(self):
        assert is_safe_path("/var/www\n    malicious_directive;") is False

    def test_shell_subshell(self):
        assert is_safe_path("/var/$(whoami)/www") is False

    def test_backtick(self):
        assert is_safe_path("/var/`id`/www") is False

    def test_braces(self):
        assert is_safe_path("/var/{bad}/www") is False

    def test_pipe(self):
        assert is_safe_path("/var/www | cat /etc/shadow") is False
