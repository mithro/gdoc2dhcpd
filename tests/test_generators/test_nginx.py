"""Tests for the nginx reverse proxy generator."""

from gdoc2netcfg.derivations.dns_names import derive_all_dns_names
from gdoc2netcfg.generators.nginx import generate_nginx
from gdoc2netcfg.models.addressing import IPv4Address, IPv6Address, MACAddress
from gdoc2netcfg.models.host import (
    Host,
    NetworkInterface,
    NetworkInventory,
    SSLCertInfo,
)
from gdoc2netcfg.models.network import IPv6Prefix, Site

SITE = Site(
    name="welland",
    domain="welland.mithis.com",
    ipv6_prefixes=[IPv6Prefix(prefix="2404:e80:a137:", name="Launtel")],
    network_subdomains={10: "int", 90: "iot"},
)


def _make_host(hostname="desktop", ip="10.1.10.100", ssl_cert_info=None):
    ipv4 = IPv4Address(ip)
    parts = ip.split(".")
    aa = parts[1]
    bb = parts[2].zfill(2)
    ccc = parts[3]
    ipv6 = IPv6Address(f"2404:e80:a137:{aa}{bb}::{ccc}", "2404:e80:a137:")

    host = Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=[
            NetworkInterface(
                name=None,
                mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                ipv4=ipv4,
                ipv6_addresses=[ipv6],
                dhcp_name=hostname,
            ),
        ],
        default_ipv4=ipv4,
        subdomain="int",
        ssl_cert_info=ssl_cert_info,
    )
    derive_all_dns_names(host, SITE)
    return host


def _make_inventory(*hosts):
    return NetworkInventory(site=SITE, hosts=list(hosts))


VALID_LE_CERT = SSLCertInfo(
    issuer="Let's Encrypt",
    self_signed=False,
    valid=True,
    expiry="2026-04-15",
    sans=("desktop.welland.mithis.com",),
)

SELF_SIGNED_CERT = SSLCertInfo(
    issuer="desktop",
    self_signed=True,
    valid=False,
    expiry="2027-01-01",
    sans=(),
)


class TestNginxFileStructure:
    def test_produces_acme_snippet(self):
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        assert "snippets/acme-challenge.conf" in files

    def test_produces_four_files_per_host(self):
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "desktop.welland.mithis.com"
        site_files = [k for k in files if k.startswith("sites-available/")]
        assert len(site_files) == 4

        prefixes = {f.split("/")[1] for f in site_files}
        assert f"{fqdn}-http-public" in prefixes
        assert f"{fqdn}-http-private" in prefixes

    def test_https_files_have_consistent_names(self):
        host = _make_host()  # No ssl_cert_info
        files = generate_nginx(_make_inventory(host))

        fqdn = "desktop.welland.mithis.com"
        assert f"sites-available/{fqdn}-https-public" in files
        assert f"sites-available/{fqdn}-https-private" in files

    def test_ssl_verify_off_when_no_cert(self):
        host = _make_host()  # No ssl_cert_info
        files = generate_nginx(_make_inventory(host))

        fqdn = "desktop.welland.mithis.com"
        block = files[f"sites-available/{fqdn}-https-public"]
        assert "proxy_ssl_verify off;" in block

    def test_ssl_verify_on_when_valid_le_cert(self):
        host = _make_host(ssl_cert_info=VALID_LE_CERT)
        files = generate_nginx(_make_inventory(host))

        fqdn = "desktop.welland.mithis.com"
        block = files[f"sites-available/{fqdn}-https-public"]
        assert "proxy_ssl_verify on;" in block

    def test_ssl_verify_off_when_self_signed(self):
        host = _make_host(ssl_cert_info=SELF_SIGNED_CERT)
        files = generate_nginx(_make_inventory(host))

        fqdn = "desktop.welland.mithis.com"
        block = files[f"sites-available/{fqdn}-https-public"]
        assert "proxy_ssl_verify off;" in block

    def test_host_with_no_fqdns_skipped(self):
        host = Host(
            machine_name="local",
            hostname="local",
            interfaces=[
                NetworkInterface(
                    name=None,
                    mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                    ipv4=IPv4Address("192.168.1.1"),
                    ipv6_addresses=[],
                    dhcp_name="local",
                ),
            ],
            default_ipv4=IPv4Address("192.168.1.1"),
        )
        files = generate_nginx(_make_inventory(host))

        # Only the acme snippet, no sites-available
        site_files = [k for k in files if k.startswith("sites-available/")]
        assert len(site_files) == 0


class TestAcmeSnippet:
    def test_default_webroot(self):
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        snippet = files["snippets/acme-challenge.conf"]
        assert "root /var/www/acme;" in snippet
        assert "auth_basic off;" in snippet

    def test_custom_webroot(self):
        host = _make_host()
        files = generate_nginx(
            _make_inventory(host), acme_webroot="/srv/acme"
        )

        snippet = files["snippets/acme-challenge.conf"]
        assert "root /srv/acme;" in snippet


class TestHTTPBlock:
    def test_http_public_has_listen_80(self):
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com-http-public"]
        assert "listen 80;" in block
        assert "listen [::]:80;" in block

    def test_http_public_has_server_name(self):
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com-http-public"]
        assert "desktop.welland.mithis.com" in block
        assert "desktop.int.welland.mithis.com" in block
        assert "server_name" in block

    def test_http_public_has_proxy_pass(self):
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com-http-public"]
        assert "proxy_pass http://10.1.10.100;" in block

    def test_http_public_no_auth(self):
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com-http-public"]
        assert "auth_basic" not in block

    def test_http_private_has_auth(self):
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com-http-private"]
        assert 'auth_basic "Restricted";' in block
        assert "auth_basic_user_file" in block

    def test_http_includes_acme_snippet(self):
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com-http-public"]
        assert "include snippets/acme-challenge.conf;" in block

    def test_http_has_proxy_headers(self):
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com-http-public"]
        assert "proxy_set_header Host $host;" in block
        assert "proxy_set_header X-Real-IP $remote_addr;" in block
        assert "proxy_set_header X-Forwarded-For" in block
        assert "proxy_set_header X-Forwarded-Proto" in block


class TestHTTPSBlock:
    def test_https_has_listen_443(self):
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com-https-public"]
        assert "listen 443 ssl;" in block
        assert "listen [::]:443 ssl;" in block

    def test_https_has_ssl_cert_paths(self):
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com-https-public"]
        fqdn = "desktop.welland.mithis.com"
        assert f"ssl_certificate /etc/letsencrypt/live/{fqdn}/fullchain.pem;" in block
        assert f"ssl_certificate_key /etc/letsencrypt/live/{fqdn}/privkey.pem;" in block

    def test_https_noverify_has_ssl_verify_off(self):
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com-https-public"]
        assert "proxy_ssl_verify off;" in block
        assert "proxy_pass https://10.1.10.100;" in block

    def test_https_verify_has_ssl_verify_on(self):
        host = _make_host(ssl_cert_info=VALID_LE_CERT)
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com-https-public"]
        assert "proxy_ssl_verify on;" in block

    def test_https_private_has_auth(self):
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com-https-private"]
        assert 'auth_basic "Restricted";' in block

    def test_https_includes_acme_snippet(self):
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com-https-public"]
        assert "include snippets/acme-challenge.conf;" in block

    def test_custom_htpasswd_file(self):
        host = _make_host()
        files = generate_nginx(
            _make_inventory(host),
            htpasswd_file="/etc/nginx/custom.htpasswd",
        )

        block = files["sites-available/desktop.welland.mithis.com-http-private"]
        assert "auth_basic_user_file /etc/nginx/custom.htpasswd;" in block


class TestMultipleHosts:
    def test_two_hosts_produce_eight_site_files(self):
        h1 = _make_host(hostname="desktop", ip="10.1.10.100")
        h2 = _make_host(hostname="server", ip="10.1.10.200")
        files = generate_nginx(_make_inventory(h1, h2))

        site_files = [k for k in files if k.startswith("sites-available/")]
        assert len(site_files) == 8  # 4 per host

    def test_each_host_uses_own_ip(self):
        h1 = _make_host(hostname="desktop", ip="10.1.10.100")
        h2 = _make_host(hostname="server", ip="10.1.10.200")
        files = generate_nginx(_make_inventory(h1, h2))

        desktop_http = files["sites-available/desktop.welland.mithis.com-http-public"]
        assert "proxy_pass http://10.1.10.100;" in desktop_http

        server_http = files["sites-available/server.welland.mithis.com-http-public"]
        assert "proxy_pass http://10.1.10.200;" in server_http


class TestPathValidation:
    def test_rejects_malicious_acme_webroot(self):
        import pytest

        host = _make_host()
        with pytest.raises(ValueError, match="Unsafe acme_webroot"):
            generate_nginx(
                _make_inventory(host),
                acme_webroot="/var/www/acme; rm -rf /",
            )

    def test_rejects_malicious_htpasswd_file(self):
        import pytest

        host = _make_host()
        with pytest.raises(ValueError, match="Unsafe htpasswd_file"):
            generate_nginx(
                _make_inventory(host),
                htpasswd_file="/etc/passwd\n    evil_directive;",
            )
