"""Tests for the nginx reverse proxy generator."""

from gdoc2netcfg.derivations.dns_names import derive_all_dns_names
from gdoc2netcfg.generators.nginx import generate_nginx
from gdoc2netcfg.models.addressing import IPv4Address, IPv6Address, MACAddress
from gdoc2netcfg.models.host import (
    Host,
    NetworkInterface,
    NetworkInventory,
)
from gdoc2netcfg.models.network import IPv6Prefix, Site

SITE = Site(
    name="welland",
    domain="welland.mithis.com",
    site_octet=1,
    ipv6_prefixes=[IPv6Prefix(prefix="2404:e80:a137:", name="Launtel")],
    network_subdomains={
        8: "int", 9: "int", 10: "int", 11: "int",
        12: "int", 13: "int", 14: "int", 15: "int",
        90: "iot",
    },
)


def _make_host(hostname="desktop", ip="10.1.10.100"):
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
                ip_addresses=(ipv4, ipv6),
                dhcp_name=hostname,
            ),
        ],
        default_ipv4=ipv4,
        subdomain="int",
    )
    derive_all_dns_names(host, SITE)
    return host


def _make_inventory(*hosts):
    return NetworkInventory(site=SITE, hosts=list(hosts))


class TestNginxFileStructure:
    def test_produces_acme_snippet(self):
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        assert "snippets/acme-challenge.conf" in files

    def test_produces_four_site_files_per_host(self):
        """Each host gets 2 HTTP + 2 stream files."""
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "desktop.welland.mithis.com"
        site_files = [k for k in files if k.startswith("sites-available/")]
        assert len(site_files) == 4

        prefixes = {f.split("/")[1] for f in site_files}
        assert f"{fqdn}-http-public" in prefixes
        assert f"{fqdn}-http-private" in prefixes
        assert f"{fqdn}-stream" in prefixes
        assert f"{fqdn}-stream-map" in prefixes

    def test_no_https_http_files_generated(self):
        """HTTPS is handled by stream SNI, not http-module blocks."""
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        https_files = [k for k in files if "https" in k and k.startswith("sites-available/")]
        assert len(https_files) == 0

    def test_host_with_no_fqdns_skipped(self):
        host = Host(
            machine_name="local",
            hostname="local",
            interfaces=[
                NetworkInterface(
                    name=None,
                    mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                    ip_addresses=(IPv4Address("192.168.1.1"),),
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

    def test_ipv6_only_names_excluded(self):
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com-http-public"]
        assert "ipv4.desktop.welland.mithis.com" in block
        assert "ipv6.desktop.welland.mithis.com" not in block

    def test_http_public_has_proxy_pass(self):
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com-http-public"]
        assert "proxy_pass http://10.1.10.100;" in block

    def test_http_public_no_auth_in_main_location(self):
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com-http-public"]
        # auth_basic "Restricted" should NOT appear (that's the private variant)
        assert 'auth_basic "Restricted"' not in block
        # auth_basic off IS present in the ACME challenge block
        assert "auth_basic off;" in block

    def test_http_private_has_auth(self):
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com-http-private"]
        assert 'auth_basic "Restricted";' in block
        assert "auth_basic_user_file" in block

    def test_http_has_inline_acme_with_try_files(self):
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com-http-public"]
        assert "location /.well-known/acme-challenge/" in block
        assert "root /var/www/acme;" in block
        assert "auth_basic off;" in block
        assert "try_files $uri @acme_fallback;" in block

    def test_http_has_acme_fallback_proxy(self):
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com-http-public"]
        assert "location @acme_fallback {" in block
        assert "proxy_pass http://10.1.10.100;" in block

    def test_http_has_proxy_headers(self):
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com-http-public"]
        assert "proxy_set_header Host $host;" in block
        assert "proxy_set_header X-Real-IP $remote_addr;" in block
        assert "proxy_set_header X-Forwarded-For" in block
        assert "proxy_set_header X-Forwarded-Proto" in block

    def test_http_has_websocket_headers(self):
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com-http-public"]
        assert "proxy_http_version 1.1;" in block
        assert "proxy_set_header Upgrade $http_upgrade;" in block
        assert 'proxy_set_header Connection "upgrade";' in block


class TestAcmeFallback:
    def test_fallback_proxy_has_headers(self):
        """@acme_fallback location has standard proxy headers."""
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com-http-public"]
        # Find the fallback section
        fallback_start = block.index("@acme_fallback")
        fallback = block[fallback_start:]
        assert "proxy_set_header Host $host;" in fallback
        assert "proxy_set_header X-Real-IP $remote_addr;" in fallback
        assert "proxy_set_header X-Forwarded-For" in fallback
        assert "proxy_set_header X-Forwarded-Proto" in fallback

    def test_custom_webroot_in_acme_block(self):
        """Custom acme_webroot flows through to inline ACME block."""
        host = _make_host()
        files = generate_nginx(
            _make_inventory(host), acme_webroot="/srv/acme",
        )

        block = files["sites-available/desktop.welland.mithis.com-http-public"]
        assert "root /srv/acme;" in block

    def test_multi_interface_fallback_uses_upstream(self):
        """Multi-interface hosts use upstream name in ACME fallback."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "rpi-sdr-kraken.welland.mithis.com"
        block = files[f"sites-available/{fqdn}-http-public"]
        fallback_start = block.index("@acme_fallback")
        fallback = block[fallback_start:]
        # Should proxy to the upstream, not a bare IP
        assert f"proxy_pass http://{fqdn}-http-public-backend;" in fallback

    def test_no_include_snippet_in_http_block(self):
        """HTTP blocks no longer use include for ACME — it's inline."""
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com-http-public"]
        assert "include snippets/acme-challenge.conf;" not in block

    def test_snippet_file_still_generated(self):
        """The snippet file is still generated for deployment compatibility."""
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        assert "snippets/acme-challenge.conf" in files


class TestCustomHtpasswd:
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
        assert len(site_files) == 8  # 4 per host (2 HTTP + 2 stream)

    def test_each_host_uses_own_ip(self):
        h1 = _make_host(hostname="desktop", ip="10.1.10.100")
        h2 = _make_host(hostname="server", ip="10.1.10.200")
        files = generate_nginx(_make_inventory(h1, h2))

        desktop_http = files["sites-available/desktop.welland.mithis.com-http-public"]
        assert "proxy_pass http://10.1.10.100;" in desktop_http

        server_http = files["sites-available/server.welland.mithis.com-http-public"]
        assert "proxy_pass http://10.1.10.200;" in server_http


def _make_multi_iface_host(
    hostname="rpi-sdr-kraken",
    iface_ips=None,
    subdomain="iot",
):
    """Create a host with multiple named interfaces.

    iface_ips is a dict of {interface_name: ip_string}.
    The first interface's IP becomes default_ipv4.
    """
    if iface_ips is None:
        iface_ips = {"eth0": "10.1.90.149", "wlan0": "10.1.90.150"}

    interfaces = []
    default_ipv4 = None
    for i, (iface_name, ip) in enumerate(iface_ips.items()):
        ipv4 = IPv4Address(ip)
        parts = ip.split(".")
        aa = parts[1]
        bb = parts[2].zfill(2)
        ccc = parts[3]
        ipv6 = IPv6Address(f"2404:e80:a137:{aa}{bb}::{ccc}", "2404:e80:a137:")

        if i == 0:
            default_ipv4 = ipv4

        interfaces.append(
            NetworkInterface(
                name=iface_name,
                mac=MACAddress.parse(f"aa:bb:cc:dd:ee:{i:02x}"),
                ip_addresses=(ipv4, ipv6),
                dhcp_name=f"{iface_name}-{hostname}",
            ),
        )

    host = Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=interfaces,
        default_ipv4=default_ipv4,
        subdomain=subdomain,
    )
    derive_all_dns_names(host, SITE)
    return host


def _extract_server_blocks(config_text: str) -> list[str]:
    """Extract individual server { ... } blocks from a config file."""
    blocks = []
    depth = 0
    current: list[str] = []
    for line in config_text.split("\n"):
        stripped = line.strip()
        if stripped.startswith("server {"):
            depth = 1
            current = [line]
        elif depth > 0:
            current.append(line)
            depth += stripped.count("{") - stripped.count("}")
            if depth == 0:
                blocks.append("\n".join(current))
                current = []
    return blocks


class TestMultiInterfaceHost:
    def test_produces_four_files(self):
        """Multi-interface hosts produce 2 HTTP + 2 stream files."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        site_files = [k for k in files if k.startswith("sites-available/")]
        assert len(site_files) == 4

    def test_file_contains_upstream_block(self):
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        conf = files["sites-available/rpi-sdr-kraken.welland.mithis.com-http-public"]
        assert "upstream rpi-sdr-kraken.welland.mithis.com-http-public-backend {" in conf
        assert "server 10.1.90.149:80;" in conf
        assert "server 10.1.90.150:80;" in conf

    def test_file_contains_three_server_blocks(self):
        """Each file has root + eth0 + wlan0 server blocks."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        conf = files["sites-available/rpi-sdr-kraken.welland.mithis.com-http-public"]
        blocks = _extract_server_blocks(conf)
        assert len(blocks) == 3

    def test_root_server_block_uses_upstream(self):
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        conf = files["sites-available/rpi-sdr-kraken.welland.mithis.com-http-public"]
        blocks = _extract_server_blocks(conf)
        root_block = blocks[0]
        expected = "proxy_pass http://rpi-sdr-kraken.welland.mithis.com-http-public-backend;"
        assert expected in root_block
        assert "proxy_next_upstream error timeout http_502;" in root_block

    def test_root_server_block_has_only_root_names(self):
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        conf = files["sites-available/rpi-sdr-kraken.welland.mithis.com-http-public"]
        blocks = _extract_server_blocks(conf)
        root_block = blocks[0]
        assert "rpi-sdr-kraken.welland.mithis.com" in root_block
        assert "eth0.rpi-sdr-kraken" not in root_block
        assert "wlan0.rpi-sdr-kraken" not in root_block

    def test_interface_server_blocks_use_named_upstream(self):
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "rpi-sdr-kraken.welland.mithis.com"
        conf = files[f"sites-available/{fqdn}-http-public"]
        blocks = _extract_server_blocks(conf)
        eth0_block = blocks[1]
        wlan0_block = blocks[2]

        # Per-interface blocks use named upstreams, not bare IPs
        assert f"proxy_pass http://eth0.{fqdn}-http-public-backend;" in eth0_block
        assert f"proxy_pass http://wlan0.{fqdn}-http-public-backend;" in wlan0_block

    def test_interface_server_blocks_have_interface_names(self):
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        conf = files["sites-available/rpi-sdr-kraken.welland.mithis.com-http-public"]
        blocks = _extract_server_blocks(conf)
        eth0_block = blocks[1]
        wlan0_block = blocks[2]

        assert "eth0.rpi-sdr-kraken.welland.mithis.com" in eth0_block
        assert "wlan0.rpi-sdr-kraken.welland.mithis.com" in wlan0_block

    def test_single_interface_host_unchanged(self):
        """Single-interface hosts should not produce upstream blocks."""
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com-http-public"]
        assert "upstream" not in block
        assert "proxy_next_upstream" not in block
        assert "proxy_pass http://10.1.10.100;" in block

class TestAltNames:
    def test_alt_names_in_server_name(self):
        host = _make_host()
        host.alt_names = ["alias.example.com"]
        derive_all_dns_names(host, SITE)
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com-http-public"]
        assert "alias.example.com" in block

    def test_wildcard_alt_names_in_server_name(self):
        host = _make_host()
        host.alt_names = ["*.example.com"]
        derive_all_dns_names(host, SITE)
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com-http-public"]
        assert "*.example.com" in block

    def test_multiple_alt_names(self):
        host = _make_host()
        host.alt_names = ["a.example.com", "b.example.com"]
        derive_all_dns_names(host, SITE)
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com-http-public"]
        assert "a.example.com" in block
        assert "b.example.com" in block


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


class TestSharedIPHost:
    """Tests for hosts with multiple NICs sharing the same IP address."""

    def test_shared_ip_treated_as_single_interface(self):
        """Two NICs with same IP should produce single-interface config (no upstream)."""
        host = _make_multi_iface_host(
            hostname="roku",
            iface_ips={"eth0": "10.1.90.50", "wlan0": "10.1.90.50"},
            subdomain="iot",
        )
        files = generate_nginx(_make_inventory(host))

        fqdn = "roku.welland.mithis.com"
        site_files = [k for k in files if k.startswith("sites-available/")]
        assert len(site_files) == 4  # 2 HTTP + 2 stream

        # Should use direct proxy_pass, not upstream
        http_pub = files[f"sites-available/{fqdn}-http-public"]
        assert "upstream" not in http_pub
        assert "proxy_pass http://10.1.90.50;" in http_pub

    def test_shared_ip_no_duplicate_upstream_entries(self):
        """If shared-IP host is somehow multi-interface, IPs should be unique."""
        # Create a host with 3 NICs: eth0+wlan0 on same IP, eth1 on different IP
        host = _make_multi_iface_host(
            hostname="server",
            iface_ips={"eth0": "10.1.10.100", "wlan0": "10.1.10.100", "eth1": "10.1.10.101"},
            subdomain="int",
        )
        files = generate_nginx(_make_inventory(host))

        fqdn = "server.welland.mithis.com"
        http_pub = files[f"sites-available/{fqdn}-http-public"]
        # Extract the main round-robin upstream block (first one)
        main_upstream_end = http_pub.index("}\n\n")
        main_upstream = http_pub[:main_upstream_end]
        # Main upstream should have two entries, not three
        assert main_upstream.count("server 10.1.10.100:80;") == 1
        assert main_upstream.count("server 10.1.10.101:80;") == 1


class TestHealthcheck:
    """Tests for lua-resty-upstream-healthcheck config generation."""

    def test_no_healthcheck_files_for_single_interface_only(self):
        """No conf.d/ or healthcheck.d/ files when only single-interface hosts."""
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        confd_files = [k for k in files if k.startswith("conf.d/")]
        hcd_files = [k for k in files if k.startswith("healthcheck.d/")]
        assert len(confd_files) == 0
        assert len(hcd_files) == 0

    def test_healthcheck_files_present_for_multi_interface_host(self):
        """conf.d/ files and per-host .lua emitted for multi-interface host."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        assert "conf.d/lua-healthcheck.conf" in files
        assert "conf.d/healthcheck-init.conf" in files
        assert "conf.d/healthcheck-status.conf" in files
        fqdn = "rpi-sdr-kraken.welland.mithis.com"
        assert f"healthcheck.d/{fqdn}.lua" in files

    def test_lua_healthcheck_conf_default_path(self):
        """Default lua_package_path uses /usr/share/lua/5.1/."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        conf = files["conf.d/lua-healthcheck.conf"]
        assert "lua_package_path" in conf
        assert "/usr/share/lua/5.1/" in conf

    def test_lua_healthcheck_conf_custom_path(self):
        """Custom lua_healthcheck_path flows through to lua_package_path."""
        host = _make_multi_iface_host()
        files = generate_nginx(
            _make_inventory(host),
            lua_healthcheck_path="/opt/lua/lib/",
        )

        conf = files["conf.d/lua-healthcheck.conf"]
        assert "/opt/lua/lib/" in conf

    def test_rejects_unsafe_lua_healthcheck_path(self):
        """Path injection in lua_healthcheck_path is rejected."""
        import pytest

        host = _make_multi_iface_host()
        with pytest.raises(ValueError, match="Unsafe lua_healthcheck_path"):
            generate_nginx(
                _make_inventory(host),
                lua_healthcheck_path="/opt/lua'; evil;",
            )

    def test_per_host_lua_has_two_http_variants(self):
        """Per-host .lua file contains spawn_checker for 2 HTTP variants."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "rpi-sdr-kraken.welland.mithis.com"
        lua = files[f"healthcheck.d/{fqdn}.lua"]
        assert f"{fqdn}-http-public-backend" in lua
        assert f"{fqdn}-http-private-backend" in lua
        assert "https" not in lua

    def test_separate_lua_files_per_host(self):
        """Each multi-interface host gets its own .lua file."""
        h1 = _make_multi_iface_host(
            hostname="host-a",
            iface_ips={"eth0": "10.1.90.10", "eth1": "10.1.90.11"},
        )
        h2 = _make_multi_iface_host(
            hostname="host-b",
            iface_ips={"eth0": "10.1.90.20", "eth1": "10.1.90.21"},
        )
        files = generate_nginx(_make_inventory(h1, h2))

        # Separate per-host .lua files
        assert "healthcheck.d/host-a.welland.mithis.com.lua" in files
        assert "healthcheck.d/host-b.welland.mithis.com.lua" in files
        # Single generic init_worker block (no host-specific content)
        init = files["conf.d/healthcheck-init.conf"]
        assert init.count("init_worker_by_lua_block") == 1
        assert "host-a" not in init
        assert "host-b" not in init

    def test_init_conf_scans_healthcheck_dir(self):
        """Init conf is a generic loader that scans healthcheck.d/."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        init = files["conf.d/healthcheck-init.conf"]
        assert "init_worker_by_lua_block" in init
        assert "healthcheck.d" in init
        assert "loadfile" in init

    def test_init_conf_custom_healthcheck_dir(self):
        """Custom healthcheck_dir flows through to init conf."""
        host = _make_multi_iface_host()
        files = generate_nginx(
            _make_inventory(host),
            healthcheck_dir="/opt/nginx/hc.d",
        )

        init = files["conf.d/healthcheck-init.conf"]
        assert "/opt/nginx/hc.d" in init

    def test_rejects_unsafe_healthcheck_dir(self):
        """Path injection in healthcheck_dir is rejected."""
        import pytest

        host = _make_multi_iface_host()
        with pytest.raises(ValueError, match="Unsafe healthcheck_dir"):
            generate_nginx(
                _make_inventory(host),
                healthcheck_dir="/etc/nginx/hc'; rm -rf /;",
            )

    def test_per_host_lua_checks_upstream_exists(self):
        """Per-host .lua file guards against missing upstreams."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "rpi-sdr-kraken.welland.mithis.com"
        lua = files[f"healthcheck.d/{fqdn}.lua"]
        assert "get_primary_peers" in lua

    def test_status_conf_has_listener_and_endpoint(self):
        """Status page config has correct listener and endpoint."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        status = files["conf.d/healthcheck-status.conf"]
        assert "127.0.0.1:8080" in status
        assert "/upstream-status" in status
        assert "status_page" in status

    def test_healthcheck_lua_omits_valid_statuses(self):
        """valid_statuses is omitted so any HTTP response means healthy."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "rpi-sdr-kraken.welland.mithis.com"
        lua = files[f"healthcheck.d/{fqdn}.lua"]
        assert "valid_statuses" not in lua

    def test_mixed_hosts_only_multi_interface_in_healthcheck(self):
        """Single-interface hosts are excluded from healthcheck files."""
        single = _make_host(hostname="desktop", ip="10.1.10.100")
        multi = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(single, multi))

        fqdn = "rpi-sdr-kraken.welland.mithis.com"
        assert f"healthcheck.d/{fqdn}.lua" in files
        hcd_files = [k for k in files if k.startswith("healthcheck.d/")]
        assert len(hcd_files) == 1  # only the multi-interface host

    def test_shared_ip_host_no_healthcheck(self):
        """Shared-IP hosts (treated as single-interface) don't trigger healthcheck."""
        shared = _make_multi_iface_host(
            hostname="roku",
            iface_ips={"eth0": "10.1.90.50", "wlan0": "10.1.90.50"},
            subdomain="iot",
        )
        files = generate_nginx(_make_inventory(shared))

        confd_files = [k for k in files if k.startswith("conf.d/")]
        hcd_files = [k for k in files if k.startswith("healthcheck.d/")]
        assert len(confd_files) == 0
        assert len(hcd_files) == 0


class TestStreamSNI:
    """Tests for stream SNI passthrough config generation."""

    def test_per_host_stream_file(self):
        """Each host gets a sites-available/{fqdn}-stream file."""
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "desktop.welland.mithis.com"
        assert f"sites-available/{fqdn}-stream" in files

    def test_per_host_stream_map_file(self):
        """Each host gets a sites-available/{fqdn}-stream-map file."""
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "desktop.welland.mithis.com"
        assert f"sites-available/{fqdn}-stream-map" in files

    def test_single_host_stream_upstream(self):
        """Single-interface host gets direct server entry in stream upstream."""
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "desktop.welland.mithis.com"
        stream = files[f"sites-available/{fqdn}-stream"]
        assert f"upstream {fqdn}-tls {{" in stream
        assert "server 10.1.10.100:443;" in stream
        assert "balancer_by_lua_file" not in stream

    def test_multi_interface_stream_upstream_has_balancer(self):
        """Multi-interface host uses balancer_by_lua_file in stream upstream."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "rpi-sdr-kraken.welland.mithis.com"
        stream = files[f"sites-available/{fqdn}-stream"]
        assert f"upstream {fqdn}-tls {{" in stream
        assert "server 0.0.0.1:443;" in stream
        assert "balancer_by_lua_file" in stream

    def test_stream_map_entries_for_all_fqdns(self):
        """Stream map file has entries for all FQDN DNS names."""
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "desktop.welland.mithis.com"
        stream_map = files[f"sites-available/{fqdn}-stream-map"]
        # Root FQDN and subdomain variant
        assert f"desktop.welland.mithis.com {fqdn}-tls;" in stream_map
        assert f"desktop.int.welland.mithis.com {fqdn}-tls;" in stream_map
        # ipv4 prefix variant
        assert f"ipv4.desktop.welland.mithis.com {fqdn}-tls;" in stream_map

    def test_no_ipv6_only_names_in_stream_map(self):
        """IPv6-only DNS names are excluded from stream map."""
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "desktop.welland.mithis.com"
        stream_map = files[f"sites-available/{fqdn}-stream-map"]
        assert "ipv6.desktop.welland.mithis.com" not in stream_map

    def test_no_bare_hostnames_in_stream_map(self):
        """Bare (non-FQDN) hostnames excluded from stream map (SNI is always FQDN)."""
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "desktop.welland.mithis.com"
        stream_map = files[f"sites-available/{fqdn}-stream-map"]
        # "desktop" without domain should not appear as its own map entry
        for line in stream_map.strip().splitlines():
            name = line.split()[0]
            assert "." in name, f"bare hostname in stream map: {name}"

    def test_no_https_http_files_generated(self):
        """No *-https-* files in sites-available (stream replaces HTTPS)."""
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        https_files = [k for k in files if "https" in k and k.startswith("sites-available/")]
        assert len(https_files) == 0

    def test_healthcheck_lua_only_http_variants(self):
        """HTTP health check .lua files have only HTTP variants, no HTTPS."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "rpi-sdr-kraken.welland.mithis.com"
        lua = files[f"healthcheck.d/{fqdn}.lua"]
        # 2 try_spawn calls (http-public + http-private) + 1 function def
        assert lua.count("try_spawn({\n") == 2
        assert "https" not in lua


class TestStreamHealthcheck:
    """Tests for custom HTTPS health checker for stream upstreams."""

    def test_no_stream_healthcheck_for_single_interface(self):
        """Single-interface hosts don't generate stream health check files."""
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        stream_d = [k for k in files if k.startswith("stream.d/")]
        stream_hc = [k for k in files if k.startswith("stream-healthcheck.d/")]
        assert len(stream_d) == 0
        assert len(stream_hc) == 0

    def test_stream_healthcheck_lua_conf_generated(self):
        """Multi-interface host triggers stream.d/ lua config with package path."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        assert "stream.d/generated-lua-healthcheck.conf" in files
        conf = files["stream.d/generated-lua-healthcheck.conf"]
        assert "lua_shared_dict stream_healthcheck" in conf
        assert "lua_package_path" in conf
        assert "stream-healthcheck.d" in conf

    def test_stream_healthcheck_init_generated(self):
        """Init worker block loads per-host files from hosts/ subdirectory."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        assert "stream.d/generated-healthcheck-init.conf" in files
        init = files["stream.d/generated-healthcheck-init.conf"]
        assert "init_worker_by_lua_block" in init
        # Scans hosts/ subdirectory, not top-level (avoids loading checker/balancer)
        assert "/hosts" in init

    def test_stream_per_host_lua_in_hosts_subdir(self):
        """Per-host Lua files live in hosts/ subdirectory."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "rpi-sdr-kraken.welland.mithis.com"
        key = f"stream-healthcheck.d/hosts/{fqdn}.lua"
        assert key in files
        lua = files[key]
        assert "10.1.90.149" in lua
        assert "10.1.90.150" in lua
        assert f"{fqdn}-tls" in lua

    def test_stream_checker_lua_generated(self):
        """Shared checker.lua module is generated at top level."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        assert "stream-healthcheck.d/checker.lua" in files
        checker = files["stream-healthcheck.d/checker.lua"]
        assert "sock:connect" in checker
        assert "stream_healthcheck" in checker

    def test_per_host_balancer_lua_generated(self):
        """Each multi-interface host gets its own balancer with hardcoded upstream name."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "rpi-sdr-kraken.welland.mithis.com"
        key = f"stream-healthcheck.d/{fqdn}-balancer.lua"
        assert key in files
        balancer = files[key]
        assert f"{fqdn}-tls" in balancer
        assert "set_current_peer" in balancer

    def test_stream_upstream_references_per_host_balancer(self):
        """Multi-interface stream upstream references per-host balancer."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "rpi-sdr-kraken.welland.mithis.com"
        stream = files[f"sites-available/{fqdn}-stream"]
        assert f"stream-healthcheck.d/{fqdn}-balancer.lua" in stream

    def test_stream_healthcheck_custom_dir(self):
        """Custom stream_healthcheck_dir flows through to generated files."""
        host = _make_multi_iface_host()
        files = generate_nginx(
            _make_inventory(host),
            stream_healthcheck_dir="/opt/nginx/stream-hc.d",
        )

        conf = files["stream.d/generated-lua-healthcheck.conf"]
        assert "/opt/nginx/stream-hc.d" in conf

        init = files["stream.d/generated-healthcheck-init.conf"]
        assert "/opt/nginx/stream-hc.d/hosts" in init

        fqdn = "rpi-sdr-kraken.welland.mithis.com"
        stream = files[f"sites-available/{fqdn}-stream"]
        assert f"/opt/nginx/stream-hc.d/{fqdn}-balancer.lua" in stream

    def test_no_shared_balancer_lua(self):
        """No shared balancer.lua — each host gets its own per-host balancer."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        assert "stream-healthcheck.d/balancer.lua" not in files

    def test_rejects_unsafe_stream_healthcheck_dir(self):
        """Path injection in stream_healthcheck_dir is rejected."""
        import pytest

        host = _make_multi_iface_host()
        with pytest.raises(ValueError, match="Unsafe stream_healthcheck_dir"):
            generate_nginx(
                _make_inventory(host),
                stream_healthcheck_dir="/etc/nginx/hc'; rm -rf /;",
            )

    def test_checker_lua_has_round_robin(self):
        """get_healthy_peer uses round-robin, not always first healthy."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        checker = files["stream-healthcheck.d/checker.lua"]
        assert "rr_index" in checker or "round" in checker.lower()
