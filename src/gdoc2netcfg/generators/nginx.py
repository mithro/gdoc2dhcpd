"""nginx reverse proxy configuration generator.

Produces per-host nginx server blocks under sites-available/ and a
shared ACME challenge snippet. Each host gets four config file variants:

  - {fqdn}-http-public       HTTP, no auth
  - {fqdn}-http-private      HTTP, auth_basic
  - {fqdn}-https-public      HTTPS, no auth
  - {fqdn}-https-private     HTTPS, auth_basic

Multi-interface hosts get a combined config file (per variant) containing:

  - An upstream block listing all interface IPs for round-robin failover
  - A root server block using the upstream with proxy_next_upstream
    on error/timeout/502, with hostname-level DNS names
  - A server block per named interface using direct proxy_pass to
    that interface's IP, with interface-specific DNS names

Single-interface hosts produce one set of four files with direct
proxy_pass (no upstream block).

The proxy_ssl_verify setting inside HTTPS configs is set based on the
host's SSL cert status: "on" if there's a valid Let's Encrypt cert,
"off" otherwise.

Admins activate configs via symlinks in sites-enabled/.
"""

from __future__ import annotations

from typing import NamedTuple

from gdoc2netcfg.models.host import DNSName, Host, NetworkInventory
from gdoc2netcfg.utils.dns import is_safe_dns_name, is_safe_path


class _UpstreamInfo(NamedTuple):
    """Metadata for a generated upstream block, used for healthcheck config."""

    name: str       # e.g. "tweed.welland.mithis.com-https-public-backend"
    hc_type: str    # "http" or "https"
    host: str       # e.g. "tweed.welland.mithis.com"


def _is_nginx_name(dn: DNSName) -> bool:
    """Check if a DNS name should appear in nginx configs.

    Excludes IPv6-only names (ipv4 is None) since nginx proxies to
    IPv4 backends, and names with unsafe characters.
    """
    return dn.ipv4 is not None and is_safe_dns_name(dn.name)


def _partition_dns_names(
    host: Host,
) -> tuple[list[DNSName], dict[str, list[DNSName]]]:
    """Partition a host's DNS names into root and per-interface groups.

    Returns (root_names, iface_names) where:
      - root_names: DNS names not specific to any named interface
      - iface_names: dict mapping interface name → list of DNS names

    A DNS name belongs to an interface group if it contains
    "{iface_name}.{hostname}" — this matches Pass 2 names and their
    Pass 3/4 derivatives.
    """
    named_ifaces = [iface for iface in host.interfaces if iface.name]

    if not named_ifaces:
        return list(host.dns_names), {}

    iface_names: dict[str, list[DNSName]] = {
        iface.name: [] for iface in named_ifaces
    }
    root_names: list[DNSName] = []

    for dn in host.dns_names:
        matched = False
        for iface in named_ifaces:
            marker = f"{iface.name}.{host.hostname}"
            if marker in dn.name:
                iface_names[iface.name].append(dn)
                matched = True
                break
        if not matched:
            root_names.append(dn)

    return root_names, iface_names


def _parse_https_listen(value: str) -> tuple[str, str]:
    """Parse https_listen config into (ipv4_listen, ipv6_listen) directives.

    Returns the text after 'listen ' and before ' ssl;'.
    """
    if not value:
        return ("443", "[::]:443")

    if ":" in value:
        # addr:port form like "127.0.0.1:8443"
        host, port = value.rsplit(":", 1)
        if host == "127.0.0.1":
            ipv6_host = "[::1]"
        else:
            ipv6_host = f"[{host}]" if ":" not in host else host
        return (f"{host}:{port}", f"{ipv6_host}:{port}")
    else:
        # Port-only form like "8443"
        return (value, f"[::]:{value}")


def _upstream_block(upstream_name: str, ips: list[str], port: int = 80) -> str:
    """Generate an nginx upstream block for failover.

    Lists all IPs as equal-weight servers for round-robin with
    automatic failure detection. Port specifies the backend port.
    """
    lines = [f"upstream {upstream_name} {{"]
    for ip in ips:
        lines.append(f"    server {ip}:{port};")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def generate_nginx(
    inventory: NetworkInventory,
    acme_webroot: str = "/var/www/acme",
    htpasswd_file: str = "/etc/nginx/.htpasswd",
    https_listen: str = "",
    lua_healthcheck_path: str = "/usr/share/lua/5.1/",
    healthcheck_dir: str = "/etc/nginx/healthcheck.d",
) -> dict[str, str]:
    """Generate nginx reverse proxy configs for each host.

    Returns a dict mapping relative paths to file contents.

    Args:
        https_listen: Override HTTPS listen directives. Examples:
            "" (default) → listen 443 / [::]:443
            "8443" → listen 8443 / [::]:8443
            "127.0.0.1:8443" → listen 127.0.0.1:8443 / [::1]:8443
        lua_healthcheck_path: Base directory for lua-resty-upstream-healthcheck.
            Used to set lua_package_path in nginx config.
        healthcheck_dir: Runtime directory where nginx loads per-host
            healthcheck .lua files from. The init_worker block scans this
            directory at startup.

    Raises:
        ValueError: If acme_webroot, htpasswd_file, lua_healthcheck_path,
            or healthcheck_dir contain unsafe characters.
    """
    if not is_safe_path(acme_webroot):
        raise ValueError(f"Unsafe acme_webroot path: {acme_webroot!r}")
    if not is_safe_path(htpasswd_file):
        raise ValueError(f"Unsafe htpasswd_file path: {htpasswd_file!r}")
    if not is_safe_path(lua_healthcheck_path):
        raise ValueError(f"Unsafe lua_healthcheck_path: {lua_healthcheck_path!r}")
    if not is_safe_path(healthcheck_dir):
        raise ValueError(f"Unsafe healthcheck_dir: {healthcheck_dir!r}")

    listen_ipv4, listen_ipv6 = _parse_https_listen(https_listen)

    files: dict[str, str] = {}
    healthcheck_hosts: list[tuple[str, list[_UpstreamInfo]]] = []

    # Shared ACME challenge snippet
    files["snippets/acme-challenge.conf"] = _acme_challenge_snippet(acme_webroot)

    for host in inventory.hosts_sorted():
        fqdns = [
            dn.name for dn in host.dns_names
            if dn.is_fqdn and _is_nginx_name(dn)
        ]
        if not fqdns:
            continue

        # Determine proxy_ssl_verify setting for HTTPS
        has_valid_cert = (
            host.ssl_cert_info is not None
            and host.ssl_cert_info.valid
            and not host.ssl_cert_info.self_signed
        )

        if not host.is_multi_interface():
            # Single-interface host: unchanged behaviour
            primary_fqdn = fqdns[0]
            all_names = [
                dn.name for dn in host.dns_names
                if _is_nginx_name(dn)
            ]
            target_ip = str(host.default_ipv4)

            _emit_four_files(
                files, primary_fqdn, all_names, target_ip,
                has_valid_cert, htpasswd_file,
                listen_ipv4, listen_ipv6,
            )
        else:
            # Multi-interface host: single file per variant containing
            # upstream block + root server block + per-interface server blocks
            root_dns, iface_dns = _partition_dns_names(host)

            root_fqdns = [
                dn.name for dn in root_dns
                if dn.is_fqdn and _is_nginx_name(dn)
            ]
            if not root_fqdns:
                continue

            primary_fqdn = root_fqdns[0]
            root_names = [
                dn.name for dn in root_dns
                if _is_nginx_name(dn)
            ]

            all_ips = [
                str(vi.ipv4) for vi in host.virtual_interfaces
            ]

            # Collect per-interface (name_list, ip) pairs
            iface_configs: list[tuple[list[str], str]] = []
            for iface in host.interfaces:
                if iface.name is None:
                    continue
                dns_for_iface = iface_dns.get(iface.name, [])
                iface_names = [
                    dn.name for dn in dns_for_iface
                    if _is_nginx_name(dn)
                ]
                if not iface_names:
                    continue
                iface_configs.append((iface_names, str(iface.ipv4)))

            _emit_combined_four_files(
                files, primary_fqdn, root_names,
                all_ips, iface_configs,
                has_valid_cert, htpasswd_file,
                listen_ipv4, listen_ipv6,
            )

            # Collect upstream metadata for per-host healthcheck config
            host_upstreams = []
            for suffix, _builder, _port in _VARIANT_BUILDERS:
                upstream_name = f"{primary_fqdn}-{suffix}-backend"
                hc_type = "https" if suffix.startswith("https") else "http"
                host_upstreams.append(_UpstreamInfo(
                    name=upstream_name,
                    hc_type=hc_type,
                    host=primary_fqdn,
                ))
            healthcheck_hosts.append((primary_fqdn, host_upstreams))

    # Emit healthcheck config files if any multi-interface hosts exist
    if healthcheck_hosts:
        files["conf.d/lua-healthcheck.conf"] = _lua_healthcheck_conf(
            lua_healthcheck_path,
        )
        files["conf.d/healthcheck-init.conf"] = _healthcheck_init_conf(
            healthcheck_dir,
        )
        files["conf.d/healthcheck-status.conf"] = _healthcheck_status_conf()
        for fqdn, upstreams in healthcheck_hosts:
            files[f"healthcheck.d/{fqdn}.lua"] = _healthcheck_host_lua(upstreams)

    return files


def _emit_four_files(
    files: dict[str, str],
    primary_fqdn: str,
    all_names: list[str],
    target_ip: str,
    has_valid_cert: bool,
    htpasswd_file: str,
    listen_ipv4: str = "443",
    listen_ipv6: str = "[::]:443",
) -> None:
    """Emit the four config file variants for a single-interface host."""
    files[f"sites-available/{primary_fqdn}-http-public"] = _http_block(
        all_names, target_ip, private=False,
    )
    files[f"sites-available/{primary_fqdn}-http-private"] = _http_block(
        all_names, target_ip, private=True, htpasswd_file=htpasswd_file,
    )
    files[f"sites-available/{primary_fqdn}-https-public"] = _https_block(
        all_names, target_ip, primary_fqdn,
        verify=has_valid_cert, private=False,
        listen_ipv4=listen_ipv4, listen_ipv6=listen_ipv6,
    )
    files[f"sites-available/{primary_fqdn}-https-private"] = _https_block(
        all_names, target_ip, primary_fqdn,
        verify=has_valid_cert, private=True, htpasswd_file=htpasswd_file,
        listen_ipv4=listen_ipv4, listen_ipv6=listen_ipv6,
    )


def _emit_combined_four_files(
    files: dict[str, str],
    primary_fqdn: str,
    root_names: list[str],
    all_ips: list[str],
    iface_configs: list[tuple[list[str], str]],
    has_valid_cert: bool,
    htpasswd_file: str,
    listen_ipv4: str = "443",
    listen_ipv6: str = "[::]:443",
) -> None:
    """Emit four config files for a multi-interface host.

    Each file contains its own upstream block (with a variant-specific
    name to avoid conflicts when multiple variants are enabled), the
    root server block (using upstream failover), and one server block
    per named interface (using direct proxy_pass).

    HTTP variants use port 80 backends, HTTPS variants use port 443.
    """
    for suffix, builder, port in _VARIANT_BUILDERS:
        upstream_name = f"{primary_fqdn}-{suffix}-backend"
        upstream_text = _upstream_block(upstream_name, all_ips, port=port)
        parts = [upstream_text]

        # Root server block (upstream failover)
        parts.append(builder(
            root_names, primary_fqdn,
            has_valid_cert, htpasswd_file,
            upstream_name=upstream_name,
            listen_ipv4=listen_ipv4, listen_ipv6=listen_ipv6,
        ))

        # Per-interface server blocks (direct proxy_pass)
        for iface_names, iface_ip in iface_configs:
            parts.append(builder(
                iface_names, primary_fqdn,
                has_valid_cert, htpasswd_file,
                target_ip=iface_ip,
                listen_ipv4=listen_ipv4, listen_ipv6=listen_ipv6,
            ))

        files[f"sites-available/{primary_fqdn}-{suffix}"] = "\n".join(parts)


def _build_http_public(
    names: list[str],
    primary_fqdn: str,
    has_valid_cert: bool,
    htpasswd_file: str,
    upstream_name: str = "",
    target_ip: str = "",
    listen_ipv4: str = "443",
    listen_ipv6: str = "[::]:443",
) -> str:
    return _http_block(names, target_ip, private=False, upstream_name=upstream_name)


def _build_http_private(
    names: list[str],
    primary_fqdn: str,
    has_valid_cert: bool,
    htpasswd_file: str,
    upstream_name: str = "",
    target_ip: str = "",
    listen_ipv4: str = "443",
    listen_ipv6: str = "[::]:443",
) -> str:
    return _http_block(
        names, target_ip, private=True,
        htpasswd_file=htpasswd_file, upstream_name=upstream_name,
    )


def _build_https_public(
    names: list[str],
    primary_fqdn: str,
    has_valid_cert: bool,
    htpasswd_file: str,
    upstream_name: str = "",
    target_ip: str = "",
    listen_ipv4: str = "443",
    listen_ipv6: str = "[::]:443",
) -> str:
    return _https_block(
        names, target_ip, primary_fqdn,
        verify=has_valid_cert, private=False, upstream_name=upstream_name,
        listen_ipv4=listen_ipv4, listen_ipv6=listen_ipv6,
    )


def _build_https_private(
    names: list[str],
    primary_fqdn: str,
    has_valid_cert: bool,
    htpasswd_file: str,
    upstream_name: str = "",
    target_ip: str = "",
    listen_ipv4: str = "443",
    listen_ipv6: str = "[::]:443",
) -> str:
    return _https_block(
        names, target_ip, primary_fqdn,
        verify=has_valid_cert, private=True,
        htpasswd_file=htpasswd_file, upstream_name=upstream_name,
        listen_ipv4=listen_ipv4, listen_ipv6=listen_ipv6,
    )


_VARIANT_BUILDERS = [
    ("http-public", _build_http_public, 80),
    ("http-private", _build_http_private, 80),
    ("https-public", _build_https_public, 443),
    ("https-private", _build_https_private, 443),
]


def _acme_challenge_snippet(acme_webroot: str) -> str:
    """Generate the shared ACME challenge location snippet."""
    return (
        f"location /.well-known/acme-challenge/ {{\n"
        f"    root {acme_webroot};\n"
        f"    auth_basic off;\n"
        f"}}\n"
    )


def _server_names(names: list[str]) -> str:
    """Format the server_name directive."""
    return " ".join(names)



def _http_block(
    names: list[str],
    target_ip: str,
    private: bool,
    htpasswd_file: str = "",
    upstream_name: str = "",
) -> str:
    """Generate an HTTP (port 80) server block.

    When upstream_name is set, proxy_pass targets the upstream and
    proxy_next_upstream is added for failover.
    """
    lines = [
        "server {",
        "    listen 80;",
        "    listen [::]:80;",
        f"    server_name {_server_names(names)};",
        "",
        "    include snippets/acme-challenge.conf;",
        "",
        "    location / {",
    ]

    if private:
        lines.append('        auth_basic "Restricted";')
        lines.append(f"        auth_basic_user_file {htpasswd_file};")

    if upstream_name:
        lines.append(f"        proxy_pass http://{upstream_name};")
        lines.append("        proxy_next_upstream error timeout http_502;")
    else:
        lines.append(f"        proxy_pass http://{target_ip};")

    lines.extend([
        "        proxy_http_version 1.1;",
        '        proxy_set_header Upgrade $http_upgrade;',
        '        proxy_set_header Connection "upgrade";',
        "        proxy_set_header Host $host;",
        "        proxy_set_header X-Real-IP $remote_addr;",
        "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "        proxy_set_header X-Forwarded-Proto $scheme;",
        "    }",
        "}",
        "",
    ])
    return "\n".join(lines)


def _https_block(
    names: list[str],
    target_ip: str,
    primary_fqdn: str,
    verify: bool,
    private: bool,
    htpasswd_file: str = "",
    upstream_name: str = "",
    listen_ipv4: str = "443",
    listen_ipv6: str = "[::]:443",
) -> str:
    """Generate an HTTPS server block.

    When upstream_name is set, proxy_pass targets the upstream and
    proxy_next_upstream is added for failover.
    """
    verify_str = "on" if verify else "off"

    lines = [
        "server {",
        f"    listen {listen_ipv4} ssl;",
        f"    listen {listen_ipv6} ssl;",
        f"    server_name {_server_names(names)};",
        "",
        f"    ssl_certificate /etc/letsencrypt/live/{primary_fqdn}/fullchain.pem;",
        f"    ssl_certificate_key /etc/letsencrypt/live/{primary_fqdn}/privkey.pem;",
        "",
        "    include snippets/acme-challenge.conf;",
        "",
        "    location / {",
    ]

    if private:
        lines.append('        auth_basic "Restricted";')
        lines.append(f"        auth_basic_user_file {htpasswd_file};")

    if upstream_name:
        lines.append(f"        proxy_pass https://{upstream_name};")
        lines.append("        proxy_next_upstream error timeout http_502;")
    else:
        lines.append(f"        proxy_pass https://{target_ip};")

    lines.append(f"        proxy_ssl_verify {verify_str};")
    if verify:
        lines.append(
            "        proxy_ssl_trusted_certificate"
            " /etc/ssl/certs/ca-certificates.crt;"
        )
    lines.extend([
        "        proxy_http_version 1.1;",
        '        proxy_set_header Upgrade $http_upgrade;',
        '        proxy_set_header Connection "upgrade";',
        "        proxy_set_header Host $host;",
        "        proxy_set_header X-Real-IP $remote_addr;",
        "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "        proxy_set_header X-Forwarded-Proto $scheme;",
        "    }",
        "}",
        "",
    ])
    return "\n".join(lines)


def _lua_healthcheck_conf(lua_path: str) -> str:
    """Generate the lua-resty-upstream-healthcheck global config.

    Sets up lua_package_path, shared memory zone for healthcheck state,
    and disables socket logging errors (healthcheck probes to down
    backends are expected to fail).
    """
    return (
        f"lua_package_path \"{lua_path}?.lua;{lua_path}?/init.lua;;\";\n"
        "lua_shared_dict healthcheck 1m;\n"
        "# NB: lua_socket_log_errors is a global setting — it suppresses\n"
        "# socket errors for ALL Lua modules, not just healthcheck probes.\n"
        "lua_socket_log_errors off;\n"
    )


def _healthcheck_init_conf(healthcheck_dir: str) -> str:
    """Generate a generic init_worker_by_lua_block that loads per-host files.

    Scans the healthcheck_dir for .lua files and executes each one.
    Per-host files contain their own upstream existence guards, so files
    for disabled hosts (no upstream block in running config) are safely
    skipped at runtime.
    """
    return (
        "init_worker_by_lua_block {\n"
        f'    local dir = "{healthcheck_dir}"\n'
        '    local pipe = io.popen("ls " .. dir .. "/*.lua")\n'
        "    if not pipe then return end\n"
        "    for path in pipe:lines() do\n"
        "        local fn, err = loadfile(path)\n"
        "        if fn then\n"
        "            local ok, exec_err = pcall(fn)\n"
        "            if not ok then\n"
        '                ngx.log(ngx.ERR, "healthcheck config error in ", '
        "path, \": \", exec_err)\n"
        "            end\n"
        "        else\n"
        '            ngx.log(ngx.ERR, "failed to load ", path, ": ", err)\n'
        "        end\n"
        "    end\n"
        "    pipe:close()\n"
        "}\n"
    )


def _healthcheck_host_lua(upstreams: list[_UpstreamInfo]) -> str:
    """Generate a per-host Lua file with spawn_checker calls.

    Each file is self-contained: it requires the healthcheck and upstream
    modules, defines a try_spawn helper that checks upstream existence
    before spawning, then calls it for each variant.

    The upstream existence check (get_primary_peers) means this file can
    be deployed permanently — if the host's server config isn't enabled
    (not symlinked into sites-enabled/), the upstreams won't exist and
    the spawn calls are silently skipped.
    """
    lines = [
        'local hc = require "resty.upstream.healthcheck"',
        'local upstream_mod = require "ngx.upstream"',
        "",
        "local function try_spawn(opts)",
        "    if not upstream_mod.get_primary_peers(opts.upstream) then",
        "        return",
        "    end",
        "    local ok, err = hc.spawn_checker(opts)",
        "    if not ok then",
        '        ngx.log(ngx.ERR, "failed to spawn health checker for ",'
        " opts.upstream, \": \", err)",
        "    end",
        "end",
        "",
    ]

    for us in upstreams:
        lines.append("try_spawn({")
        checker_args = [
            'shm = "healthcheck"',
            f'upstream = "{us.name}"',
            f'type = "{us.hc_type}"',
            f'http_req = "GET / HTTP/1.0\\r\\nHost: {us.host}\\r\\n\\r\\n"',
            "interval = 5000",
            "timeout = 2000",
            "fall = 3",
            "rise = 2",
            # 401/403 are valid because backends use auth_basic — a
            # rejected-but-responding backend is still healthy.
            "valid_statuses = {200, 301, 302, 401, 403}",
        ]
        if us.hc_type == "https":
            checker_args.append("ssl_verify = false")
        for arg in checker_args:
            lines.append(f"    {arg},")
        lines.append("})")
        lines.append("")

    return "\n".join(lines)


def _healthcheck_status_conf() -> str:
    """Generate the healthcheck status monitoring endpoint.

    Listens on 127.0.0.1:8080 (localhost only) and exposes the
    healthcheck status page at /upstream-status.
    """
    return (
        "server {\n"
        "    listen 127.0.0.1:8080;\n"
        "\n"
        "    location /upstream-status {\n"
        "        default_type text/plain;\n"
        "        content_by_lua_block {\n"
        "            local hc = require \"resty.upstream.healthcheck\"\n"
        "            ngx.say(hc.healthcheck_status_page())\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
