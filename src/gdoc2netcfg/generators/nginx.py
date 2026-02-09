"""nginx reverse proxy configuration generator.

Produces per-host nginx server blocks under sites-available/ and a
shared ACME challenge snippet. Each host gets four config file variants:

  - {fqdn}-http-public       HTTP, no auth
  - {fqdn}-http-private      HTTP, auth_basic
  - {fqdn}-stream            Stream upstream block (TLS passthrough)
  - {fqdn}-stream-map        SNI map entries for stream routing

HTTPS is handled via stream SNI passthrough rather than http-module
HTTPS blocks, ensuring consistent TLS behavior for both IPv4 (proxied)
and IPv6 (direct) paths.

Multi-interface hosts get a combined config file (per variant) containing:

  - An upstream block listing all interface IPs for round-robin failover
  - A root server block using the upstream with proxy_next_upstream
    on error/timeout/502, with hostname-level DNS names
  - A server block per named interface using direct proxy_pass to
    that interface's IP, with interface-specific DNS names

Single-interface hosts produce one set of two files with direct
proxy_pass (no upstream block).

Admins activate configs via symlinks in sites-enabled/.
"""

from __future__ import annotations

from typing import NamedTuple

from gdoc2netcfg.models.host import DNSName, Host, NetworkInventory
from gdoc2netcfg.utils.dns import is_safe_dns_name, is_safe_path


class _UpstreamInfo(NamedTuple):
    """Metadata for a generated upstream block, used for healthcheck config."""

    name: str       # e.g. "tweed.welland.mithis.com-http-public-backend"
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


def _stream_upstream_block(
    upstream_name: str,
    ips: list[str],
    balancer_lua_path: str = "",
) -> str:
    """Generate a stream upstream block for TLS passthrough.

    Single-interface hosts get a direct server entry.
    Multi-interface hosts use a placeholder server with
    balancer_by_lua_file for health-aware peer selection.
    """
    lines = [f"upstream {upstream_name} {{"]
    if balancer_lua_path:
        # Multi-interface: placeholder IP, Lua balancer selects real peer
        lines.append("    server 0.0.0.1:443;  # placeholder")
        lines.append(f"    balancer_by_lua_file {balancer_lua_path};")
    else:
        for ip in ips:
            lines.append(f"    server {ip}:443;")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def _stream_map_entries(
    upstream_name: str,
    dns_names: list[str],
) -> str:
    """Generate bare SNI map entries for a host.

    Each line maps a DNS name to the host's stream upstream. These are
    included by the admin's hand-crafted map block via:
        include /etc/nginx/sites-enabled/*-stream-map;
    """
    lines = []
    for name in dns_names:
        # Pad to align the upstream name (nginx map syntax: key value;)
        lines.append(f"{name} {upstream_name};")
    lines.append("")
    return "\n".join(lines)


def _emit_stream_files(
    files: dict[str, str],
    primary_fqdn: str,
    fqdn_names: list[str],
    ips: list[str],
    balancer_lua_path: str = "",
) -> None:
    """Emit stream upstream and SNI map files for a host.

    fqdn_names must be FQDN-only (not bare hostnames) because SNI
    values in TLS ClientHello are always fully qualified domain names.
    """
    upstream_name = f"{primary_fqdn}-tls"

    files[f"sites-available/{primary_fqdn}-stream"] = _stream_upstream_block(
        upstream_name, ips, balancer_lua_path=balancer_lua_path,
    )
    files[f"sites-available/{primary_fqdn}-stream-map"] = _stream_map_entries(
        upstream_name, fqdn_names,
    )


def generate_nginx(
    inventory: NetworkInventory,
    acme_webroot: str = "/var/www/acme",
    htpasswd_file: str = "/etc/nginx/.htpasswd",
    lua_healthcheck_path: str = "/usr/share/lua/5.1/",
    healthcheck_dir: str = "/etc/nginx/healthcheck.d",
    stream_healthcheck_dir: str = "/etc/nginx/stream-healthcheck.d",
) -> dict[str, str]:
    """Generate nginx reverse proxy configs for each host.

    Returns a dict mapping relative paths to file contents.

    Args:
        lua_healthcheck_path: Base directory for lua-resty-upstream-healthcheck.
            Used to set lua_package_path in nginx config.
        healthcheck_dir: Runtime directory where nginx loads per-host
            healthcheck .lua files from. The init_worker block scans this
            directory at startup.
        stream_healthcheck_dir: Runtime directory for stream health check
            Lua files. Used as the balancer_by_lua_file path in stream
            upstream blocks for multi-interface hosts.

    Raises:
        ValueError: If acme_webroot, htpasswd_file, lua_healthcheck_path,
            healthcheck_dir, or stream_healthcheck_dir contain unsafe characters.
    """
    if not is_safe_path(acme_webroot):
        raise ValueError(f"Unsafe acme_webroot path: {acme_webroot!r}")
    if not is_safe_path(htpasswd_file):
        raise ValueError(f"Unsafe htpasswd_file path: {htpasswd_file!r}")
    if not is_safe_path(lua_healthcheck_path):
        raise ValueError(f"Unsafe lua_healthcheck_path: {lua_healthcheck_path!r}")
    if not is_safe_path(healthcheck_dir):
        raise ValueError(f"Unsafe healthcheck_dir: {healthcheck_dir!r}")
    if not is_safe_path(stream_healthcheck_dir):
        raise ValueError(f"Unsafe stream_healthcheck_dir: {stream_healthcheck_dir!r}")

    files: dict[str, str] = {}
    healthcheck_hosts: list[tuple[str, list[_UpstreamInfo]]] = []
    # (fqdn, upstream_name, ips) for multi-interface stream health checks
    stream_healthcheck_hosts: list[tuple[str, str, list[str]]] = []

    # Shared ACME challenge snippet
    files["snippets/acme-challenge.conf"] = _acme_challenge_snippet(acme_webroot)

    for host in inventory.hosts_sorted():
        fqdns = [
            dn.name for dn in host.dns_names
            if dn.is_fqdn and _is_nginx_name(dn)
        ]
        if not fqdns:
            continue

        # All nginx-eligible names (including bare hostnames) for HTTP server_name
        all_nginx_names = [
            dn.name for dn in host.dns_names
            if _is_nginx_name(dn)
        ]
        # FQDN-only subset for stream SNI map (TLS ClientHello uses FQDNs)
        all_fqdn_names = [
            dn.name for dn in host.dns_names
            if dn.is_fqdn and _is_nginx_name(dn)
        ]

        if not host.is_multi_interface():
            # Single-interface host
            primary_fqdn = fqdns[0]
            target_ip = str(host.default_ipv4)

            _emit_http_files(
                files, primary_fqdn, all_nginx_names, target_ip,
                htpasswd_file, acme_webroot,
            )
            _emit_stream_files(
                files, primary_fqdn, all_fqdn_names,
                ips=[target_ip],
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

            # Collect per-interface (name_list, ip, fqdn) tuples.
            iface_configs: list[tuple[list[str], str, str]] = []
            for iface in host.interfaces:
                if iface.name is None:
                    continue
                dns_for_iface = iface_dns.get(iface.name, [])
                iface_fqdns = [
                    dn.name for dn in dns_for_iface
                    if dn.is_fqdn and _is_nginx_name(dn)
                ]
                iface_names = [
                    dn.name for dn in dns_for_iface
                    if _is_nginx_name(dn)
                ]
                if not iface_names or not iface_fqdns:
                    continue
                iface_configs.append(
                    (iface_names, str(iface.ipv4), iface_fqdns[0])
                )

            _emit_combined_http_files(
                files, primary_fqdn, root_names,
                all_ips, iface_configs,
                htpasswd_file, acme_webroot,
            )
            balancer_path = f"{stream_healthcheck_dir}/{primary_fqdn}-balancer.lua"
            _emit_stream_files(
                files, primary_fqdn, all_fqdn_names,
                ips=all_ips, balancer_lua_path=balancer_path,
            )

            # Collect upstream metadata for per-host healthcheck config
            host_upstreams = []
            for suffix, _builder in _VARIANT_BUILDERS:
                upstream_name = f"{primary_fqdn}-{suffix}-backend"
                host_upstreams.append(_UpstreamInfo(
                    name=upstream_name,
                    host=primary_fqdn,
                ))
            healthcheck_hosts.append((primary_fqdn, host_upstreams))

            # Collect stream healthcheck metadata
            stream_upstream_name = f"{primary_fqdn}-tls"
            stream_healthcheck_hosts.append(
                (primary_fqdn, stream_upstream_name, all_ips)
            )

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

    # Emit stream health check files if any multi-interface hosts exist
    if stream_healthcheck_hosts:
        files["stream.d/generated-lua-healthcheck.conf"] = (
            _stream_lua_healthcheck_conf(stream_healthcheck_dir)
        )
        files["stream.d/generated-healthcheck-init.conf"] = (
            _stream_healthcheck_init_conf(stream_healthcheck_dir)
        )
        files["stream-healthcheck.d/checker.lua"] = _stream_checker_lua()
        for fqdn, upstream_name, ips in stream_healthcheck_hosts:
            files[f"stream-healthcheck.d/hosts/{fqdn}.lua"] = (
                _stream_healthcheck_host_lua(upstream_name, fqdn, ips)
            )
            files[f"stream-healthcheck.d/{fqdn}-balancer.lua"] = (
                _stream_balancer_lua(upstream_name)
            )

    return files


def _emit_http_files(
    files: dict[str, str],
    primary_fqdn: str,
    all_names: list[str],
    target_ip: str,
    htpasswd_file: str,
    acme_webroot: str = "/var/www/acme",
) -> None:
    """Emit the two HTTP config file variants for a single-interface host."""
    files[f"sites-available/{primary_fqdn}-http-public"] = _http_block(
        all_names, target_ip, private=False, acme_webroot=acme_webroot,
    )
    files[f"sites-available/{primary_fqdn}-http-private"] = _http_block(
        all_names, target_ip, private=True,
        htpasswd_file=htpasswd_file, acme_webroot=acme_webroot,
    )


def _emit_combined_http_files(
    files: dict[str, str],
    primary_fqdn: str,
    root_names: list[str],
    all_ips: list[str],
    iface_configs: list[tuple[list[str], str, str]],
    htpasswd_file: str,
    acme_webroot: str = "/var/www/acme",
) -> None:
    """Emit two HTTP config files for a multi-interface host.

    Each file contains upstream blocks (a round-robin failover upstream
    for the root, plus one single-server upstream per interface named by
    its FQDN), the root server block, and one server block per named
    interface.
    """
    for suffix, builder in _VARIANT_BUILDERS:
        upstream_name = f"{primary_fqdn}-{suffix}-backend"
        upstream_text = _upstream_block(upstream_name, all_ips, port=80)
        parts = [upstream_text]

        # Per-interface upstream blocks (single server, named by FQDN)
        for _iface_names, iface_ip, iface_fqdn in iface_configs:
            iface_upstream = f"{iface_fqdn}-{suffix}-backend"
            parts.append(
                _upstream_block(iface_upstream, [iface_ip], port=80)
            )

        # Root server block (upstream failover)
        parts.append(builder(
            root_names, htpasswd_file,
            acme_webroot=acme_webroot,
            upstream_name=upstream_name,
        ))

        # Per-interface server blocks (proxy_pass via named upstream)
        for iface_names, _iface_ip, iface_fqdn in iface_configs:
            iface_upstream = f"{iface_fqdn}-{suffix}-backend"
            parts.append(builder(
                iface_names, htpasswd_file,
                acme_webroot=acme_webroot,
                upstream_name=iface_upstream,
            ))

        files[f"sites-available/{primary_fqdn}-{suffix}"] = "\n".join(parts)


def _build_http_public(
    names: list[str],
    htpasswd_file: str,
    acme_webroot: str = "/var/www/acme",
    upstream_name: str = "",
) -> str:
    return _http_block(
        names, "", private=False,
        acme_webroot=acme_webroot, upstream_name=upstream_name,
    )


def _build_http_private(
    names: list[str],
    htpasswd_file: str,
    acme_webroot: str = "/var/www/acme",
    upstream_name: str = "",
) -> str:
    return _http_block(
        names, "", private=True,
        acme_webroot=acme_webroot,
        htpasswd_file=htpasswd_file, upstream_name=upstream_name,
    )


_VARIANT_BUILDERS = [
    ("http-public", _build_http_public),
    ("http-private", _build_http_private),
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


def _acme_challenge_block(
    acme_webroot: str,
    proxy_target: str,
) -> list[str]:
    """Generate ACME challenge location blocks with fallback proxy.

    Returns lines for two locations within an HTTP server block:
    1. A primary location that tries serving from disk first
    2. A named fallback location that proxies to the backend

    The try_files directive serves local challenge files (for certbot
    running on this nginx host) and falls back to proxying the request
    to the backend (for backends that handle their own ACME challenges).
    """
    return [
        "    location /.well-known/acme-challenge/ {",
        f"        root {acme_webroot};",
        "        auth_basic off;",
        "        try_files $uri @acme_fallback;",
        "    }",
        "",
        "    location @acme_fallback {",
        f"        proxy_pass http://{proxy_target};",
        "        proxy_http_version 1.1;",
        "        proxy_set_header Host $host;",
        "        proxy_set_header X-Real-IP $remote_addr;",
        "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "        proxy_set_header X-Forwarded-Proto $scheme;",
        "    }",
    ]


def _http_block(
    names: list[str],
    target_ip: str,
    private: bool,
    acme_webroot: str = "/var/www/acme",
    htpasswd_file: str = "",
    upstream_name: str = "",
) -> str:
    """Generate an HTTP (port 80) server block.

    When upstream_name is set, proxy_pass targets the upstream and
    proxy_next_upstream is added for failover.
    """
    proxy_target = upstream_name if upstream_name else target_ip
    lines = [
        "server {",
        "    listen 80;",
        "    listen [::]:80;",
        f"    server_name {_server_names(names)};",
        "",
    ]

    lines.extend(_acme_challenge_block(acme_webroot, proxy_target))
    lines.append("")

    lines.append("    location / {")

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
            'type = "http"',
            f'http_req = "GET / HTTP/1.0\\r\\nHost: {us.host}\\r\\n\\r\\n"',
            "interval = 5000",
            "timeout = 2000",
            "fall = 3",
            "rise = 2",
            # Omit valid_statuses: when nil, lua-resty-upstream-healthcheck
            # skips status code validation — any HTTP response means the
            # backend is alive. Only connection failures mark it down.
        ]
        for arg in checker_args:
            lines.append(f"    {arg},")
        lines.append("})")
        lines.append("")

    return "\n".join(lines)


def _stream_lua_healthcheck_conf(stream_healthcheck_dir: str) -> str:
    """Generate the stream-level Lua config.

    This is included in the stream {} block (via stream.d/) and sets up:
    - lua_package_path so require "checker" resolves to checker.lua
    - lua_shared_dict for health check state
    - Suppresses socket errors (expected from health probes to down backends)
    """
    return (
        f'lua_package_path "{stream_healthcheck_dir}/?.lua;;";\n'
        "lua_shared_dict stream_healthcheck 1m;\n"
        "lua_socket_log_errors off;\n"
    )


def _stream_healthcheck_init_conf(stream_healthcheck_dir: str) -> str:
    """Generate a stream-level init_worker_by_lua_block.

    Scans stream_healthcheck_dir/hosts/ for per-host .lua config files
    and loads each one. Per-host files register their peers and health
    check parameters with the shared checker module.

    The hosts/ subdirectory is scanned (not the top level) to avoid
    accidentally loading checker.lua and per-host balancer files as
    config files — those are Lua modules, not init_worker scripts.
    """
    hosts_dir = f"{stream_healthcheck_dir}/hosts"
    return (
        "init_worker_by_lua_block {\n"
        f'    local dir = "{hosts_dir}"\n'
        '    local checker = require "checker"\n'
        '    local pipe = io.popen("ls " .. dir .. "/*.lua")\n'
        "    if not pipe then return end\n"
        "    for path in pipe:lines() do\n"
        "        local fn, err = loadfile(path)\n"
        "        if fn then\n"
        "            local ok, exec_err = pcall(fn)\n"
        "            if not ok then\n"
        '                ngx.log(ngx.ERR, "stream healthcheck config error in ", '
        "path, \": \", exec_err)\n"
        "            end\n"
        "        else\n"
        '            ngx.log(ngx.ERR, "failed to load ", path, ": ", err)\n'
        "        end\n"
        "    end\n"
        "    pipe:close()\n"
        "    checker.start()\n"
        "}\n"
    )


def _stream_healthcheck_host_lua(
    upstream_name: str,
    fqdn: str,
    ips: list[str],
) -> str:
    """Generate a per-host Lua file for stream health checking.

    Registers the upstream's peers (IP addresses) and health check
    parameters with the shared checker module. The checker module
    runs periodic HTTPS probes to each peer.
    """
    lines = [
        'local checker = require "checker"',
        "",
        "checker.register({",
        f'    upstream = "{upstream_name}",',
        f'    host = "{fqdn}",',
        "    peers = {",
    ]
    for ip in ips:
        lines.append(f'        "{ip}",')
    lines.extend([
        "    },",
        "    interval = 5,",
        "    timeout = 2,",
        "    fall = 3,",
        "    rise = 2,",
        "})",
        "",
    ])
    return "\n".join(lines)


def _stream_checker_lua() -> str:
    """Generate the shared checker.lua module for stream health checks.

    This module:
    1. Maintains a registry of upstreams and their peers
    2. Uses ngx.timer.every to probe each peer on port 443
    3. Uses TCP connect to verify backend is accepting connections
    4. Tracks consecutive failures (fall) and recoveries (rise)
    5. Stores health status in lua_shared_dict stream_healthcheck
    """
    return '''\
local _M = {}

local registry = {}
local shm = ngx.shared.stream_healthcheck

function _M.register(opts)
    registry[opts.upstream] = {
        host = opts.host,
        peers = opts.peers,
        interval = opts.interval or 5,
        timeout = opts.timeout or 2,
        fall = opts.fall or 3,
        rise = opts.rise or 2,
    }
    -- Initialise health state for each peer
    for _, ip in ipairs(opts.peers) do
        local key = opts.upstream .. ":" .. ip
        if not shm:get(key .. ":healthy") then
            shm:set(key .. ":healthy", true)
            shm:set(key .. ":fail_count", 0)
            shm:set(key .. ":ok_count", 0)
        end
    end
end

local function check_peer(upstream_name, info, ip)
    local sock = ngx.socket.tcp()
    sock:settimeout(info.timeout * 1000)

    local ok, err = sock:connect(ip, 443)
    if ok then
        sock:close()
    end

    -- TCP connect success = backend is accepting connections on port 443
    return ok, err
end

local function run_checks()
    for upstream_name, info in pairs(registry) do
        for _, ip in ipairs(info.peers) do
            local key = upstream_name .. ":" .. ip
            local healthy, err = check_peer(upstream_name, info, ip)

            if healthy then
                shm:set(key .. ":fail_count", 0)
                local ok_count = (shm:get(key .. ":ok_count") or 0) + 1
                shm:set(key .. ":ok_count", ok_count)
                if ok_count >= info.rise then
                    shm:set(key .. ":healthy", true)
                end
            else
                shm:set(key .. ":ok_count", 0)
                local fail_count = (shm:get(key .. ":fail_count") or 0) + 1
                shm:set(key .. ":fail_count", fail_count)
                if fail_count >= info.fall then
                    shm:set(key .. ":healthy", false)
                end
            end
        end
    end
end

function _M.start()
    local min_interval = 5
    for _, info in pairs(registry) do
        if info.interval < min_interval then
            min_interval = info.interval
        end
    end
    ngx.timer.every(min_interval, function(premature)
        if premature then return end
        run_checks()
    end)
end

function _M.get_healthy_peer(upstream_name)
    local info = registry[upstream_name]
    if not info then return nil, "unknown upstream" end

    -- Round-robin across healthy peers using a shared counter
    local rr_key = upstream_name .. ":rr_index"
    local rr_index = (shm:get(rr_key) or 0)
    local n = #info.peers

    for i = 1, n do
        local idx = ((rr_index + i - 1) % n) + 1
        local ip = info.peers[idx]
        local key = upstream_name .. ":" .. ip
        if shm:get(key .. ":healthy") then
            shm:set(rr_key, idx)
            return ip
        end
    end

    -- All peers down: round-robin as fallback
    local idx = (rr_index % n) + 1
    shm:set(rr_key, idx)
    return info.peers[idx], "all peers unhealthy"
end

return _M
'''


def _stream_balancer_lua(upstream_name: str) -> str:
    """Generate a per-host balancer Lua file for balancer_by_lua_file.

    Each multi-interface host gets its own balancer file with the
    upstream name hardcoded. This avoids the problem of trying to
    discover the upstream name at runtime in the stream balancer
    context, where nginx variables like ngx.var.upstream_name are
    not available.
    """
    return f'''\
local checker = require "checker"
local balancer = require "ngx.balancer"

local peer, err = checker.get_healthy_peer("{upstream_name}")
if not peer then
    ngx.log(ngx.ERR, "no healthy peer for stream upstream {upstream_name}: ", err)
    return ngx.exit(502)
end

local ok, set_err = balancer.set_current_peer(peer, 443)
if not ok then
    ngx.log(ngx.ERR, "failed to set stream peer: ", set_err)
    return ngx.exit(502)
end
'''


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
        "            ngx.say(hc.status_page())\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
