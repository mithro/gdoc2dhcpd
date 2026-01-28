"""nginx reverse proxy configuration generator.

Produces per-host nginx server blocks under sites-available/ and a
shared ACME challenge snippet. Each host gets four config files:

  - {fqdn}-http-public       HTTP, no auth
  - {fqdn}-http-private      HTTP, auth_basic
  - {fqdn}-https-public      HTTPS, no auth
  - {fqdn}-https-private     HTTPS, auth_basic

The proxy_ssl_verify setting inside HTTPS configs is set based on the
host's SSL cert status: "on" if there's a valid Let's Encrypt cert,
"off" otherwise.

Admins activate configs via symlinks in sites-enabled/.
"""

from __future__ import annotations

from gdoc2netcfg.models.host import NetworkInventory
from gdoc2netcfg.utils.dns import is_safe_dns_name, is_safe_path


def generate_nginx(
    inventory: NetworkInventory,
    acme_webroot: str = "/var/www/acme",
    htpasswd_file: str = "/etc/nginx/.htpasswd",
) -> dict[str, str]:
    """Generate nginx reverse proxy configs for each host.

    Returns a dict mapping relative paths to file contents.

    Raises:
        ValueError: If acme_webroot or htpasswd_file contain unsafe characters.
    """
    if not is_safe_path(acme_webroot):
        raise ValueError(f"Unsafe acme_webroot path: {acme_webroot!r}")
    if not is_safe_path(htpasswd_file):
        raise ValueError(f"Unsafe htpasswd_file path: {htpasswd_file!r}")

    files: dict[str, str] = {}

    # Shared ACME challenge snippet
    files["snippets/acme-challenge.conf"] = _acme_challenge_snippet(acme_webroot)

    for host in inventory.hosts_sorted():
        fqdns = [
            dn.name for dn in host.dns_names
            if dn.is_fqdn and is_safe_dns_name(dn.name)
        ]
        if not fqdns:
            continue

        primary_fqdn = fqdns[0]
        all_names = [
            dn.name for dn in host.dns_names
            if is_safe_dns_name(dn.name)
        ]
        target_ip = str(host.default_ipv4)

        # Determine proxy_ssl_verify setting for HTTPS
        has_valid_cert = (
            host.ssl_cert_info is not None
            and host.ssl_cert_info.valid
            and not host.ssl_cert_info.self_signed
        )

        # HTTP public
        files[f"sites-available/{primary_fqdn}-http-public"] = _http_block(
            all_names, target_ip, private=False,
        )

        # HTTP private
        files[f"sites-available/{primary_fqdn}-http-private"] = _http_block(
            all_names, target_ip, private=True,
            htpasswd_file=htpasswd_file,
        )

        # HTTPS public
        files[f"sites-available/{primary_fqdn}-https-public"] = _https_block(
            all_names, target_ip, primary_fqdn,
            verify=has_valid_cert, private=False,
        )

        # HTTPS private
        files[f"sites-available/{primary_fqdn}-https-private"] = _https_block(
            all_names, target_ip, primary_fqdn,
            verify=has_valid_cert, private=True,
            htpasswd_file=htpasswd_file,
        )

    return files


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
) -> str:
    """Generate an HTTP (port 80) server block."""
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

    lines.extend([
        f"        proxy_pass http://{target_ip};",
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
) -> str:
    """Generate an HTTPS (port 443) server block."""
    verify_str = "on" if verify else "off"

    lines = [
        "server {",
        "    listen 443 ssl;",
        "    listen [::]:443 ssl;",
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

    lines.extend([
        f"        proxy_pass https://{target_ip};",
        f"        proxy_ssl_verify {verify_str};",
        "        proxy_set_header Host $host;",
        "        proxy_set_header X-Real-IP $remote_addr;",
        "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "        proxy_set_header X-Forwarded-Proto $scheme;",
        "    }",
        "}",
        "",
    ])
    return "\n".join(lines)
