"""Let's Encrypt certificate provisioning generator.

Produces per-host certbot scripts in certs-available/{fqdn}, DNS-01
validation hook scripts in hooks/, and a renew-enabled.sh orchestrator.
Only public FQDNs (is_fqdn=True) are included as -d domains — short
names can't be validated by Let's Encrypt.

Uses DNS-01 challenge validation via dnsmasq TXT records, avoiding
HTTP-01 failures when AAAA records point directly to devices instead
of the reverse proxy.

Deploy hooks are added based on hardware_type:
  - supermicro-bmc → certbot-hook-bmc-ipmi-supermicro
  - netgear-switch → certbot-hook-netgear-switches
"""

from __future__ import annotations

from gdoc2netcfg.derivations.hardware import (
    HARDWARE_NETGEAR_SWITCH,
    HARDWARE_SUPERMICRO_BMC,
)
from gdoc2netcfg.models.host import NetworkInventory
from gdoc2netcfg.utils.dns import is_safe_dns_name, is_safe_path, is_safe_systemd_unit

# Deploy hook scripts, looked up by hardware type
_DEPLOY_HOOKS: dict[str, str] = {
    HARDWARE_SUPERMICRO_BMC: "/usr/local/bin/certbot-hook-bmc-ipmi-supermicro",
    HARDWARE_NETGEAR_SWITCH: "/usr/local/bin/certbot-hook-netgear-switches",
}

_DEFAULT_DNSMASQ_CONF_DIR = "/etc/dnsmasq.d/external"
_DEFAULT_DNSMASQ_SERVICE = "dnsmasq@external"


def _generate_auth_hook(dnsmasq_conf_dir: str, dnsmasq_service: str) -> str:
    """Generate the DNS-01 auth hook script.

    Certbot calls this with CERTBOT_DOMAIN and CERTBOT_VALIDATION env vars.
    It appends a txt-record line to dnsmasq config and reloads.
    """
    return (
        "#!/bin/sh\n"
        "# DNS-01 auth hook: add ACME challenge TXT record to dnsmasq\n"
        "# Called by certbot with CERTBOT_DOMAIN and CERTBOT_VALIDATION\n"
        "set -e\n"
        f'CONF_DIR="{dnsmasq_conf_dir}"\n'
        'RECORD="txt-record=_acme-challenge.${CERTBOT_DOMAIN},${CERTBOT_VALIDATION}"\n'
        'echo "$RECORD" >> "$CONF_DIR/acme-challenge.conf"\n'
        f'systemctl reload {dnsmasq_service}\n'
        "sleep 2\n"
    )


def _generate_cleanup_hook(dnsmasq_conf_dir: str, dnsmasq_service: str) -> str:
    """Generate the DNS-01 cleanup hook script.

    Certbot calls this after validation. Removes the TXT record and reloads.
    """
    return (
        "#!/bin/sh\n"
        "# DNS-01 cleanup hook: remove ACME challenge TXT record from dnsmasq\n"
        "# Called by certbot with CERTBOT_DOMAIN and CERTBOT_VALIDATION\n"
        "set -e\n"
        f'CONF_DIR="{dnsmasq_conf_dir}"\n'
        'RECORD="txt-record=_acme-challenge.${CERTBOT_DOMAIN},${CERTBOT_VALIDATION}"\n'
        'CONF_FILE="$CONF_DIR/acme-challenge.conf"\n'
        'if [ -f "$CONF_FILE" ]; then\n'
        '    ESCAPED=$(printf \'%s\\n\' "$RECORD" | sed \'s/[][\\\\.*^$&/]/\\\\&/g\')\n'
        '    sed -i "/^${ESCAPED}$/d" "$CONF_FILE"\n'
        'fi\n'
        f'systemctl reload {dnsmasq_service}\n'
    )


def generate_letsencrypt(
    inventory: NetworkInventory,
    dnsmasq_conf_dir: str = _DEFAULT_DNSMASQ_CONF_DIR,
    dnsmasq_service: str = _DEFAULT_DNSMASQ_SERVICE,
) -> dict[str, str]:
    """Generate certbot provisioning scripts for each host.

    Returns a dict mapping relative paths to file contents:
      - hooks/dnsmasq-dns01-auth         (auth hook)
      - hooks/dnsmasq-dns01-cleanup      (cleanup hook)
      - certs-available/{primary_fqdn}   (one per host)
      - renew-enabled.sh                 (orchestrator)

    Raises:
        ValueError: If dnsmasq_conf_dir or dnsmasq_service contain
            unsafe characters.
    """
    if not is_safe_path(dnsmasq_conf_dir):
        raise ValueError(f"Unsafe dnsmasq_conf_dir path: {dnsmasq_conf_dir!r}")
    if not is_safe_systemd_unit(dnsmasq_service):
        raise ValueError(f"Unsafe dnsmasq_service name: {dnsmasq_service!r}")

    files: dict[str, str] = {}

    # Hook scripts
    files["hooks/dnsmasq-dns01-auth"] = _generate_auth_hook(
        dnsmasq_conf_dir, dnsmasq_service,
    )
    files["hooks/dnsmasq-dns01-cleanup"] = _generate_cleanup_hook(
        dnsmasq_conf_dir, dnsmasq_service,
    )

    for host in inventory.hosts_sorted():
        # Collect only public FQDNs with safe characters
        fqdns = [
            dn.name for dn in host.dns_names
            if dn.is_fqdn and is_safe_dns_name(dn.name)
        ]

        if not fqdns:
            continue

        # Primary FQDN is the cert-name (first FQDN, typically hostname.domain)
        cert_name = fqdns[0]

        # Build certbot command
        lines = [
            "#!/bin/sh",
            'HOOKS_DIR="$(cd "$(dirname "$0")/../hooks" && pwd)"',
        ]
        cmd_parts = [
            "certbot certonly --manual",
            "  --preferred-challenges dns",
            '  --manual-auth-hook "$HOOKS_DIR/dnsmasq-dns01-auth"',
            '  --manual-cleanup-hook "$HOOKS_DIR/dnsmasq-dns01-cleanup"',
            f"  --cert-name {cert_name}",
        ]
        for fqdn in fqdns:
            cmd_parts.append(f"  -d {fqdn}")

        # Deploy hook based on hardware type
        hook_path = _DEPLOY_HOOKS.get(host.hardware_type or "")
        if hook_path:
            cmd_parts.append(f"  --deploy-hook {hook_path}")

        lines.append(" \\\n".join(cmd_parts))
        lines.append("")

        files[f"certs-available/{cert_name}"] = "\n".join(lines)

    # Orchestrator script
    files["renew-enabled.sh"] = (
        "#!/bin/sh\n"
        "for cert in certs-enabled/*; do\n"
        '    sh "$cert"\n'
        "done\n"
    )

    return files
