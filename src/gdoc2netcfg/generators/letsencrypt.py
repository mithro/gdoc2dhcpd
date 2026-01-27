"""Let's Encrypt certificate provisioning generator.

Produces per-host certbot scripts in certs-available/{fqdn} and a
renew-enabled.sh orchestrator. Only public FQDNs (is_fqdn=True) are
included as -d domains — short names can't be validated by Let's Encrypt.

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
from gdoc2netcfg.utils.dns import is_safe_dns_name

# Deploy hook scripts, looked up by hardware type
_DEPLOY_HOOKS: dict[str, str] = {
    HARDWARE_SUPERMICRO_BMC: "/usr/local/bin/certbot-hook-bmc-ipmi-supermicro",
    HARDWARE_NETGEAR_SWITCH: "/usr/local/bin/certbot-hook-netgear-switches",
}


def generate_letsencrypt(
    inventory: NetworkInventory,
    acme_webroot: str = "/var/www/acme",
) -> dict[str, str]:
    """Generate certbot provisioning scripts for each host.

    Returns a dict mapping relative paths to file contents:
      - certs-available/{primary_fqdn}  (one per host)
      - renew-enabled.sh                (orchestrator)
    """
    files: dict[str, str] = {}

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
        lines = ["#!/bin/sh"]
        cmd_parts = [
            "certbot certonly --webroot",
            f"  -w {acme_webroot}",
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
