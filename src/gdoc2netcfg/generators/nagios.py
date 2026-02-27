"""Nagios monitoring configuration generator.

Produces Nagios host definitions for network switches, extracted
from nagios.py.
"""

from __future__ import annotations

import jinja2

from gdoc2netcfg.models.host import NetworkInventory

_SWITCH_TEMPLATE = jinja2.Template("""\
define host {
    host_name   {{ hostname }}
    address     {{ ip }}
{% if parent %}
    parents     {{ parent }}
{% endif %}
    hostgroups  allhosts,switches
}
""")


def generate_nagios(inventory: NetworkInventory) -> str:
    """Generate Nagios host definitions for switches."""
    output: list[str] = []

    for host in inventory.hosts_sorted():
        # Determine hardware type from extra fields
        driver = host.extra.get("Driver", "")
        if not driver:
            continue

        hardware = driver.split(", ")[0].split(" ")[0]
        if hardware != "switch":
            continue

        if host.first_ipv4 is None:
            continue

        output.append(
            _SWITCH_TEMPLATE.render(
                hostname=host.hostname,
                ip=str(host.first_ipv4),
                parent=host.extra.get("Parent", ""),
            )
        )

    return "\n".join(output)
