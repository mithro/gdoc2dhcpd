"""SNMP availability validation constraints.

Validates that hosts with known SNMP-capable hardware respond to SNMP
when they are reachable. Non-response from reachable known devices is
flagged as an error; unreachable hosts and unknown hardware are skipped.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from gdoc2netcfg.constraints.errors import (
    ConstraintViolation,
    Severity,
    ValidationResult,
)
from gdoc2netcfg.derivations.hardware import (
    HARDWARE_CISCO_SWITCH,
    HARDWARE_NETGEAR_SWITCH,
    HARDWARE_SUPERMICRO_BMC,
)

if TYPE_CHECKING:
    from gdoc2netcfg.models.host import Host
    from gdoc2netcfg.supplements.reachability import HostReachability

# Hardware types that should always respond to SNMP
SNMP_REQUIRED_HARDWARE = {HARDWARE_CISCO_SWITCH, HARDWARE_NETGEAR_SWITCH, HARDWARE_SUPERMICRO_BMC}


def validate_snmp_availability(
    hosts: list[Host],
    reachability: dict[str, HostReachability] | None = None,
) -> ValidationResult:
    """Validate SNMP availability for known SNMP-capable hardware.

    For hosts with hardware_type in SNMP_REQUIRED_HARDWARE:
    - If host is UP (reachable) but snmp_data is None → ERROR
    - If host is DOWN (unreachable) → no error (network issue)
    - If no reachability data → skip validation entirely

    For all other hardware types: no validation (SNMP is opportunistic).

    Args:
        hosts: Host objects with snmp_data and hardware_type populated.
        reachability: Pre-computed reachability data. When None,
            SNMP validation is skipped entirely (can't distinguish
            "no SNMP" from "host down").

    Returns:
        ValidationResult with SNMP availability violations.
    """
    result = ValidationResult()

    if reachability is None:
        return result

    for host in hosts:
        if host.hardware_type not in SNMP_REQUIRED_HARDWARE:
            continue

        host_reach = reachability.get(host.hostname)
        if host_reach is None or not host_reach.is_up:
            continue

        if host.snmp_data is None:
            result.add(ConstraintViolation(
                severity=Severity.ERROR,
                code="snmp_no_response",
                message=(
                    f"{host.hardware_type} host is reachable but not responding "
                    f"to SNMP (IPs: {', '.join(host_reach.active_ips)})"
                ),
                record_id=host.hostname,
                field="snmp_data",
            ))

    return result
