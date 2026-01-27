"""Constraint predicates organized by scope.

Field Constraints — run on raw DeviceRecords after Source.
Record Constraints — run on Hosts after Field Derivations.
Cross-Record Constraints — run on NetworkInventory after Aggregate Derivations.
"""

from __future__ import annotations

import re

from gdoc2netcfg.constraints.errors import (
    ConstraintViolation,
    Severity,
    ValidationResult,
)
from gdoc2netcfg.models.host import Host, NetworkInventory
from gdoc2netcfg.sources.parser import DeviceRecord

_DHCP_NAME_RE = re.compile(r'^[a-z0-9.\-_]+$')


# ---------------------------------------------------------------------------
# Field Constraints (on raw DeviceRecords)
# ---------------------------------------------------------------------------

def validate_field_constraints(records: list[DeviceRecord]) -> ValidationResult:
    """Validate field-level constraints on raw device records.

    Checks:
    - MAC address must be present
    - Machine name must be present
    - IP address must be present
    """
    result = ValidationResult()

    for record in records:
        record_id = f"{record.sheet_name}:{record.row_number}"

        if not record.mac_address:
            result.add(ConstraintViolation(
                severity=Severity.WARNING,
                code="missing_mac",
                message=f"No MAC address (machine={record.machine!r})",
                record_id=record_id,
                field="mac_address",
            ))

        if not record.machine:
            result.add(ConstraintViolation(
                severity=Severity.WARNING,
                code="missing_machine",
                message=f"No machine name (ip={record.ip!r})",
                record_id=record_id,
                field="machine",
            ))

        if not record.ip:
            result.add(ConstraintViolation(
                severity=Severity.WARNING,
                code="missing_ip",
                message=f"No IP address (machine={record.machine!r})",
                record_id=record_id,
                field="ip",
            ))

    return result


# ---------------------------------------------------------------------------
# Record Constraints (on Hosts after derivations)
# ---------------------------------------------------------------------------

def validate_record_constraints(hosts: list[Host]) -> ValidationResult:
    """Validate record-level constraints on derived Host objects.

    Checks:
    - DHCP names must match [a-z0-9.\\-_]+ pattern
    - BMC hosts must be on Network Management network (10.1.5.X)
      unless they are test-hardware (10.41.X.X)
    - Test-hardware BMCs (10.41.X.X) must be on 10.X.1.X subnet
    """
    result = ValidationResult()

    for host in hosts:
        for iface in host.interfaces:
            # DHCP name validation
            if iface.dhcp_name and not _DHCP_NAME_RE.match(iface.dhcp_name):
                result.add(ConstraintViolation(
                    severity=Severity.ERROR,
                    code="invalid_dhcp_name",
                    message=(
                        f"Invalid characters in DHCP name: {iface.dhcp_name!r} "
                        f"(host={host.hostname})"
                    ),
                    record_id=host.hostname,
                    field="dhcp_name",
                ))

            # BMC placement validation
            if iface.name and "bmc" in iface.name.lower():
                ip_str = str(iface.ipv4)

                if ip_str.startswith("10.41."):
                    # Test-hardware BMC: must be on 10.X.1.X subnet
                    third_octet = iface.ipv4.octets[2]
                    if third_octet != 1:
                        result.add(ConstraintViolation(
                            severity=Severity.ERROR,
                            code="bmc_wrong_subnet",
                            message=(
                                f"Test-hardware BMC must be on 10.X.1.X subnet! "
                                f"{iface.dhcp_name} has IP {ip_str}, expected 10.41.1.X"
                            ),
                            record_id=host.hostname,
                            field="ip",
                        ))
                elif not ip_str.startswith("10.1.5."):
                    # Regular BMC: must be on Network Management (10.1.5.X)
                    result.add(ConstraintViolation(
                        severity=Severity.ERROR,
                        code="bmc_not_management",
                        message=(
                            f"BMC not on Network Management network! "
                            f"{iface.dhcp_name} has IP {ip_str}, expected 10.1.5.X"
                        ),
                        record_id=host.hostname,
                        field="ip",
                    ))

    return result


# ---------------------------------------------------------------------------
# Cross-Record Constraints (on NetworkInventory)
# ---------------------------------------------------------------------------

def validate_cross_record_constraints(inventory: NetworkInventory) -> ValidationResult:
    """Validate cross-record constraints on the full inventory.

    Checks:
    - MAC address must not be assigned to multiple different IPs
    - IP address uniqueness (multiple MACs on same IP only in roaming range)
    """
    result = ValidationResult()

    # MAC → IP uniqueness
    mac_to_ips: dict[str, list[tuple[str, str]]] = {}  # mac → [(ip, dhcp_name)]
    for host in inventory.hosts:
        for iface in host.interfaces:
            mac_str = str(iface.mac)
            ip_str = str(iface.ipv4)
            if mac_str not in mac_to_ips:
                mac_to_ips[mac_str] = []
            mac_to_ips[mac_str].append((ip_str, iface.dhcp_name))

    for mac, entries in mac_to_ips.items():
        unique_ips = set(ip for ip, _ in entries)
        if len(unique_ips) > 1:
            ip_list = ", ".join(f"{ip} ({name})" for ip, name in entries)
            result.add(ConstraintViolation(
                severity=Severity.ERROR,
                code="mac_duplicate_ip",
                message=f"MAC {mac} assigned to multiple IPs: {ip_list}",
                record_id=mac,
                field="mac_address",
            ))

    # Multiple MACs per IP: only allowed in roaming range (10.1.20.X)
    for ip_str, macs in inventory.ip_to_macs.items():
        if len(macs) > 1 and not ip_str.startswith("10.1.20."):
            mac_list = ", ".join(f"{mac} ({name})" for mac, name in macs)
            result.add(ConstraintViolation(
                severity=Severity.ERROR,
                code="ip_multiple_macs",
                message=(
                    f"Multiple MACs for non-roaming IP {ip_str}: {mac_list}"
                ),
                record_id=ip_str,
                field="ip",
            ))

    return result


def validate_all(
    records: list[DeviceRecord],
    hosts: list[Host],
    inventory: NetworkInventory,
) -> ValidationResult:
    """Run all constraints at the appropriate scope.

    Returns a combined ValidationResult with all violations.
    """
    combined = ValidationResult()

    for result in [
        validate_field_constraints(records),
        validate_record_constraints(hosts),
        validate_cross_record_constraints(inventory),
    ]:
        for violation in result.violations:
            combined.add(violation)

    return combined
