"""SSL certificate validation constraints.

Validates SSL certificate data against expected DNS names and reports:
- Self-signed certificates that should migrate to Let's Encrypt
- Expired or soon-to-expire certificates
- Missing or extra SANs compared to expected DNS names
- Hostname/SAN mismatches
"""

from __future__ import annotations

from datetime import datetime, timezone

from gdoc2netcfg.constraints.errors import (
    ConstraintViolation,
    Severity,
    ValidationResult,
)
from gdoc2netcfg.models.host import Host

# Days until expiry that triggers a warning
EXPIRY_WARNING_DAYS = 30


def validate_ssl_certificates(
    hosts: list[Host],
    expiry_warning_days: int = EXPIRY_WARNING_DAYS,
) -> ValidationResult:
    """Validate SSL certificates against expected DNS names.

    Checks:
    - Self-signed certs that should migrate to Let's Encrypt
    - Expired or soon-to-expire Let's Encrypt certificates
    - SANs that don't match expected DNS names
    - Primary hostname not in SANs

    Args:
        hosts: Host objects with ssl_cert_info and dns_names populated.
        expiry_warning_days: Days until expiry to trigger warning.

    Returns:
        ValidationResult with all SSL-related violations.
    """
    result = ValidationResult()

    for host in hosts:
        if host.ssl_cert_info is None:
            continue

        cert = host.ssl_cert_info
        hostname = host.hostname

        # Get expected FQDNs from dns_names
        expected_fqdns = {dn.name for dn in host.dns_names if dn.is_fqdn}

        # Check for self-signed certificates
        if cert.self_signed:
            result.add(ConstraintViolation(
                severity=Severity.WARNING,
                code="ssl_self_signed",
                message=f"Self-signed certificate (issuer: {cert.issuer}), "
                        f"consider migrating to Let's Encrypt",
                record_id=hostname,
                field="ssl_cert_info",
            ))

        # Check for expired or soon-to-expire certificates
        if cert.expiry:
            _check_expiry(result, hostname, cert, expiry_warning_days)

        # Check SAN coverage
        _check_san_coverage(result, hostname, cert, expected_fqdns)

    return result


def _check_expiry(
    result: ValidationResult,
    hostname: str,
    cert,
    warning_days: int,
) -> None:
    """Check certificate expiry and add violations if needed."""
    try:
        expiry_date = datetime.strptime(cert.expiry, "%Y-%m-%d").replace(
            tzinfo=timezone.utc
        )
    except (ValueError, TypeError):
        return

    now = datetime.now(timezone.utc)
    days_until_expiry = (expiry_date - now).days

    if days_until_expiry < 0:
        result.add(ConstraintViolation(
            severity=Severity.ERROR,
            code="ssl_expired",
            message=f"Certificate expired {-days_until_expiry} days ago "
                    f"(expired: {cert.expiry}, issuer: {cert.issuer})",
            record_id=hostname,
            field="ssl_cert_info.expiry",
        ))
    elif days_until_expiry <= warning_days:
        result.add(ConstraintViolation(
            severity=Severity.WARNING,
            code="ssl_expiring_soon",
            message=f"Certificate expires in {days_until_expiry} days "
                    f"(expires: {cert.expiry}, issuer: {cert.issuer})",
            record_id=hostname,
            field="ssl_cert_info.expiry",
        ))


def _check_san_coverage(
    result: ValidationResult,
    hostname: str,
    cert,
    expected_fqdns: set[str],
) -> None:
    """Check that SANs cover expected FQDNs."""
    cert_sans = set(cert.sans)

    # Find primary FQDN (first one, typically hostname.domain)
    primary_fqdn = None
    for fqdn in sorted(expected_fqdns):
        if fqdn.startswith(hostname.replace(".", "-") + ".") or fqdn.startswith(hostname + "."):
            primary_fqdn = fqdn
            break

    # Check if primary hostname is in SANs
    if primary_fqdn and primary_fqdn not in cert_sans:
        result.add(ConstraintViolation(
            severity=Severity.WARNING,
            code="ssl_missing_primary_san",
            message=f"Primary FQDN '{primary_fqdn}' not in certificate SANs "
                    f"(SANs: {', '.join(sorted(cert_sans))})",
            record_id=hostname,
            field="ssl_cert_info.sans",
        ))

    # Check for missing SANs (expected but not in cert)
    missing_sans = expected_fqdns - cert_sans
    if missing_sans and len(missing_sans) <= 10:
        # Only report if a reasonable number are missing
        result.add(ConstraintViolation(
            severity=Severity.WARNING,
            code="ssl_missing_sans",
            message=f"Expected FQDNs not in certificate: "
                    f"{', '.join(sorted(missing_sans)[:5])}"
                    f"{' (and more)' if len(missing_sans) > 5 else ''}",
            record_id=hostname,
            field="ssl_cert_info.sans",
        ))

    # Check for extra SANs (in cert but not expected)
    # Filter out obvious non-FQDN SANs like "IPMI", "fritz.box", etc.
    extra_sans = cert_sans - expected_fqdns
    extra_sans = {s for s in extra_sans if "." in s and not s.endswith(".local")}
    if extra_sans:
        result.add(ConstraintViolation(
            severity=Severity.WARNING,
            code="ssl_extra_sans",
            message=f"Certificate has SANs not in expected DNS names: "
                    f"{', '.join(sorted(extra_sans)[:5])}"
                    f"{' (and more)' if len(extra_sans) > 5 else ''}",
            record_id=hostname,
            field="ssl_cert_info.sans",
        ))


def format_ssl_validation_report(result: ValidationResult) -> str:
    """Format SSL validation results as a categorized report.

    Groups violations by type for easier reading:
    - Self-signed certificates needing migration
    - Expired/expiring certificates
    - SAN mismatches
    """
    if not result.violations:
        return "SSL validation: All certificates OK"

    sections = []

    # Self-signed certificates
    self_signed = [v for v in result.violations if v.code == "ssl_self_signed"]
    if self_signed:
        lines = ["Self-signed certificates (consider Let's Encrypt):"]
        for v in sorted(self_signed, key=lambda x: x.record_id):
            lines.append(f"  - {v.record_id}: {v.message.split(',')[0]}")
        sections.append("\n".join(lines))

    # Expired certificates
    expired = [v for v in result.violations if v.code == "ssl_expired"]
    if expired:
        lines = ["EXPIRED certificates (immediate action required):"]
        for v in sorted(expired, key=lambda x: x.record_id):
            lines.append(f"  - {v.record_id}: {v.message}")
        sections.append("\n".join(lines))

    # Expiring soon
    expiring = [v for v in result.violations if v.code == "ssl_expiring_soon"]
    if expiring:
        lines = ["Certificates expiring soon:"]
        for v in sorted(expiring, key=lambda x: x.record_id):
            lines.append(f"  - {v.record_id}: {v.message}")
        sections.append("\n".join(lines))

    # SAN mismatches
    san_issues = [v for v in result.violations if v.code.startswith("ssl_") and "san" in v.code]
    if san_issues:
        lines = ["SAN mismatches:"]
        for v in sorted(san_issues, key=lambda x: (x.record_id, x.code)):
            lines.append(f"  - {v.record_id} ({v.code}): {v.message}")
        sections.append("\n".join(lines))

    return "\n\n".join(sections)
