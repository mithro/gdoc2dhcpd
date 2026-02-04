"""Supplement: SSL/TLS certificate scanning.

Scans hosts for TLS certificate information on port 443. Results are
cached in ssl_certs.json to avoid re-scanning on every pipeline run.

This is a Supplement, not a Source — it enriches existing Host records
with additional data from external systems (TLS endpoints).
"""

from __future__ import annotations

import json
import socket
import ssl
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, NameOID

from gdoc2netcfg.models.host import Host, SSLCertInfo
from gdoc2netcfg.supplements.reachability import (
    HostReachability,
    check_port_open,
    check_reachable,
)


def _fetch_cert(ip: str, timeout: float = 5.0) -> dict | None:
    """Connect to port 443 and retrieve certificate details.

    Connects by IP address, so hostname verification is intentionally
    disabled. The 'valid' flag indicates certificate chain validity
    against the system trust store, not hostname match — hostname
    matching is the responsibility of the consumer (e.g. nginx config
    determines which cert maps to which server_name).

    Uses the cryptography library to parse the binary DER certificate,
    which works even for self-signed certificates where Python's
    getpeercert() returns minimal information.

    Returns a dict with issuer, self_signed, valid, expiry, and sans,
    or None if the connection fails.
    """
    # Chain verification context — hostname check disabled because we
    # connect by IP, not by hostname.
    ctx_verify = ssl.create_default_context()
    ctx_verify.check_hostname = False

    # Non-verifying context for retrieving self-signed cert details
    ctx_noverify = ssl.create_default_context()
    ctx_noverify.check_hostname = False
    ctx_noverify.verify_mode = ssl.CERT_NONE

    cert_der = None
    valid = False

    # Try verified first
    try:
        with socket.create_connection((ip, 443), timeout=timeout) as sock:
            with ctx_verify.wrap_socket(sock) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                valid = True
    except ssl.SSLCertVerificationError:
        # Cert exists but doesn't validate — try without verification
        try:
            with socket.create_connection((ip, 443), timeout=timeout) as sock:
                with ctx_noverify.wrap_socket(sock) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
        except (OSError, ssl.SSLError):
            return None
    except (OSError, ssl.SSLError):
        return None

    if cert_der is None:
        return None

    # Parse with cryptography library for full details
    try:
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
    except Exception:
        return None

    # Extract issuer organization or common name
    issuer_org = _get_name_attribute(cert.issuer, NameOID.ORGANIZATION_NAME)
    issuer_cn = _get_name_attribute(cert.issuer, NameOID.COMMON_NAME)
    issuer = issuer_org or issuer_cn or "Unknown"

    # Extract subject CN for SAN fallback
    subject_cn = _get_name_attribute(cert.subject, NameOID.COMMON_NAME)

    # Detect self-signed: issuer == subject (compare full Name objects)
    self_signed = cert.issuer == cert.subject

    # Extract expiry
    expiry = cert.not_valid_after_utc.strftime("%Y-%m-%d")

    # Extract SANs (Subject Alternative Names)
    sans = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                sans.append(name.value)
    except x509.ExtensionNotFound:
        # No SAN extension — fall back to subject CN
        if subject_cn:
            sans.append(subject_cn)

    return {
        "issuer": issuer,
        "self_signed": self_signed,
        "valid": valid,
        "expiry": expiry,
        "sans": sans,
    }


def _get_name_attribute(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
    """Extract a single attribute from an X.509 Name, or None if not present."""
    try:
        attrs = name.get_attributes_for_oid(oid)
        if attrs:
            return attrs[0].value
    except Exception:
        pass
    return None


def load_ssl_cert_cache(cache_path: Path) -> dict[str, dict]:
    """Load cached SSL certificate data from disk."""
    if not cache_path.exists():
        return {}
    with open(cache_path) as f:
        return json.load(f)


def save_ssl_cert_cache(cache_path: Path, data: dict[str, dict]) -> None:
    """Save SSL certificate data to disk cache."""
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    with open(cache_path, "w") as f:
        json.dump(data, f, indent="  ", sort_keys=True)


def scan_ssl_certs(
    hosts: list[Host],
    cache_path: Path,
    force: bool = False,
    max_age: float = 300,
    verbose: bool = False,
    reachability: dict[str, HostReachability] | None = None,
) -> dict[str, dict]:
    """Scan hosts for SSL/TLS certificates on port 443.

    Args:
        hosts: Host objects with IPs to scan.
        cache_path: Path to ssl_certs.json cache file.
        force: Force re-scan even if cache is fresh.
        max_age: Maximum cache age in seconds (default 5 minutes).
        verbose: Print progress to stdout.
        reachability: Pre-computed reachability data. When provided,
            uses active IPs from this instead of pinging each host.

    Returns:
        Mapping of hostname to certificate info dict.
    """
    import sys

    certs = load_ssl_cert_cache(cache_path)

    # Check if cache is fresh enough
    if not force and cache_path.exists():
        age = time.time() - cache_path.stat().st_mtime
        if age < max_age:
            if verbose:
                print(f"ssl_certs.json last updated {age:.0f}s ago, using cache.", file=sys.stderr)
            return certs

    for host in sorted(hosts, key=lambda h: h.hostname.split(".")[::-1]):
        if verbose:
            print(f"  {host.hostname:>20s} ", end="", flush=True, file=sys.stderr)

        # Use pre-computed reachability if available, otherwise ping
        if reachability is not None:
            host_reach = reachability.get(host.hostname)
            if host_reach is None or not host_reach.is_up:
                if verbose:
                    print("down", file=sys.stderr)
                continue
            active_ip = host_reach.active_ips[0] if host_reach.active_ips else None
        else:
            active_ip = None
            for iface in host.interfaces:
                ip_str = str(iface.ipv4)
                if check_reachable(ip_str):
                    active_ip = ip_str
                    break

        if active_ip is None:
            if verbose:
                print("down", file=sys.stderr)
            continue

        if verbose:
            print(f"up({active_ip}) ", end="", flush=True, file=sys.stderr)

        # Check HTTPS availability
        if not check_port_open(active_ip, 443):
            if verbose:
                print("no-https", file=sys.stderr)
            continue

        if verbose:
            print("with-https ", end="", flush=True, file=sys.stderr)

        cert_info = _fetch_cert(active_ip)
        if cert_info is not None:
            certs[host.hostname] = cert_info
            if verbose:
                status = "valid" if cert_info["valid"] else "invalid"
                issuer = cert_info["issuer"]
                print(f"{status} ({issuer})", file=sys.stderr)
        else:
            if verbose:
                print("fetch-failed", file=sys.stderr)

    save_ssl_cert_cache(cache_path, certs)
    return certs


def enrich_hosts_with_ssl_certs(
    hosts: list[Host],
    cert_data: dict[str, dict],
) -> None:
    """Attach cached SSL cert info to Host objects.

    Modifies hosts in-place by setting host.ssl_cert_info.
    """
    for host in hosts:
        info = cert_data.get(host.hostname)
        if info is not None:
            host.ssl_cert_info = SSLCertInfo(
                issuer=info["issuer"],
                self_signed=info["self_signed"],
                valid=info["valid"],
                expiry=info["expiry"],
                sans=tuple(info.get("sans", [])),
            )
