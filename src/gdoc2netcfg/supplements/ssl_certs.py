"""Supplement: SSL/TLS certificate scanning.

Scans hosts for TLS certificate information on port 443. Results are
cached in ssl_certs.json to avoid re-scanning on every pipeline run.

This is a Supplement, not a Source — it enriches existing Host records
with additional data from external systems (TLS endpoints).
"""

from __future__ import annotations

import json
import ssl
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

from gdoc2netcfg.models.host import Host, SSLCertInfo
from gdoc2netcfg.supplements.reachability import check_port_open, check_reachable


def _fetch_cert(ip: str, timeout: float = 5.0) -> dict | None:
    """Connect to port 443 and retrieve certificate details.

    Returns a dict with issuer, self_signed, valid, expiry, and sans,
    or None if the connection fails.
    """
    # First try with system trust verification
    ctx_verify = ssl.create_default_context()
    ctx_verify.check_hostname = False

    # Also prepare a non-verifying context for self-signed certs
    ctx_noverify = ssl.create_default_context()
    ctx_noverify.check_hostname = False
    ctx_noverify.verify_mode = ssl.CERT_NONE

    cert_dict = None
    valid = False

    # Try verified first
    try:
        with socket.create_connection((ip, 443), timeout=timeout) as sock:
            with ctx_verify.wrap_socket(sock) as ssock:
                cert_dict = ssock.getpeercert()
                valid = True
    except ssl.SSLCertVerificationError:
        # Cert exists but doesn't validate — try without verification
        try:
            with socket.create_connection((ip, 443), timeout=timeout) as sock:
                with ctx_noverify.wrap_socket(sock) as ssock:
                    cert_dict = ssock.getpeercert()
        except (OSError, ssl.SSLError):
            return None
    except (OSError, ssl.SSLError):
        return None

    if cert_dict is None:
        return None

    # Extract issuer organization
    issuer_parts = dict(x[0] for x in cert_dict.get("issuer", ()))
    issuer = issuer_parts.get("organizationName", "Unknown")

    # Extract expiry
    not_after = cert_dict.get("notAfter", "")
    try:
        expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
        expiry = expiry_dt.strftime("%Y-%m-%d")
    except (ValueError, TypeError):
        expiry = ""

    # Extract SANs
    sans = []
    for san_type, san_value in cert_dict.get("subjectAltName", ()):
        if san_type == "DNS":
            sans.append(san_value)

    # Detect self-signed: issuer == subject
    subject_parts = dict(x[0] for x in cert_dict.get("subject", ()))
    self_signed = issuer_parts == subject_parts

    return {
        "issuer": issuer,
        "self_signed": self_signed,
        "valid": valid,
        "expiry": expiry,
        "sans": sans,
    }


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
) -> dict[str, dict]:
    """Scan hosts for SSL/TLS certificates on port 443.

    Args:
        hosts: Host objects with IPs to scan.
        cache_path: Path to ssl_certs.json cache file.
        force: Force re-scan even if cache is fresh.
        max_age: Maximum cache age in seconds (default 5 minutes).
        verbose: Print progress to stdout.

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

        # Find an active IP
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
