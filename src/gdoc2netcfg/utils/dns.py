"""Validation utilities for values interpolated into config files and scripts.

Prevents injection of shell metacharacters or config directives through
crafted DNS names or file paths.
"""

from __future__ import annotations

import re

# RFC 952/1123 compliant: labels are alphanumeric + hyphens, separated by dots.
# We also allow underscores (common in internal DNS) and wildcards (*).
_DNS_NAME_RE = re.compile(r"^[a-zA-Z0-9._*-]+$")

# Safe file path: alphanumeric, path separators, dots, hyphens, underscores.
# Rejects shell metacharacters, newlines, semicolons, braces, backticks.
_SAFE_PATH_RE = re.compile(r"^[a-zA-Z0-9/._ -]+$")

# Safe systemd unit name: alphanumeric, hyphens, underscores, dots, @.
# The @ is used for template instantiation (e.g. dnsmasq@external).
_SAFE_UNIT_RE = re.compile(r"^[a-zA-Z0-9._@-]+$")


def is_safe_dns_name(name: str) -> bool:
    """Check if a DNS name is safe for use in config files and scripts.

    Returns True if the name contains only characters valid in DNS names:
    letters, digits, hyphens, dots, underscores, and wildcards.

    Returns False for names containing shell metacharacters, whitespace,
    semicolons, braces, newlines, or other potentially dangerous characters.

    >>> is_safe_dns_name("desktop.welland.mithis.com")
    True
    >>> is_safe_dns_name("eth0.big-storage.int.welland.mithis.com")
    True
    >>> is_safe_dns_name("ipv4.desktop.welland.mithis.com")
    True
    >>> is_safe_dns_name("example.com; rm -rf /")
    False
    >>> is_safe_dns_name("foo$(whoami).com")
    False
    >>> is_safe_dns_name("")
    False
    """
    return bool(name and _DNS_NAME_RE.match(name))


def is_safe_path(path: str) -> bool:
    """Check if a file path is safe for interpolation into configs and scripts.

    Returns True if the path contains only safe characters: letters, digits,
    forward slashes, dots, hyphens, underscores, and spaces.

    Returns False for paths containing shell metacharacters (;|$`),
    control characters (newlines, nulls), or config syntax ({}).

    Defense-in-depth: config paths come from gdoc2netcfg.toml (admin-managed),
    but validating them prevents injection if the config file is compromised.

    >>> is_safe_path("/var/www/acme")
    True
    >>> is_safe_path("/etc/nginx/.htpasswd")
    True
    >>> is_safe_path("/path/with spaces/dir")
    True
    >>> is_safe_path("/etc/passwd; rm -rf /")
    False
    >>> is_safe_path("")
    False
    """
    return bool(path and _SAFE_PATH_RE.match(path))


def is_safe_systemd_unit(name: str) -> bool:
    """Check if a systemd unit name is safe for interpolation into scripts.

    Returns True if the name contains only characters valid in systemd
    unit names: letters, digits, hyphens, underscores, dots, and @.
    The @ character is used for template instantiation (e.g. dnsmasq@external).

    >>> is_safe_systemd_unit("dnsmasq@external")
    True
    >>> is_safe_systemd_unit("nginx")
    True
    >>> is_safe_systemd_unit("dnsmasq; curl evil.com")
    False
    >>> is_safe_systemd_unit("")
    False
    """
    return bool(name and _SAFE_UNIT_RE.match(name))
