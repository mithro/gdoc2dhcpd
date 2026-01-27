"""DNS name validation utilities.

Provides validation for DNS names before they are interpolated into
config files (nginx, certbot) or shell scripts. Prevents injection
of shell metacharacters or config directives through crafted names.
"""

from __future__ import annotations

import re

# RFC 952/1123 compliant: labels are alphanumeric + hyphens, separated by dots.
# We also allow underscores (common in internal DNS) and wildcards (*).
_DNS_NAME_RE = re.compile(r"^[a-zA-Z0-9._*-]+$")


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
