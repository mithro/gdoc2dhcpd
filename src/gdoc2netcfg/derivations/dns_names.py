"""DNS name derivations: hostname, DHCP name, common suffix, subdomain variants."""

from __future__ import annotations


def compute_hostname(machine_name: str, sheet_type: str) -> str:
    """Compute the hostname from a machine name and sheet type.

    IoT devices get a '.iot' suffix appended. Network devices use the
    machine name directly (lowercased).

    >>> compute_hostname('thermostat', 'IoT')
    'thermostat.iot'
    >>> compute_hostname('Desktop', 'Network')
    'desktop'
    """
    hostname = machine_name.lower().strip()
    if sheet_type == "IoT":
        hostname += ".iot"
    elif sheet_type == "Test":
        hostname += ".test"
    return hostname


def compute_dhcp_name(machine_name: str, interface: str, sheet_type: str) -> str:
    """Compute the DHCP name from a machine name and interface.

    If an interface is specified, it's prepended with a dash separator.
    IoT devices get a '.iot' suffix.

    >>> compute_dhcp_name('desktop', 'eth0', 'Network')
    'eth0-desktop'
    >>> compute_dhcp_name('desktop', '', 'Network')
    'desktop'
    >>> compute_dhcp_name('thermostat', '', 'IoT')
    'thermostat.iot'
    >>> compute_dhcp_name('camera', 'eth0', 'IoT')
    'eth0-camera.iot'
    """
    dhcp_name = machine_name.lower().strip()
    if interface and interface.strip():
        dhcp_name = interface.lower().strip() + "-" + dhcp_name
    if sheet_type == "IoT":
        dhcp_name += ".iot"
    return dhcp_name


def common_suffix(a: str, *others: str) -> str:
    """Find the longest common suffix of two or more strings.

    Used to determine the canonical hostname when multiple interfaces
    share a machine. For example, eth1.ten64 and eth2.ten64 → ten64.

    >>> common_suffix('a', 'a')
    'a'
    >>> common_suffix('a', 'a', 'a')
    'a'
    >>> common_suffix('a', 'a', 'b')
    ''
    >>> common_suffix('aa', 'a')
    'a'
    >>> common_suffix('ab', 'a')
    ''
    >>> common_suffix('aba', 'aa')
    'a'
    >>> common_suffix('abca', 'aca')
    'ca'
    >>> common_suffix('abca')
    'abca'
    """
    if not others:
        return a

    lengths = [len(b) for b in others]
    lengths.append(len(a))
    min_len = min(lengths)

    i = 1
    while i < (min_len + 1):
        if not all(a[-i:] == b[-i:] for b in others):
            break
        i += 1
    i -= 1

    if i == 0:
        return ""
    return a[-i:]
