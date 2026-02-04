"""Network address types: MAC, IPv4, and IPv6 addresses."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from gdoc2netcfg.utils.ip import is_local as _is_local
from gdoc2netcfg.utils.ip import is_rfc1918 as _is_rfc1918

_MAC_RE = re.compile(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$')


@dataclass(frozen=True, order=True)
class MACAddress:
    """A normalized, validated Ethernet MAC address.

    Always stored in lowercase colon-separated format (aa:bb:cc:dd:ee:ff).
    """

    address: str

    def __post_init__(self) -> None:
        if not _MAC_RE.match(self.address):
            raise ValueError(f"Invalid MAC address: {self.address!r}")

    @classmethod
    def parse(cls, raw: str) -> MACAddress:
        """Parse a MAC address from various formats.

        Accepts colon-separated, dash-separated, or dot-separated formats.
        Normalizes to lowercase colon-separated.

        >>> MACAddress.parse('AA:BB:CC:DD:EE:FF')
        MACAddress(address='aa:bb:cc:dd:ee:ff')
        >>> MACAddress.parse('aa-bb-cc-dd-ee-ff')
        MACAddress(address='aa:bb:cc:dd:ee:ff')
        >>> MACAddress.parse('aabb.ccdd.eeff')
        MACAddress(address='aa:bb:cc:dd:ee:ff')
        """
        raw = raw.strip().lower()
        # Remove common separators and re-format
        cleaned = raw.replace('-', '').replace(':', '').replace('.', '')
        if len(cleaned) != 12:
            raise ValueError(f"Invalid MAC address: {raw!r}")
        formatted = ':'.join(cleaned[i:i + 2] for i in range(0, 12, 2))
        return cls(address=formatted)

    def to_int(self) -> int:
        """Convert to integer for prefix calculations.

        >>> MACAddress.parse('00:00:00:00:00:01').to_int()
        1
        >>> MACAddress.parse('ff:ff:ff:ff:ff:ff').to_int()
        281474976710655
        """
        return int(self.address.replace(':', ''), 16)

    @classmethod
    def from_int(cls, value: int) -> MACAddress:
        """Create from integer value.

        >>> MACAddress.from_int(1)
        MACAddress(address='00:00:00:00:00:01')
        """
        hex_str = f'{value:012x}'
        formatted = ':'.join(hex_str[i:i + 2] for i in range(0, 12, 2))
        return cls(address=formatted)

    def prefix(self, bits: int) -> int:
        """Get the prefix of this MAC at the given bit length.

        Returns the integer value with low bits masked to zero.

        >>> hex(MACAddress.parse('aa:bb:cc:dd:ee:ff').prefix(24))
        '0xaabbcc000000'
        >>> hex(MACAddress.parse('aa:bb:cc:dd:ee:ff').prefix(48))
        '0xaabbccddeeff'
        """
        mac_int = self.to_int()
        mask = (0xffffffffffff << (48 - bits)) & 0xffffffffffff
        return mac_int & mask

    def __str__(self) -> str:
        return self.address


@dataclass(frozen=True, order=True)
class IPv4Address:
    """An IPv4 address with utility methods for network classification.

    Wraps Python's ipaddress.IPv4Address and adds octets access and
    network classification helpers used throughout the pipeline.
    """

    _sort_key: tuple[int, ...]
    address: str

    def __init__(self, address: str) -> None:
        parsed = ipaddress.IPv4Address(address)
        addr_str = str(parsed)
        octets = tuple(int(b) for b in addr_str.split('.'))
        object.__setattr__(self, 'address', addr_str)
        object.__setattr__(self, '_sort_key', octets)

    @property
    def octets(self) -> tuple[int, int, int, int]:
        """Return the four octets as a tuple of ints.

        >>> IPv4Address('10.1.10.124').octets
        (10, 1, 10, 124)
        """
        return self._sort_key  # type: ignore[return-value]

    def is_local(self) -> bool:
        """Check if this address is in a reserved/non-routable range.

        >>> IPv4Address('10.1.10.1').is_local()
        True
        >>> IPv4Address('8.8.8.8').is_local()
        False
        """
        return _is_local(self.address)

    def is_rfc1918(self) -> bool:
        """Check if this address is in RFC 1918 private space.

        >>> IPv4Address('10.1.10.1').is_rfc1918()
        True
        >>> IPv4Address('8.8.8.8').is_rfc1918()
        False
        """
        return _is_rfc1918(self.address)

    def __str__(self) -> str:
        return self.address

    def __repr__(self) -> str:
        return f"IPv4Address({self.address!r})"


@dataclass(frozen=True)
class IPv6Address:
    """An IPv6 address with provenance tracking (which prefix it came from).

    Generated from IPv4 addresses via the mapping scheme:
    10.AA.BB.CCC -> {prefix}AABB::CCC
    """

    address: str
    prefix: str  # The IPv6 prefix this was generated from

    @property
    def exploded(self) -> str:
        """Return the fully expanded IPv6 address.

        >>> IPv6Address('2404:e80:a137:110::124', '2404:e80:a137:').exploded
        '2404:0e80:a137:0110:0000:0000:0000:0124'
        """
        return ipaddress.IPv6Address(self.address).exploded

    def to_ptr(self) -> str:
        """Convert to PTR record format (ip6.arpa nibble format).

        >>> IPv6Address('2404:e80:a137:110::124', '2404:e80:a137:').to_ptr()
        '4.2.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.1.0.7.3.1.a.0.8.e.0.4.0.4.2.ip6.arpa'
        """
        addr = ipaddress.IPv6Address(self.address)
        full_hex = addr.exploded.replace(':', '')
        return '.'.join(reversed(full_hex)) + '.ip6.arpa'

    def __str__(self) -> str:
        return self.address

    def __repr__(self) -> str:
        return f"IPv6Address({self.address!r}, prefix={self.prefix!r})"
