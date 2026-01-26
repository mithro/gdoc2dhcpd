"""Network topology models: VLANs, IPv6 prefixes, and sites."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class VLAN:
    """A VLAN definition with its identity and subnet mapping.

    Attributes:
        id: VLAN numeric identifier (e.g. 10)
        name: Human-readable name (e.g. 'int')
        subdomain: DNS subdomain for hosts on this VLAN (e.g. 'int')
    """

    id: int
    name: str
    subdomain: str

    def __str__(self) -> str:
        return f"VLAN {self.id} ({self.name})"


@dataclass(frozen=True)
class IPv6Prefix:
    """An IPv6 prefix used for dual-stack address generation.

    Attributes:
        prefix: The prefix string (e.g. '2404:e80:a137:')
        name: Human-readable name (e.g. 'Launtel')
        enabled: Whether this prefix is currently active
    """

    prefix: str
    name: str = ""
    enabled: bool = True

    def __str__(self) -> str:
        status = "enabled" if self.enabled else "disabled"
        return f"{self.prefix} ({self.name}, {status})"


@dataclass
class Site:
    """A network site with its topology configuration.

    Aggregates all the topology information needed by derivations:
    domain name, VLANs, IPv6 prefixes, and public IPv4 (for split-horizon).

    Attributes:
        name: Site identifier (e.g. 'welland')
        domain: Fully qualified domain (e.g. 'welland.mithis.com')
        vlans: VLAN definitions keyed by ID
        ipv6_prefixes: Active IPv6 prefixes for address generation
        network_subdomains: Third-octet to subdomain mapping for 10.1.X.Y
        public_ipv4: Optional public IPv4 for split-horizon DNS
    """

    name: str
    domain: str
    vlans: dict[int, VLAN] = field(default_factory=dict)
    ipv6_prefixes: list[IPv6Prefix] = field(default_factory=list)
    network_subdomains: dict[int, str] = field(default_factory=dict)
    public_ipv4: str | None = None

    @property
    def active_ipv6_prefixes(self) -> list[IPv6Prefix]:
        """Return only enabled IPv6 prefixes."""
        return [p for p in self.ipv6_prefixes if p.enabled]
