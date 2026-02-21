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
        third_octets: Which third-octet values this VLAN covers in
            10.{site_octet}.X.Y addresses, computed from the CIDR.
            For example, VLAN 10 (int) with /21 covers octets 8-15.
        is_global: True for VLANs that use the second octet instead
            of third (e.g. 10.31.X.X for VLAN 31), typically /16 ranges.
        is_transit: True for point-to-point transit VLANs (/30), which
            use a unique (second_octet, third_octet) pair for matching.
        transit_match: For transit VLANs, the (second_octet, third_octet)
            pair to match against (e.g. (99, 21) for 10.99.21.X → VLAN 121).
    """

    id: int
    name: str
    subdomain: str
    third_octets: tuple[int, ...] = ()
    is_global: bool = False
    is_transit: bool = False
    transit_match: tuple[int, int] | None = None  # (second_octet, third_octet)

    @property
    def covered_third_octets(self) -> tuple[int, ...]:
        """Return the third-octet values covered by this VLAN.

        For global VLANs (is_global=True), returns empty tuple since
        they match on the second octet instead.
        For site VLANs, returns third_octets if set, otherwise falls
        back to (self.id,) as the default single-octet mapping.
        """
        if self.is_global or self.is_transit:
            return ()
        return self.third_octets if self.third_octets else (self.id,)

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
        site_octet: Second octet identifying the site (1=Welland, 2=Monarto).
            Used to match 10.{site_octet}.X.Y addresses to this site.
        vlans: VLAN definitions keyed by ID
        ipv6_prefixes: Active IPv6 prefixes for address generation
        network_subdomains: Third-octet to subdomain mapping for 10.{site_octet}.X.Y
        public_ipv4: Optional public IPv4 for split-horizon DNS
    """

    name: str
    domain: str
    site_octet: int = 0
    all_sites: tuple[str, ...] = ()
    vlans: dict[int, VLAN] = field(default_factory=dict)
    ipv6_prefixes: list[IPv6Prefix] = field(default_factory=list)
    network_subdomains: dict[int, str] = field(default_factory=dict)
    public_ipv4: str | None = None

    @property
    def active_ipv6_prefixes(self) -> list[IPv6Prefix]:
        """Return only enabled IPv6 prefixes."""
        return [p for p in self.ipv6_prefixes if p.enabled]

    def vlan_by_name(self, name: str) -> VLAN | None:
        """Look up a VLAN by its name (e.g. 'net', 'roam')."""
        for vlan in self.vlans.values():
            if vlan.name == name:
                return vlan
        return None

    def ip_prefix_for_vlan(self, vlan_name: str) -> str | None:
        """Return the IP prefix string for a site VLAN (e.g. '10.1.5.').

        Only works for site-local VLANs (not global). Returns None if
        the VLAN is not found, is global, or has no covered octets.
        """
        vlan = self.vlan_by_name(vlan_name)
        if vlan is None or vlan.is_global or vlan.is_transit:
            return None
        octets = vlan.covered_third_octets
        if not octets:
            return None
        return f"10.{self.site_octet}.{octets[0]}."
