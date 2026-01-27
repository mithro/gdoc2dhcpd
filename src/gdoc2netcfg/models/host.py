"""Host models: network interfaces, hosts, and the full inventory."""

from __future__ import annotations

from dataclasses import dataclass, field

from gdoc2netcfg.models.addressing import IPv4Address, IPv6Address, MACAddress
from gdoc2netcfg.models.network import Site


@dataclass(frozen=True)
class DNSName:
    """A DNS name with its associated IP addresses.

    Each DNS name maps to a specific IPv4 address and zero or more
    IPv6 addresses. The is_fqdn flag distinguishes full domain names
    (e.g. 'big-storage.welland.mithis.com') from short names
    (e.g. 'big-storage').
    """

    name: str
    ipv4: IPv4Address | None = None
    ipv6_addresses: tuple[IPv6Address, ...] = ()
    is_fqdn: bool = False


@dataclass(frozen=True)
class NetworkInterface:
    """A single network interface on a host.

    Attributes:
        name: Interface name (e.g. 'eth0', 'bmc'), or None for the default/only interface
        mac: Ethernet MAC address
        ipv4: IPv4 address
        ipv6_addresses: IPv6 addresses generated from the IPv4
        vlan_id: VLAN this interface belongs to (derived from IP)
        dhcp_name: Name used for DHCP registration
    """

    name: str | None
    mac: MACAddress
    ipv4: IPv4Address
    ipv6_addresses: list[IPv6Address] = field(default_factory=list)
    vlan_id: int | None = None
    dhcp_name: str = ""


@dataclass(frozen=True)
class SSLCertInfo:
    """SSL/TLS certificate information for a host.

    Populated by the ssl_certs supplement after scanning port 443.
    """

    issuer: str
    self_signed: bool
    valid: bool
    expiry: str
    sans: tuple[str, ...] = ()


@dataclass
class Host:
    """A logical host with one or more network interfaces.

    Built by aggregating raw device records that share the same machine name.

    Attributes:
        machine_name: Raw machine name from the spreadsheet
        hostname: Computed hostname (may include suffix like '.iot')
        sheet_type: Which spreadsheet sheet this came from ('Network', 'IoT', etc.)
        interfaces: All network interfaces for this host
        default_ipv4: The primary IPv4 address for bare hostname resolution
        subdomain: Network subdomain (e.g. 'int', 'iot', 'net')
        sshfp_records: SSH fingerprint records (populated by supplement)
        extra: Additional spreadsheet columns preserved for generators
    """

    machine_name: str
    hostname: str
    sheet_type: str = "Network"
    interfaces: list[NetworkInterface] = field(default_factory=list)
    default_ipv4: IPv4Address | None = None
    subdomain: str | None = None
    sshfp_records: list[str] = field(default_factory=list)
    extra: dict[str, str] = field(default_factory=dict)
    dns_names: list[DNSName] = field(default_factory=list)
    hardware_type: str | None = None
    ssl_cert_info: SSLCertInfo | None = None

    @property
    def interface_by_name(self) -> dict[str | None, NetworkInterface]:
        """Map interface names to interfaces."""
        return {iface.name: iface for iface in self.interfaces}

    @property
    def all_ipv4(self) -> dict[str | None, IPv4Address]:
        """Map interface names to their IPv4 addresses."""
        return {iface.name: iface.ipv4 for iface in self.interfaces}

    @property
    def all_macs(self) -> list[MACAddress]:
        """All MAC addresses across all interfaces."""
        return [iface.mac for iface in self.interfaces]

    def is_bmc(self) -> bool:
        """Check if any interface is a BMC (Baseboard Management Controller)."""
        return any(
            iface.name and 'bmc' in iface.name.lower()
            for iface in self.interfaces
        )

    def is_multi_interface(self) -> bool:
        """Check if this host has multiple network interfaces."""
        return len(self.interfaces) > 1


@dataclass
class NetworkInventory:
    """The fully enriched network data model.

    This is the output of the pipeline's derivation and supplement stages,
    and the input to all generators. Contains the site configuration, all
    hosts, and precomputed indexes for efficient lookup.

    Attributes:
        site: Site topology configuration
        hosts: All hosts in the inventory
        ip_to_hostname: Precomputed IP→hostname mapping
        ip_to_macs: Precomputed IP→[(mac, dhcp_name)] mapping
    """

    site: Site
    hosts: list[Host] = field(default_factory=list)
    ip_to_hostname: dict[str, str] = field(default_factory=dict)
    ip_to_macs: dict[str, list[tuple[MACAddress, str]]] = field(default_factory=dict)

    def hosts_sorted(self) -> list[Host]:
        """Return hosts sorted by reversed hostname components.

        This matches the existing dnsmasq.py sort order for host-record output.
        """
        return sorted(self.hosts, key=lambda h: h.hostname.split('.')[::-1])

    def host_by_hostname(self, hostname: str) -> Host | None:
        """Look up a host by its hostname."""
        for host in self.hosts:
            if host.hostname == hostname:
                return host
        return None
