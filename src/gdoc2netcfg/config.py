"""Load pipeline configuration from gdoc2netcfg.toml."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from gdoc2netcfg.models.network import VLAN, IPv6Prefix, Site


@dataclass
class SheetConfig:
    """Configuration for a single spreadsheet sheet source."""

    name: str
    url: str


@dataclass
class CacheConfig:
    """Configuration for the local CSV cache."""

    directory: Path = field(default_factory=lambda: Path(".cache"))


@dataclass
class GeneratorConfig:
    """Configuration for a single generator."""

    name: str
    enabled: bool = True
    output: str = ""
    params: dict[str, str] = field(default_factory=dict)


@dataclass
class PipelineConfig:
    """Full pipeline configuration loaded from gdoc2netcfg.toml.

    Combines topology configuration (Site) with pipeline operational
    parameters (sheets, cache, generators).
    """

    site: Site
    sheets: list[SheetConfig] = field(default_factory=list)
    cache: CacheConfig = field(default_factory=CacheConfig)
    generators: dict[str, GeneratorConfig] = field(default_factory=dict)


def _build_site(data: dict) -> Site:
    """Build a Site from parsed TOML data."""
    site_data = data.get("site", {})

    # Build VLANs from [vlans] section
    vlans: dict[int, VLAN] = {}
    for vlan_id_str, vlan_info in data.get("vlans", {}).items():
        vlan_id = int(vlan_id_str)
        vlans[vlan_id] = VLAN(
            id=vlan_id,
            name=vlan_info["name"],
            subdomain=vlan_info["subdomain"],
        )

    # Build IPv6 prefixes from [ipv6] section
    ipv6_data = data.get("ipv6", {})
    ipv6_prefixes = [
        IPv6Prefix(prefix=p.strip()) for p in ipv6_data.get("prefixes", [])
    ]

    # Build network subdomains mapping
    network_subdomains: dict[int, str] = {}
    for octet_str, subdomain in data.get("network_subdomains", {}).items():
        network_subdomains[int(octet_str)] = subdomain

    return Site(
        name=site_data.get("name", ""),
        domain=site_data.get("domain", ""),
        vlans=vlans,
        ipv6_prefixes=ipv6_prefixes,
        network_subdomains=network_subdomains,
        public_ipv4=site_data.get("public_ipv4"),
    )


def _build_sheets(data: dict) -> list[SheetConfig]:
    """Build sheet configs from parsed TOML data."""
    sheets = []
    for name, url in data.get("sheets", {}).items():
        sheets.append(SheetConfig(name=name, url=url))
    return sheets


def _build_generators(data: dict) -> dict[str, GeneratorConfig]:
    """Build generator configs from parsed TOML data."""
    generators_section = data.get("generators", {})
    enabled_names = generators_section.get("enabled", [])

    generators: dict[str, GeneratorConfig] = {}
    for name in enabled_names:
        gen_section = generators_section.get(name, {})
        generators[name] = GeneratorConfig(
            name=name,
            enabled=True,
            output=gen_section.get("output", ""),
            params={k: v for k, v in gen_section.items() if k != "output"},
        )
    return generators


def load_config(config_path: Path | str | None = None) -> PipelineConfig:
    """Load pipeline configuration from a TOML file.

    If config_path is None, looks for gdoc2netcfg.toml in the current
    directory.
    """
    if config_path is None:
        config_path = Path("gdoc2netcfg.toml")
    else:
        config_path = Path(config_path)

    with open(config_path, "rb") as f:
        data = tomllib.load(f)

    return PipelineConfig(
        site=_build_site(data),
        sheets=_build_sheets(data),
        cache=CacheConfig(
            directory=Path(data.get("cache", {}).get("directory", ".cache")),
        ),
        generators=_build_generators(data),
    )
