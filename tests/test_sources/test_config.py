"""Tests for configuration loading."""

from pathlib import Path

from gdoc2netcfg.config import load_config


class TestLoadConfig:
    def test_load_project_config(self):
        """Load the actual gdoc2netcfg.toml from the project root."""
        project_root = Path(__file__).parent.parent.parent
        config_path = project_root / "gdoc2netcfg.toml"
        config = load_config(config_path)

        # Site
        assert config.site.name == "welland"
        assert config.site.domain == "welland.mithis.com"

        # VLANs
        assert 10 in config.site.vlans
        assert config.site.vlans[10].name == "int"
        assert config.site.vlans[10].subdomain == "int"
        assert 90 in config.site.vlans
        assert config.site.vlans[90].name == "iot"

        # IPv6 prefixes
        assert len(config.site.ipv6_prefixes) >= 1
        assert config.site.ipv6_prefixes[0].prefix == "2404:e80:a137:"

        # Network subdomains
        assert config.site.network_subdomains[10] == "int"
        assert config.site.network_subdomains[11] == "int"
        assert config.site.network_subdomains[90] == "iot"

        # Sheets
        assert len(config.sheets) >= 2
        sheet_names = [s.name for s in config.sheets]
        assert "network" in sheet_names
        assert "iot" in sheet_names

        # Generators
        assert "dnsmasq" in config.generators
        assert config.generators["dnsmasq"].output == "dnsmasq.static.conf"

    def test_load_minimal_config(self, tmp_path: Path):
        """Load a minimal TOML config."""
        config_file = tmp_path / "test.toml"
        config_file.write_text(
            '[site]\nname = "test"\ndomain = "test.example.com"\n'
        )
        config = load_config(config_file)

        assert config.site.name == "test"
        assert config.site.domain == "test.example.com"
        assert config.site.vlans == {}
        assert config.sheets == []
