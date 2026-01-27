"""Tests for the CLI entry point."""

import argparse
import textwrap

import pytest

from gdoc2netcfg.cli.main import _write_multi_file_output, main
from gdoc2netcfg.config import GeneratorConfig


@pytest.fixture
def test_config(tmp_path):
    """Create a minimal test config file."""
    config = tmp_path / "gdoc2netcfg.toml"
    config.write_text(textwrap.dedent("""\
        [site]
        name = "test"
        domain = "test.example.com"

        [sheets]

        [cache]
        directory = ".cache"

        [ipv6]
        prefixes = ["2001:db8:1:"]

        [vlans]
        10 = { name = "int", subdomain = "int" }

        [network_subdomains]
        10 = "int"

        [generators]
        enabled = ["dnsmasq"]

        [generators.dnsmasq]
        output = "dnsmasq.conf"
    """))
    return config


class TestMainArgParsing:
    def test_no_command_shows_help(self, capsys):
        result = main([])
        assert result == 0

    def test_info_command(self, test_config, capsys):
        result = main(["-c", str(test_config), "info"])
        assert result == 0
        captured = capsys.readouterr()
        assert "test" in captured.out
        assert "test.example.com" in captured.out

    def test_info_shows_vlans(self, test_config, capsys):
        main(["-c", str(test_config), "info"])
        captured = capsys.readouterr()
        assert "int" in captured.out

    def test_missing_config(self, tmp_path):
        with pytest.raises(SystemExit):
            main(["-c", str(tmp_path / "missing.toml"), "info"])


class TestValidateCommand:
    def test_validate_with_no_data_exits(self, test_config, tmp_path):
        """Validate with no cached data should error."""
        with pytest.raises(SystemExit):
            main(["-c", str(test_config), "validate"])


class TestGenerateCommand:
    def test_generate_with_no_data_exits(self, test_config):
        """Generate with no cached data should error."""
        with pytest.raises(SystemExit):
            main(["-c", str(test_config), "generate"])

    def test_generate_with_cached_data(self, tmp_path, capsys):
        """Generate using cached CSV data."""
        # Create cache with sample data
        cache_dir = tmp_path / ".cache"
        cache_dir.mkdir()
        (cache_dir / "network.csv").write_text(
            "Machine,MAC Address,IP,Interface\n"
            "desktop,aa:bb:cc:dd:ee:ff,10.1.10.1,\n"
        )

        # Create config pointing to cache
        config = tmp_path / "gdoc2netcfg.toml"
        config.write_text(textwrap.dedent(f"""\
            [site]
            name = "test"
            domain = "test.example.com"

            [sheets]
            network = "https://example.com/not-used"

            [cache]
            directory = "{cache_dir}"

            [ipv6]
            prefixes = ["2001:db8:1:"]

            [vlans]
            10 = {{ name = "int", subdomain = "int" }}

            [network_subdomains]
            10 = "int"

            [generators]
            enabled = ["dnsmasq"]

            [generators.dnsmasq]
            output = ""
        """))

        result = main(["-c", str(config), "generate", "--stdout", "dnsmasq"])
        assert result == 0
        captured = capsys.readouterr()
        assert "dhcp-host=" in captured.out
        assert "aa:bb:cc:dd:ee:ff" in captured.out

    def test_generate_unknown_generator(self, tmp_path, capsys):
        """Unknown generator name should warn but not crash."""
        cache_dir = tmp_path / ".cache"
        cache_dir.mkdir()
        (cache_dir / "network.csv").write_text(
            "Machine,MAC Address,IP,Interface\n"
            "desktop,aa:bb:cc:dd:ee:ff,10.1.10.1,\n"
        )

        config = tmp_path / "gdoc2netcfg.toml"
        config.write_text(textwrap.dedent(f"""\
            [site]
            name = "test"
            domain = "test.example.com"

            [sheets]
            network = "https://example.com/not-used"

            [cache]
            directory = "{cache_dir}"

            [ipv6]
            prefixes = []

            [vlans]

            [network_subdomains]

            [generators]
            enabled = []
        """))

        result = main(["-c", str(config), "generate", "--stdout", "nonexistent"])
        assert result == 0
        captured = capsys.readouterr()
        assert "unknown generator" in captured.err


class TestMultiFileOutput:
    def test_writes_multiple_files(self, tmp_path):
        output_dir = tmp_path / "nginx"
        gen_config = GeneratorConfig(name="nginx", output_dir=str(output_dir))
        args = argparse.Namespace(stdout=False)
        file_dict = {
            "sites-available/host1": "server { }",
            "snippets/acme.conf": "location /.well-known { }",
        }
        _write_multi_file_output("nginx", file_dict, gen_config, args)

        assert (output_dir / "sites-available" / "host1").exists()
        assert (output_dir / "snippets" / "acme.conf").exists()
        assert (output_dir / "sites-available" / "host1").read_text() == "server { }"

    def test_stdout_mode(self, capsys):
        gen_config = GeneratorConfig(name="nginx", output_dir="nginx")
        args = argparse.Namespace(stdout=True)
        file_dict = {
            "file1": "content1",
            "file2": "content2",
        }
        _write_multi_file_output("nginx", file_dict, gen_config, args)

        captured = capsys.readouterr()
        assert "# === nginx: file1 ===" in captured.out
        assert "content1" in captured.out
        assert "# === nginx: file2 ===" in captured.out

    def test_default_output_dir_is_name(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        gen_config = GeneratorConfig(name="nginx", output_dir="")
        args = argparse.Namespace(stdout=False)
        _write_multi_file_output("nginx", {"f.txt": "x"}, gen_config, args)
        assert (tmp_path / "nginx" / "f.txt").exists()

    def test_path_traversal_blocked(self, tmp_path, capsys):
        output_dir = tmp_path / "nginx"
        gen_config = GeneratorConfig(name="nginx", output_dir=str(output_dir))
        args = argparse.Namespace(stdout=False)
        file_dict = {
            "../../etc/passwd": "malicious content",
            "sites-available/legit": "good content",
        }
        _write_multi_file_output("nginx", file_dict, gen_config, args)

        # Legitimate file should be written
        assert (output_dir / "sites-available" / "legit").exists()
        # Traversal path should NOT be written
        assert not (tmp_path / "etc" / "passwd").exists()
        captured = capsys.readouterr()
        assert "path traversal" in captured.err


class TestDnsmasqExternalGenerator:
    def test_generate_dnsmasq_external_with_no_public_ip(self, tmp_path, capsys):
        """External generator with no public IP produces no-op output."""
        cache_dir = tmp_path / ".cache"
        cache_dir.mkdir()
        (cache_dir / "network.csv").write_text(
            "Machine,MAC Address,IP,Interface\n"
            "desktop,aa:bb:cc:dd:ee:ff,10.1.10.1,\n"
        )

        config = tmp_path / "gdoc2netcfg.toml"
        config.write_text(textwrap.dedent(f"""\
            [site]
            name = "test"
            domain = "test.example.com"

            [sheets]
            network = "https://example.com/not-used"

            [cache]
            directory = "{cache_dir}"

            [ipv6]
            prefixes = []

            [vlans]
            10 = {{ name = "int", subdomain = "int" }}

            [network_subdomains]
            10 = "int"

            [generators]
            enabled = ["dnsmasq_external"]

            [generators.dnsmasq_external]
            output = ""
        """))

        result = main(["-c", str(config), "generate", "--stdout", "dnsmasq_external"])
        assert result == 0
        captured = capsys.readouterr()
        assert "No public_ipv4 configured" in captured.out
