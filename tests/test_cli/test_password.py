"""Tests for the password CLI command."""

import textwrap

import pytest

from gdoc2netcfg.cli.main import main


@pytest.fixture
def password_config(tmp_path):
    """Create a config with cached CSV data including credential columns."""
    cache_dir = tmp_path / ".cache"
    cache_dir.mkdir()

    # CSV with credential extra columns
    (cache_dir / "network.csv").write_text(
        "Machine,MAC Address,IP,Interface,Password,SNMP Community,"
        "IPMI Username,IPMI Password\n"
        "switch1,aa:bb:cc:dd:ee:01,10.1.30.1,,sw1pass,public,,\n"
        "desktop,aa:bb:cc:dd:ee:02,10.1.10.2,,,,admin,hunter2\n"
        "server1,aa:bb:cc:dd:ee:03,10.1.10.5,,srv1pass,community1,,\n"
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
        prefixes = ["2001:db8:1:"]

        [vlans]
        10 = {{ name = "int", subdomain = "int" }}
        30 = {{ name = "net", subdomain = "net" }}

        [network_subdomains]
        10 = "int"
        30 = "net"

        [generators]
        enabled = []
    """))
    return config


class TestPasswordByHostname:
    def test_lookup_by_machine_name(self, password_config, capsys):
        result = main(["-c", str(password_config), "password", "switch1"])
        assert result == 0
        captured = capsys.readouterr()
        assert "sw1pass" in captured.out
        assert "switch1" in captured.out

    def test_lookup_by_substring(self, password_config, capsys):
        """Substring match finds server1 via 'server'."""
        result = main([
            "-c", str(password_config), "password", "server1",
        ])
        assert result == 0
        captured = capsys.readouterr()
        assert "srv1pass" in captured.out


class TestPasswordByIP:
    def test_lookup_by_ip(self, password_config, capsys):
        result = main([
            "-c", str(password_config), "password", "10.1.30.1",
        ])
        assert result == 0
        captured = capsys.readouterr()
        assert "sw1pass" in captured.out


class TestPasswordByMAC:
    def test_lookup_by_mac(self, password_config, capsys):
        result = main([
            "-c", str(password_config), "password", "aa:bb:cc:dd:ee:01",
        ])
        assert result == 0
        captured = capsys.readouterr()
        assert "sw1pass" in captured.out


class TestPasswordQuietMode:
    def test_quiet_outputs_value_only(self, password_config, capsys):
        result = main([
            "-c", str(password_config), "password", "--quiet", "switch1",
        ])
        assert result == 0
        captured = capsys.readouterr()
        # Quiet mode: only the password value, no headers
        assert captured.out.strip() == "sw1pass"
        assert "Host:" not in captured.out

    def test_quiet_ipmi_outputs_both_values(self, password_config, capsys):
        result = main([
            "-c", str(password_config), "password",
            "--quiet", "--type", "ipmi", "desktop",
        ])
        assert result == 0
        captured = capsys.readouterr()
        lines = captured.out.strip().split("\n")
        assert "admin" in lines
        assert "hunter2" in lines


class TestPasswordTypes:
    def test_snmp_type(self, password_config, capsys):
        result = main([
            "-c", str(password_config), "password",
            "--type", "snmp", "switch1",
        ])
        assert result == 0
        captured = capsys.readouterr()
        assert "public" in captured.out
        assert "SNMP Community" in captured.out

    def test_ipmi_type(self, password_config, capsys):
        result = main([
            "-c", str(password_config), "password",
            "--type", "ipmi", "desktop",
        ])
        assert result == 0
        captured = capsys.readouterr()
        assert "admin" in captured.out
        assert "hunter2" in captured.out
        assert "IPMI Username" in captured.out
        assert "IPMI Password" in captured.out

    def test_field_flag(self, password_config, capsys):
        result = main([
            "-c", str(password_config), "password",
            "--field", "SNMP Community", "server1",
        ])
        assert result == 0
        captured = capsys.readouterr()
        assert "community1" in captured.out


class TestPasswordNoMatch:
    def test_no_match_returns_1(self, password_config, capsys):
        result = main([
            "-c", str(password_config), "password", "nonexistent",
        ])
        assert result == 1
        captured = capsys.readouterr()
        assert "no device found" in captured.err

    def test_no_match_shows_suggestions(self, password_config, capsys):
        result = main([
            "-c", str(password_config), "password", "swtich1",
        ])
        assert result == 1
        captured = capsys.readouterr()
        assert "Did you mean?" in captured.err


class TestPasswordMissingCredential:
    def test_host_found_but_no_password(self, password_config, capsys):
        # desktop has IPMI creds but no Password
        result = main([
            "-c", str(password_config), "password", "desktop",
        ])
        assert result == 1
        captured = capsys.readouterr()
        assert "no 'password' credential found" in captured.err
        assert "Available fields:" in captured.err

    def test_host_found_but_no_snmp(self, password_config, capsys):
        # desktop has no SNMP Community
        result = main([
            "-c", str(password_config), "password",
            "--type", "snmp", "desktop",
        ])
        assert result == 1
        captured = capsys.readouterr()
        assert "no 'snmp' credential found" in captured.err


class TestPasswordMutuallyExclusive:
    def test_type_and_field_exclusive(self, password_config):
        """--type and --field are mutually exclusive (argparse enforces)."""
        with pytest.raises(SystemExit):
            main([
                "-c", str(password_config), "password",
                "--type", "snmp", "--field", "Password", "switch1",
            ])
