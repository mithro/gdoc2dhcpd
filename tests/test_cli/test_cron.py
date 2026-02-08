"""Tests for cron job management (cli/cron.py)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# CronEntry data model
# ---------------------------------------------------------------------------

class TestCronEntry:
    """Tests for the CronEntry dataclass."""

    def test_cron_entry_fields(self):
        """CronEntry should store schedule, command, lock_name, and comment."""
        from gdoc2netcfg.cli.cron import CronEntry

        entry = CronEntry(
            schedule="*/15 * * * *",
            command="gdoc2netcfg fetch",
            lock_name="fetch",
            comment="Fetch CSVs from Google Sheets",
        )
        assert entry.schedule == "*/15 * * * *"
        assert entry.command == "gdoc2netcfg fetch"
        assert entry.lock_name == "fetch"
        assert entry.comment == "Fetch CSVs from Google Sheets"

    def test_cron_entry_is_frozen(self):
        """CronEntry should be immutable (frozen dataclass)."""
        from gdoc2netcfg.cli.cron import CronEntry

        entry = CronEntry(
            schedule="*/15 * * * *",
            command="gdoc2netcfg fetch",
            lock_name="fetch",
            comment="Fetch CSVs",
        )
        with pytest.raises(AttributeError):
            entry.schedule = "0 * * * *"


# ---------------------------------------------------------------------------
# Path detection: detect_uv_path
# ---------------------------------------------------------------------------

class TestDetectUvPath:
    """Tests for detect_uv_path()."""

    def test_finds_uv_via_which(self):
        """Should find uv via shutil.which() first."""
        from gdoc2netcfg.cli.cron import detect_uv_path

        with patch("shutil.which", return_value="/usr/bin/uv"):
            result = detect_uv_path()
        assert result == Path("/usr/bin/uv")

    def test_falls_back_to_local_bin(self, tmp_path):
        """When which() fails, should check ~/.local/bin/uv."""
        from gdoc2netcfg.cli.cron import detect_uv_path

        fake_uv = tmp_path / ".local" / "bin" / "uv"
        fake_uv.parent.mkdir(parents=True)
        fake_uv.touch()

        with (
            patch("shutil.which", return_value=None),
            patch("pathlib.Path.home", return_value=tmp_path),
        ):
            result = detect_uv_path()
        assert result == fake_uv

    def test_falls_back_to_usr_local_bin(self, tmp_path):
        """When which() and ~/.local/bin fail, should check /usr/local/bin/uv."""
        from gdoc2netcfg.cli.cron import detect_uv_path

        original_exists = Path.exists

        def fake_exists(path):
            if str(path) == "/usr/local/bin/uv":
                return True
            return original_exists(path)

        with (
            patch("shutil.which", return_value=None),
            patch("pathlib.Path.home", return_value=tmp_path),
            patch.object(Path, "exists", fake_exists),
        ):
            result = detect_uv_path()
        assert result == Path("/usr/local/bin/uv")

    def test_raises_when_not_found(self, tmp_path):
        """Should raise FileNotFoundError with install instructions when uv not found."""
        from gdoc2netcfg.cli.cron import detect_uv_path

        with (
            patch("shutil.which", return_value=None),
            patch("pathlib.Path.home", return_value=tmp_path),
        ):
            with pytest.raises(FileNotFoundError, match="uv"):
                detect_uv_path()


# ---------------------------------------------------------------------------
# Path detection: detect_project_root
# ---------------------------------------------------------------------------

class TestDetectProjectRoot:
    """Tests for detect_project_root()."""

    def test_finds_in_cwd(self, tmp_path):
        """Should find project root when gdoc2netcfg.toml is in cwd."""
        from gdoc2netcfg.cli.cron import detect_project_root

        (tmp_path / "gdoc2netcfg.toml").touch()

        result = detect_project_root(tmp_path)
        assert result == tmp_path

    def test_finds_in_parent(self, tmp_path):
        """Should walk up and find project root in a parent directory."""
        from gdoc2netcfg.cli.cron import detect_project_root

        (tmp_path / "gdoc2netcfg.toml").touch()
        subdir = tmp_path / "src" / "gdoc2netcfg"
        subdir.mkdir(parents=True)

        result = detect_project_root(subdir)
        assert result == tmp_path

    def test_raises_when_not_found(self, tmp_path):
        """Should raise FileNotFoundError when no gdoc2netcfg.toml found."""
        from gdoc2netcfg.cli.cron import detect_project_root

        with pytest.raises(FileNotFoundError, match="gdoc2netcfg.toml"):
            detect_project_root(tmp_path)


# ---------------------------------------------------------------------------
# Cron entry generation
# ---------------------------------------------------------------------------

class TestGenerateCronEntries:
    """Tests for generate_cron_entries()."""

    def test_returns_correct_count(self):
        """Should return 8 CronEntry objects (per the agreed schedule)."""
        from gdoc2netcfg.cli.cron import generate_cron_entries

        entries = generate_cron_entries()
        assert len(entries) == 8

    def test_fetch_schedule(self):
        """Fetch should run every 15 minutes."""
        from gdoc2netcfg.cli.cron import generate_cron_entries

        entries = generate_cron_entries()
        fetch = [e for e in entries if e.lock_name == "fetch"]
        assert len(fetch) == 1
        assert fetch[0].schedule == "*/15 * * * *"

    def test_generate_schedule(self):
        """Generate should run every 15 minutes."""
        from gdoc2netcfg.cli.cron import generate_cron_entries

        entries = generate_cron_entries()
        gen = [e for e in entries if e.lock_name == "generate"]
        assert len(gen) == 1
        assert gen[0].schedule == "*/15 * * * *"

    def test_reachability_schedule(self):
        """Reachability should run every 30 minutes."""
        from gdoc2netcfg.cli.cron import generate_cron_entries

        entries = generate_cron_entries()
        reach = [e for e in entries if e.lock_name == "reachability"]
        assert len(reach) == 1
        assert reach[0].schedule == "*/30 * * * *"

    def test_sshfp_schedule(self):
        """SSHFP should run daily at 02:00."""
        from gdoc2netcfg.cli.cron import generate_cron_entries

        entries = generate_cron_entries()
        sshfp = [e for e in entries if e.lock_name == "sshfp"]
        assert len(sshfp) == 1
        assert sshfp[0].schedule == "0 2 * * *"

    def test_ssl_certs_schedule(self):
        """SSL certs should run daily at 02:05."""
        from gdoc2netcfg.cli.cron import generate_cron_entries

        entries = generate_cron_entries()
        ssl = [e for e in entries if e.lock_name == "ssl-certs"]
        assert len(ssl) == 1
        assert ssl[0].schedule == "5 2 * * *"

    def test_snmp_schedule(self):
        """SNMP should run daily at 03:00."""
        from gdoc2netcfg.cli.cron import generate_cron_entries

        entries = generate_cron_entries()
        snmp = [e for e in entries if e.lock_name == "snmp"]
        assert len(snmp) == 1
        assert snmp[0].schedule == "0 3 * * *"

    def test_bridge_schedule(self):
        """Bridge should run daily at 03:05."""
        from gdoc2netcfg.cli.cron import generate_cron_entries

        entries = generate_cron_entries()
        bridge = [e for e in entries if e.lock_name == "bridge"]
        assert len(bridge) == 1
        assert bridge[0].schedule == "5 3 * * *"

    def test_bmc_firmware_schedule(self):
        """BMC firmware should run weekly on Sunday at 04:00."""
        from gdoc2netcfg.cli.cron import generate_cron_entries

        entries = generate_cron_entries()
        bmc = [e for e in entries if e.lock_name == "bmc-firmware"]
        assert len(bmc) == 1
        assert bmc[0].schedule == "0 4 * * 0"

    def test_all_lock_names_unique(self):
        """All lock names should be unique."""
        from gdoc2netcfg.cli.cron import generate_cron_entries

        entries = generate_cron_entries()
        lock_names = [e.lock_name for e in entries]
        assert len(lock_names) == len(set(lock_names))
