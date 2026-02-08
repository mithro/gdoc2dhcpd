"""Cron job management for gdoc2netcfg.

Provides commands to install, show, and uninstall scheduled cron jobs
that keep cached data and generated config files up to date.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CronEntry:
    """A single cron job entry."""

    schedule: str       # e.g. "*/15 * * * *"
    command: str        # e.g. "gdoc2netcfg fetch"
    lock_name: str      # e.g. "fetch" (used for flock lock file name)
    comment: str        # e.g. "Fetch CSVs from Google Sheets"


def detect_uv_path() -> Path:
    """Find the uv binary.

    Checks shutil.which() first, then ~/.local/bin/uv, then /usr/local/bin/uv.
    Raises FileNotFoundError with install instructions if not found.
    """
    # Try PATH first
    which_result = shutil.which("uv")
    if which_result is not None:
        return Path(which_result)

    # Try ~/.local/bin/uv
    local_uv = Path.home() / ".local" / "bin" / "uv"
    if local_uv.exists():
        return local_uv

    # Try /usr/local/bin/uv
    system_uv = Path("/usr/local/bin/uv")
    if system_uv.exists():
        return system_uv

    raise FileNotFoundError(
        "uv not found. Install it with: curl -LsSf https://astral.sh/uv/install.sh | sh"
    )


def detect_project_root(start: Path | None = None) -> Path:
    """Find the project root by walking up from start looking for gdoc2netcfg.toml.

    Raises FileNotFoundError if not found.
    """
    current = (start or Path.cwd()).resolve()
    while True:
        if (current / "gdoc2netcfg.toml").exists():
            return current
        parent = current.parent
        if parent == current:
            break
        current = parent

    raise FileNotFoundError(
        "gdoc2netcfg.toml not found in current directory or any parent. "
        "Run this command from the gdoc2netcfg project directory."
    )


def generate_cron_entries() -> list[CronEntry]:
    """Generate the list of cron entries for the agreed schedule."""
    return [
        # Every 15 minutes: fetch + generate
        CronEntry(
            schedule="*/15 * * * *",
            command="gdoc2netcfg fetch",
            lock_name="fetch",
            comment="Fetch CSVs from Google Sheets",
        ),
        CronEntry(
            schedule="*/15 * * * *",
            command="gdoc2netcfg generate",
            lock_name="generate",
            comment="Generate config files from cached data",
        ),
        # Every 30 minutes: reachability
        CronEntry(
            schedule="*/30 * * * *",
            command="gdoc2netcfg reachability",
            lock_name="reachability",
            comment="Ping all hosts to refresh reachability cache",
        ),
        # Daily 02:00: sshfp
        CronEntry(
            schedule="0 2 * * *",
            command="gdoc2netcfg sshfp",
            lock_name="sshfp",
            comment="Scan SSH fingerprints",
        ),
        # Daily 02:05: ssl-certs
        CronEntry(
            schedule="5 2 * * *",
            command="gdoc2netcfg ssl-certs",
            lock_name="ssl-certs",
            comment="Scan SSL/TLS certificates",
        ),
        # Daily 03:00: snmp
        CronEntry(
            schedule="0 3 * * *",
            command="gdoc2netcfg snmp",
            lock_name="snmp",
            comment="Scan SNMP data",
        ),
        # Daily 03:05: bridge
        CronEntry(
            schedule="5 3 * * *",
            command="gdoc2netcfg bridge",
            lock_name="bridge",
            comment="Scan bridge/topology data",
        ),
        # Weekly Sunday 04:00: bmc-firmware
        CronEntry(
            schedule="0 4 * * 0",
            command="gdoc2netcfg bmc-firmware",
            lock_name="bmc-firmware",
            comment="Scan BMC firmware information",
        ),
    ]
