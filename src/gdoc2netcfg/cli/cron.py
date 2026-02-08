"""Cron job management for gdoc2netcfg.

Provides commands to install, show, and uninstall scheduled cron jobs
that keep cached data and generated config files up to date.
"""

from __future__ import annotations

import shutil
import subprocess
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


_BEGIN_MARKER = "# BEGIN gdoc2netcfg managed entries - DO NOT EDIT THIS BLOCK"
_END_MARKER = "# END gdoc2netcfg managed entries"


def _validate_no_whitespace(path: Path, label: str) -> None:
    """Raise ValueError if path contains whitespace (unsafe for unquoted cron lines)."""
    path_str = str(path)
    if any(c.isspace() for c in path_str):
        raise ValueError(
            f"{label} path contains whitespace, which is unsafe in crontab lines: {path_str}"
        )


def format_cron_line(entry: CronEntry, uv_path: Path, project_root: Path) -> str:
    """Format a single CronEntry as a crontab line.

    Uses flock for locking, uv --directory for working directory,
    and appends output to .cache/cron.log.

    Raises ValueError if either path contains whitespace (would break
    unquoted shell expansion in crontab).
    """
    _validate_no_whitespace(uv_path, "uv")
    _validate_no_whitespace(project_root, "Project root")
    lock_file = project_root / ".cache" / f"cron-{entry.lock_name}.lock"
    log_file = project_root / ".cache" / "cron.log"
    return (
        f"{entry.schedule} "
        f"flock -n {lock_file} "
        f"{uv_path} --directory {project_root} run {entry.command} "
        f">>{log_file} 2>&1"
    )


def format_crontab_block(
    entries: list[CronEntry],
    uv_path: Path,
    project_root: Path,
) -> str:
    """Format all entries as a managed crontab block with BEGIN/END markers."""
    lines = [
        _BEGIN_MARKER,
        f"# Project: {project_root}",
        "",
    ]

    for entry in entries:
        lines.append(f"# {entry.comment}")
        lines.append(format_cron_line(entry, uv_path, project_root))

    lines.append("")
    lines.append(_END_MARKER)
    lines.append("")  # trailing newline

    return "\n".join(lines)


def read_current_crontab() -> str:
    """Read the current user's crontab.

    Returns empty string if the user has no crontab.
    Re-raises CalledProcessError for unexpected failures (e.g. permission denied).
    """
    try:
        result = subprocess.run(
            ["crontab", "-l"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        # "no crontab for <user>" is the expected error when user has no crontab
        if "no crontab for" in (e.stderr or ""):
            return ""
        raise


def write_crontab(content: str) -> None:
    """Write content as the user's crontab by piping to 'crontab -'."""
    subprocess.run(
        ["crontab", "-"],
        input=content,
        text=True,
        check=True,
    )


def remove_managed_block(crontab: str) -> str:
    """Remove the gdoc2netcfg managed block from a crontab string.

    Returns the crontab with the block (between BEGIN/END markers) removed.
    Preserves all other content.

    Raises ValueError if a BEGIN marker exists without a matching END marker,
    to prevent silent data loss from a corrupted crontab.
    """
    lines = crontab.splitlines(keepends=True)
    result: list[str] = []
    inside_block = False

    for line in lines:
        stripped = line.rstrip("\n")
        if stripped == _BEGIN_MARKER:
            inside_block = True
            continue
        if stripped == _END_MARKER:
            inside_block = False
            continue
        if not inside_block:
            result.append(line)

    if inside_block:
        raise ValueError(
            "Corrupted crontab: found BEGIN marker without matching END marker. "
            "Please fix your crontab manually (crontab -e)."
        )

    # Clean up trailing blank lines
    text = "".join(result)
    if text:
        text = text.rstrip("\n") + "\n"
    return text


def add_managed_block(crontab: str, block: str) -> str:
    """Add a managed block to a crontab, replacing any existing one.

    Removes the old block first (if present), then appends the new one.
    """
    cleaned = remove_managed_block(crontab)
    if cleaned and not cleaned.endswith("\n"):
        cleaned += "\n"
    return cleaned + block
