"""Terminal color utilities.

Provides ANSI color support with automatic TTY detection and NO_COLOR
support. Designed as shared infrastructure for all CLI output.
"""

from __future__ import annotations

import os
import sys
from typing import TextIO


def use_color(stream: TextIO = sys.stderr) -> bool:
    """True if the given stream is an interactive terminal and NO_COLOR is not set."""
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def colorize(text: str, code: str, enabled: bool) -> str:
    """Wrap text in ANSI color escape if enabled."""
    if not enabled:
        return text
    return f"\033[{code}m{text}\033[0m"
