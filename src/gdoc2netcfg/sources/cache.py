"""Cache manager for downloaded CSV data and supplement results."""

from __future__ import annotations

from pathlib import Path


class CSVCache:
    """Manages a local directory cache for downloaded CSV data.

    Stores CSV files as {name}.csv in the cache directory.
    """

    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = cache_dir

    def has(self, name: str) -> bool:
        """Check if a cached CSV exists for the given sheet name."""
        return self._path(name).exists()

    def read(self, name: str) -> str:
        """Read cached CSV content for the given sheet name.

        Raises:
            FileNotFoundError: If no cache entry exists.
        """
        return self._path(name).read_text(encoding="utf-8")

    def write(self, name: str, csv_text: str) -> None:
        """Write CSV content to the cache.

        Creates the cache directory if it doesn't exist.
        """
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._path(name).write_text(csv_text, encoding="utf-8")

    def _path(self, name: str) -> Path:
        """Return the cache file path for a sheet name."""
        # Sanitize name for filesystem safety
        safe_name = name.lower().replace(" ", "_")
        return self.cache_dir / f"{safe_name}.csv"
