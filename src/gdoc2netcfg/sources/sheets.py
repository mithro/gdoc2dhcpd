"""Source: fetch CSV data from Google Sheets published URLs."""

from __future__ import annotations

import urllib.request
from dataclasses import dataclass


@dataclass
class SheetData:
    """Raw CSV data fetched from a Google Sheets published URL."""

    name: str
    csv_text: str


def fetch_sheet(name: str, url: str) -> SheetData:
    """Fetch CSV data from a Google Sheets published URL.

    Args:
        name: Human-readable sheet name (e.g. 'Network', 'IoT')
        url: Published CSV URL from Google Sheets

    Returns:
        SheetData with the raw CSV text content.

    Raises:
        urllib.error.URLError: If the network request fails.
    """
    response = urllib.request.urlopen(url)
    csv_text = response.read().decode("utf-8")
    return SheetData(name=name, csv_text=csv_text)


def fetch_all_sheets(
    sheets: list[tuple[str, str]],
) -> list[SheetData]:
    """Fetch CSV data from all configured sheets.

    Args:
        sheets: List of (name, url) pairs.

    Returns:
        List of SheetData, one per sheet. Sheets that fail to fetch are
        skipped with a warning printed to stderr.
    """
    results = []
    for name, url in sheets:
        try:
            data = fetch_sheet(name, url)
            results.append(data)
        except Exception as e:
            import sys

            print(f"Warning: failed to fetch sheet {name!r}: {e}", file=sys.stderr)
    return results
