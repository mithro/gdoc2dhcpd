"""VLAN Allocations CSV parser.

Parses the "VLAN Allocations" sheet into VLANDefinition records.
No derivation — the raw definitions are transformed into VLAN objects
by the vlan builder in derivations/vlan.py.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass


@dataclass
class VLANDefinition:
    """A raw VLAN definition from the VLAN Allocations sheet.

    Attributes:
        id: VLAN numeric identifier (e.g. 10)
        name: Short name (e.g. 'int', 'net')
        ip_range: IP range pattern (e.g. '10.1.10.X' or '10.31.X.X')
        netmask: Subnet mask (e.g. '255.255.255.0')
        cidr: CIDR suffix (e.g. '/24', '/21')
        color: Optional colour label from spreadsheet
        description: Human-readable purpose description
    """

    id: int
    name: str
    ip_range: str
    netmask: str
    cidr: str
    color: str = ""
    description: str = ""


def parse_vlan_allocations(csv_text: str) -> list[VLANDefinition]:
    """Parse VLAN Allocations CSV text into VLANDefinition records.

    Expected columns: VLAN, Name, IP Range, Netmask, CIDR, (unnamed), Color, For
    Rows with empty VLAN or Name fields are skipped.
    """
    lines = csv_text.splitlines()
    reader = csv.reader(lines)
    rows = list(reader)

    if not rows:
        return []

    # Find header row by looking for 'VLAN' and 'Name' columns
    header_idx = 0
    for i, row in enumerate(rows[:5]):
        row_lower = [c.strip().lower() for c in row]
        if "vlan" in row_lower and "name" in row_lower:
            header_idx = i
            break

    headers = [h.strip().lower() for h in rows[header_idx]]

    # Map column positions
    def _find_col(name: str) -> int | None:
        for i, h in enumerate(headers):
            if h == name:
                return i
        return None

    vlan_col = _find_col("vlan")
    name_col = _find_col("name")
    ip_range_col = _find_col("ip range")
    netmask_col = _find_col("netmask")
    cidr_col = _find_col("cidr")
    color_col = _find_col("color")
    for_col = _find_col("for")

    if vlan_col is None or name_col is None:
        return []

    definitions: list[VLANDefinition] = []

    for row in rows[header_idx + 1:]:
        if len(row) <= max(vlan_col, name_col):
            continue

        vlan_str = row[vlan_col].strip()
        name = row[name_col].strip()

        if not vlan_str or not name:
            continue

        try:
            vlan_id = int(vlan_str)
        except ValueError:
            continue

        ip_range = row[ip_range_col].strip() if ip_range_col is not None and ip_range_col < len(row) else ""
        netmask = row[netmask_col].strip() if netmask_col is not None and netmask_col < len(row) else ""
        cidr = row[cidr_col].strip() if cidr_col is not None and cidr_col < len(row) else ""
        color = row[color_col].strip() if color_col is not None and color_col < len(row) else ""
        description = row[for_col].strip() if for_col is not None and for_col < len(row) else ""

        definitions.append(VLANDefinition(
            id=vlan_id,
            name=name,
            ip_range=ip_range,
            netmask=netmask,
            cidr=cidr,
            color=color,
            description=description,
        ))

    return definitions
