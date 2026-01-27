"""Generator protocol: the interface all generators implement."""

from __future__ import annotations

from typing import Protocol

from gdoc2netcfg.models.host import NetworkInventory


class Generator(Protocol):
    """Protocol for config file generators.

    Each generator takes a NetworkInventory and produces output text.
    The generator should contain zero data derivation logic — all
    data it needs is already in the model.
    """

    def generate(self, inventory: NetworkInventory) -> str:
        """Generate output configuration text from the enriched model."""
        ...
