"""Generator protocol: the interface all generators implement."""

from __future__ import annotations

from typing import Protocol

from gdoc2netcfg.models.host import NetworkInventory


class Generator(Protocol):
    """Protocol for config file generators.

    Each generator takes a NetworkInventory and produces output.
    The generator should contain zero data derivation logic — all
    data it needs is already in the model.

    Return types:
      - str: single file content (written to GeneratorConfig.output)
      - dict[str, str]: multiple files ({relative_path: content},
        written under GeneratorConfig.output_dir)
    """

    def generate(self, inventory: NetworkInventory) -> str | dict[str, str]:
        """Generate output configuration from the enriched model."""
        ...
