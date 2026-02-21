"""Tasmota Home Assistant integration check.

Queries the Home Assistant REST API to verify that Tasmota devices
are properly registered and reporting state. Each Tasmota device
should appear as switch.tasmota_{topic} in HA.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gdoc2netcfg.config import HomeAssistantConfig
    from gdoc2netcfg.models.host import Host


def check_ha_status(
    hosts: list[Host],
    ha_config: HomeAssistantConfig,
    verbose: bool = False,
) -> dict[str, dict]:
    """Check Home Assistant for Tasmota device entities.

    For each host with tasmota_data, queries the HA REST API for the
    expected entity (switch.tasmota_{topic}). Reports existence, state,
    and last_changed.

    Args:
        hosts: Hosts with tasmota_data attached.
        ha_config: Home Assistant connection config.
        verbose: Print progress to stderr.

    Returns:
        Mapping of hostname to status dict with keys:
        exists, entity_id, state, last_changed.
    """
    results: dict[str, dict] = {}

    for host in sorted(hosts, key=lambda h: h.hostname):
        if host.tasmota_data is None:
            continue

        topic = host.tasmota_data.mqtt_topic
        if not topic:
            topic = host.machine_name

        # Tasmota auto-discovery creates entities with underscores
        entity_id = f"switch.tasmota_{topic.replace('-', '_')}"

        status = _query_ha_entity(ha_config, entity_id)
        results[host.hostname] = status

        if verbose:
            if status["exists"]:
                state = status.get("state", "?")
                changed = status.get("last_changed", "?")
                print(
                    f"  {host.hostname:30s}  {entity_id:40s}  "
                    f"state={state}  last_changed={changed}",
                    file=sys.stderr,
                )
            else:
                print(
                    f"  {host.hostname:30s}  {entity_id:40s}  NOT FOUND",
                    file=sys.stderr,
                )

    return results


def _query_ha_entity(
    ha_config: HomeAssistantConfig,
    entity_id: str,
) -> dict:
    """Query a single entity from the Home Assistant REST API.

    Args:
        ha_config: HA connection config.
        entity_id: Entity ID to look up (e.g. "switch.tasmota_au_plug_10").

    Returns:
        Dict with 'exists' bool, plus 'state', 'last_changed',
        'entity_id' if found.
    """
    url = f"{ha_config.url.rstrip('/')}/api/states/{entity_id}"
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {ha_config.token}",
            "Content-Type": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            data = json.loads(resp.read())
            return {
                "exists": True,
                "entity_id": entity_id,
                "state": data.get("state", "unknown"),
                "last_changed": data.get("last_changed", ""),
                "attributes": data.get("attributes", {}),
            }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"exists": False, "entity_id": entity_id}
        return {"exists": False, "entity_id": entity_id, "error": str(e)}
    except (urllib.error.URLError, OSError, json.JSONDecodeError, TimeoutError) as e:
        return {"exists": False, "entity_id": entity_id, "error": str(e)}
