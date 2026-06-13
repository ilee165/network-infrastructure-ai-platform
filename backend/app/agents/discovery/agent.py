"""Discovery Agent — thin typed-tool wrapper over the M1 discovery engine (M3-12).

CLAUDE.md Core Agent #3: wraps discovery runs, device inventory inspection,
and neighbor queries through classified NetOpsTool instances.  All tools
are READ_ONLY; no device state is ever modified by this agent.

Module boundary: this agent imports *only* ``agents.framework``, ``core``,
and its own ``tools`` submodule.  The tools module is the sole crossing
point into ``engines.discovery`` and ``models`` — the import-linter
contract (REPO-STRUCTURE §3.2 row 11) enforces that agents never reach
engines/services directly.
"""

from __future__ import annotations

from collections.abc import Sequence

from app.agents.discovery.tools import DISCOVERY_TOOLS
from app.agents.framework.base import BaseSpecialistAgent
from app.agents.framework.tools import NetOpsTool


class DiscoveryAgent(BaseSpecialistAgent):
    """Discovery specialist (CLAUDE.md Core Agent #3, MVP.md §5).

    Wraps the M1 discovery engine through four READ_ONLY typed tools:

    - ``trigger_discovery_run`` — enqueue a new discovery job (read-only
      job-launch; changes no device state).
    - ``list_devices`` — page through the managed device inventory.
    - ``get_device`` — retrieve full details for one device by UUID.
    - ``query_neighbors`` — list LLDP/CDP neighbors for a device.

    All tools surface plain-data JSON; the agent never imports engine or
    model modules directly — that boundary is enforced by import-linter.
    """

    # ------------------------------------------------------------------
    # BaseSpecialistAgent contract
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "discovery"

    @property
    def description(self) -> str:
        return (
            "Handles discovery, inventory inspection, and neighbor queries. "
            "Route here when the user wants to trigger a network discovery run, "
            "list or inspect managed devices, or query LLDP/CDP neighbor relationships. "
            "All operations are read-only — no device configuration is modified."
        )

    @property
    def system_prompt(self) -> str:
        return (
            "You are the Discovery Agent for an AI Network Operations Platform.\n\n"
            "Your purpose is to help users understand the current network inventory "
            "and to launch discovery runs that find new devices.\n\n"
            "Capabilities:\n"
            "- Trigger a discovery run from one or more seed IP addresses\n"
            "  (the run executes asynchronously; return the run_id to the user).\n"
            "- List all managed devices, filtered by status or vendor if requested.\n"
            "- Retrieve full details for a specific device by its UUID.\n"
            "- Query the LLDP/CDP neighbors of a device.\n\n"
            "Guidelines:\n"
            "- Always prefer querying existing inventory before launching a new run.\n"
            "- If the user's request is ambiguous (e.g. 'find all devices' with no "
            "  scope), ask the Consultant Agent to clarify before starting a run.\n"
            "- Never modify device configuration — you are read-only.\n"
            "- Return IDs and hostnames so the user can reference specific devices.\n"
        )

    @property
    def tools(self) -> Sequence[NetOpsTool]:
        """The four READ_ONLY discovery tools."""
        return DISCOVERY_TOOLS
