"""Pure structured event helpers for the Stage 7 Ryu gateway."""

from __future__ import annotations


def datapath_state_event(event: str, datapath_id: int | None) -> dict[str, str | None]:
    """Format connection lifecycle without inventing an undiscovered DPID."""

    if event not in {"connected", "disconnected"}:
        raise ValueError("event must be connected or disconnected")
    state = (
        "not_discovered"
        if datapath_id is None
        else "known_datapath_connected"
        if event == "connected"
        else "known_datapath_disconnected"
    )
    return {
        "datapath_id": None if datapath_id is None else f"{datapath_id:016x}",
        "discovery_state": state,
    }
