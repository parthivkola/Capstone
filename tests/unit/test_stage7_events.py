"""Stage 7 gateway event formatting does not require a Ryu runtime."""

import pytest

from networking.ryu.stage7_events import datapath_state_event


def test_early_disconnect_preserves_unknown_datapath_identity() -> None:
    assert datapath_state_event("disconnected", None) == {
        "datapath_id": None,
        "discovery_state": "not_discovered",
    }


def test_known_datapath_disconnect_is_distinguished() -> None:
    assert datapath_state_event("disconnected", 1) == {
        "datapath_id": "0000000000000001",
        "discovery_state": "known_datapath_disconnected",
    }


def test_unknown_datapath_event_name_is_rejected() -> None:
    with pytest.raises(ValueError, match="event must be"):
        datapath_state_event("lost", 1)
