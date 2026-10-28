"""Smoke tests for technology-neutral contracts."""

from src.sdn_defense.contracts import DecisionRecord


def test_decision_record_captures_reversibility_metadata() -> None:
    """A decision record retains its action and optional expiry."""

    record = DecisionRecord(
        event_id="event-001",
        risk_level="low",
        action="observe",
        expires_at=None,
        evidence={"score": 0.1},
    )

    assert record.action == "observe"
    assert record.expires_at is None
