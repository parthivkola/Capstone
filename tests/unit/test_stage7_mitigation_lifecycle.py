"""Tests for the bounded Stage 7 mitigation lifecycle state machine."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from services.mitigation.lifecycle import (
    ExtensionEvidence,
    InvalidLifecycleTransition,
    MitigationLifecycle,
)
from src.sdn_defense.contracts import (
    ActionType,
    MitigationAction,
    MitigationScope,
    RollbackState,
    ScopeKind,
)

START = datetime(2026, 10, 8, 12, 0, tzinfo=UTC)
SCOPE = MitigationScope.from_mapping(
    ScopeKind.FLOW,
    {
        "datapath_id": "1",
        "src_ip": "10.0.0.2",
        "dst_ip": "10.0.0.3",
        "ip_protocol": 6,
        "src_port": 40000,
        "dst_port": 18080,
    },
)


def _action() -> MitigationAction:
    return MitigationAction(
        action_id="a-1",
        action=ActionType.BLOCK,
        scope=SCOPE,
        created_at=START,
        expires_at=START + timedelta(seconds=10),
        ttl_seconds=10,
        reason="unit-test controlled decision",
        evidence_refs=("e-1",),
        policy_version="stage7-v1",
        decision_id="d-1",
    )


def _extension(
    at: datetime, *, scope: MitigationScope = SCOPE, **overrides: bool
) -> ExtensionEvidence:
    fields = {
        "still_attack_at_tier": True,
        "independently_corroborated": True,
        "protected": False,
        "adapter_confirms_active": True,
    }
    fields.update(overrides)
    return ExtensionEvidence(at, scope, **fields)


def test_activation_and_ttl_expiry_produce_exact_rollback_request() -> None:
    lifecycle = MitigationLifecycle(_action())

    activated = lifecycle.activate(START)
    assert activated.rollback_state is RollbackState.ACTIVE
    assert lifecycle.expire(START + timedelta(seconds=9)) is None

    request = lifecycle.expire(START + timedelta(seconds=10))
    assert request is not None
    assert request.action_id == "a-1"
    assert request.request_id == "rollback:a-1:expiry"
    assert lifecycle.state is RollbackState.EXPIRED


def test_one_valid_conditional_extension_doubles_original_bounded_ttl() -> None:
    lifecycle = MitigationLifecycle(_action())
    lifecycle.activate(START)
    extended = lifecycle.extend(
        _extension(START + timedelta(seconds=5)),
        now=START + timedelta(seconds=5),
    )

    assert extended.rollback_state is RollbackState.EXTENDED
    assert extended.extension_count == 1
    assert extended.expires_at == START + timedelta(seconds=20)
    assert extended.ttl_seconds == 10

    with pytest.raises(InvalidLifecycleTransition, match="expected ACTIVE"):
        lifecycle.extend(
            _extension(START + timedelta(seconds=6)),
            now=START + timedelta(seconds=6),
        )


@pytest.mark.parametrize(
    "evidence,at,match",
    [
        (
            _extension(START + timedelta(seconds=5), still_attack_at_tier=False),
            START + timedelta(seconds=5),
            "predicates",
        ),
        (
            _extension(START + timedelta(seconds=5), independently_corroborated=False),
            START + timedelta(seconds=5),
            "predicates",
        ),
        (
            _extension(START + timedelta(seconds=5), protected=True),
            START + timedelta(seconds=5),
            "predicates",
        ),
        (
            _extension(START + timedelta(seconds=5), adapter_confirms_active=False),
            START + timedelta(seconds=5),
            "predicates",
        ),
        (
            _extension(START - timedelta(seconds=6)),
            START + timedelta(seconds=5),
            "stale",
        ),
        (
            _extension(
                START + timedelta(seconds=5),
                scope=MitigationScope.from_mapping(
                    ScopeKind.FLOW,
                    {
                        "datapath_id": "1",
                        "src_ip": "10.0.0.4",
                        "dst_ip": "10.0.0.3",
                        "ip_protocol": 6,
                        "src_port": 40000,
                        "dst_port": 18080,
                    },
                ),
            ),
            START + timedelta(seconds=5),
            "scope changed",
        ),
    ],
)
def test_invalid_or_stale_extension_is_rejected(
    evidence: ExtensionEvidence, at: datetime, match: str
) -> None:
    lifecycle = MitigationLifecycle(_action())
    lifecycle.activate(START)

    with pytest.raises(InvalidLifecycleTransition, match=match):
        lifecycle.extend(evidence, now=at)
    assert lifecycle.state is RollbackState.ACTIVE


def test_extension_before_midpoint_and_after_expiry_is_rejected() -> None:
    lifecycle = MitigationLifecycle(_action())
    lifecycle.activate(START)

    with pytest.raises(InvalidLifecycleTransition, match="midpoint"):
        lifecycle.extend(_extension(START + timedelta(seconds=4)), now=START + timedelta(seconds=4))
    with pytest.raises(InvalidLifecycleTransition, match="midpoint"):
        lifecycle.extend(
            _extension(START + timedelta(seconds=10)), now=START + timedelta(seconds=10)
        )


def test_rollback_is_terminal_and_invalid_transitions_are_rejected() -> None:
    lifecycle = MitigationLifecycle(_action())
    lifecycle.activate(START)
    request = lifecycle.rollback(START + timedelta(seconds=2), reason="evidence changed")

    assert request.action_id == "a-1"
    assert lifecycle.state is RollbackState.ROLLED_BACK
    with pytest.raises(InvalidLifecycleTransition, match="ROLLED_BACK"):
        lifecycle.expire(START + timedelta(seconds=20))
    with pytest.raises(InvalidLifecycleTransition, match="expected PROPOSED"):
        lifecycle.activate(START)


def test_expiry_before_activation_and_naive_time_are_rejected() -> None:
    lifecycle = MitigationLifecycle(_action())

    with pytest.raises(InvalidLifecycleTransition, match="cannot expire"):
        lifecycle.expire(START + timedelta(seconds=10))
    with pytest.raises(ValueError, match="timezone-aware"):
        lifecycle.activate(datetime(2026, 10, 8, 12, 0))
