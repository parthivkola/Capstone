"""Unit tests for deterministic Stage 7 policy decisions and audit records."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from services.mitigation.audit import (
    action_proposal_event,
    build_action_lifecycle_event,
    build_defense_audit_event,
)
from services.mitigation.policy import PolicyMode, ProtectedFlow, RiskPolicy, RiskPolicyConfig
from src.sdn_defense.contracts import (
    ActionType,
    AdapterCapabilities,
    Classification,
    ConfidenceThresholds,
    DetectionResult,
    EvidenceItem,
    MitigationScope,
    RiskDecision,
    RiskLevel,
    ScopeKind,
    ShiftState,
)

NOW = datetime(2026, 10, 8, 12, 0, tzinfo=UTC)
FLOW = MitigationScope.from_mapping(
    ScopeKind.FLOW,
    {
        "datapath_id": "0000000000000001",
        "src_ip": "10.0.0.2",
        "dst_ip": "10.0.0.3",
        "ip_protocol": 6,
        "src_port": 40000,
        "dst_port": 18080,
    },
)


def _policy() -> RiskPolicy:
    protocol = json.loads(Path("experiments/stage7/defense-protocol.json").read_text())
    thresholds = ConfidenceThresholds(0.2, 0.5, 0.8, "validation-manifest-sha256")
    return RiskPolicy(
        RiskPolicyConfig.from_protocol(
            protocol,
            thresholds,
            persistence_observations=2,
            observation_interval_seconds=2.0,
        )
    )


def _caps(*actions: ActionType) -> AdapterCapabilities:
    scopes = (ScopeKind.FLOW, ScopeKind.TUPLE, ScopeKind.HOST)
    return AdapterCapabilities(tuple((action, scopes) for action in actions))


def _result(
    *,
    classification: Classification = Classification.ATTACK,
    score: float | None = 0.3,
    evidence: tuple[EvidenceItem, ...] = (),
    persistence: int | None = None,
    scope: MitigationScope | None = FLOW,
    shift: ShiftState = ShiftState.NO_SIGNAL,
) -> DetectionResult:
    return DetectionResult(
        event_id="event-1",
        classification=classification,
        confidence=score,
        attack_score=score,
        observed_at=NOW,
        provenance="stage7-unit-test-fixture",
        model_id="rf-test" if score is not None else None,
        shift_state=shift,
        evidence=evidence,
        scope=scope,
        persistence_count=persistence,
    )


def _corroboration() -> tuple[EvidenceItem, ...]:
    return (EvidenceItem("evidence-1", "stage3_fixture", "probe_count", 3, NOW),)


def _decide(
    result: DetectionResult,
    *,
    mode: PolicyMode = PolicyMode.RISK_AWARE,
    caps: AdapterCapabilities | None = None,
    protected: tuple[ProtectedFlow, ...] = (),
) -> RiskDecision:
    return _policy().decide(
        result,
        now=NOW,
        mode=mode,
        capabilities=caps or _caps(ActionType.RATE_LIMIT, ActionType.QUARANTINE, ActionType.BLOCK),
        protected_flows=protected,
    )


def test_benign_low_medium_high_and_very_high_policy_actions() -> None:
    benign = _decide(_result(classification=Classification.BENIGN, score=0.01))
    low = _decide(_result(score=0.1))
    medium = _decide(_result(score=0.3))
    high = _decide(_result(score=0.6, evidence=_corroboration()))
    very_high = _decide(_result(score=0.9, evidence=_corroboration(), persistence=2))

    assert (benign.risk_level, benign.action) == (RiskLevel.LOW, ActionType.MONITOR)
    assert (low.risk_level, low.action) == (RiskLevel.LOW, ActionType.MONITOR)
    assert (medium.risk_level, medium.action) == (RiskLevel.MEDIUM, ActionType.RATE_LIMIT)
    assert (high.risk_level, high.action) == (RiskLevel.HIGH, ActionType.QUARANTINE)
    assert (very_high.risk_level, very_high.action) == (
        RiskLevel.VERY_HIGH,
        ActionType.BLOCK,
    )


def test_uncertain_unknown_and_psi_alone_fail_safe() -> None:
    unknown = _decide(
        _result(classification=Classification.UNKNOWN, score=None, shift=ShiftState.SIGNAL)
    )
    repeated_unknown = _decide(
        _result(
            classification=Classification.UNKNOWN,
            score=None,
            evidence=_corroboration(),
            persistence=2,
        )
    )
    shift_only = _decide(_result(score=None, shift=ShiftState.SIGNAL))

    assert unknown.action is ActionType.MONITOR
    assert unknown.risk_level is RiskLevel.UNCERTAIN
    assert repeated_unknown.action is ActionType.RATE_LIMIT
    assert repeated_unknown.risk_level is RiskLevel.UNCERTAIN
    assert shift_only.action is ActionType.MONITOR
    assert "distribution shift alone" in shift_only.reason


def test_missing_evidence_and_protected_scope_choose_safer_action() -> None:
    no_corroboration = _decide(_result(score=0.99, persistence=2))
    protected = _decide(
        _result(score=0.99, evidence=_corroboration(), persistence=2),
        protected=(ProtectedFlow(FLOW, "protected h1 to h3 service flow"),),
    )

    assert no_corroboration.action is ActionType.QUARANTINE
    assert no_corroboration.risk_level is RiskLevel.HIGH
    assert protected.action is ActionType.MONITOR
    assert "protected scope" in protected.reason


def test_unsupported_action_or_scope_fails_closed_to_monitor() -> None:
    unsupported_action = _decide(_result(score=0.3), caps=_caps(ActionType.MONITOR))
    fixture_scope = MitigationScope.from_mapping(
        ScopeKind.SCENARIO_FIXTURE,
        {"scenario_id": "dns-anomaly", "fixture_id": "h3-dns"},
    )
    unsupported_scope = _decide(_result(score=0.3, scope=fixture_scope))
    missing_scope = _decide(_result(score=0.3, scope=None))

    assert unsupported_action.action is ActionType.MONITOR
    assert "does not support" in unsupported_action.reason
    assert unsupported_scope.action is ActionType.MONITOR
    assert missing_scope.action is ActionType.MONITOR
    assert missing_scope.uncertain


def test_policy_a_and_b_are_explicit_and_thresholds_are_validation_manifest_bound() -> None:
    attack_without_score = _result(score=None)
    policy_a = _decide(attack_without_score, mode=PolicyMode.ALWAYS_BLOCK)
    policy_b = _decide(_result(score=0.85), mode=PolicyMode.CONFIDENCE)

    assert policy_a.action is ActionType.BLOCK
    assert policy_b.action is ActionType.BLOCK
    with pytest.raises(ValueError, match="calibration_id"):
        ConfidenceThresholds(0.2, 0.5, 0.8, "")
    with pytest.raises(ValueError, match="nondecreasing"):
        ConfidenceThresholds(0.5, 0.4, 0.8, "validation")


def test_exact_scope_and_result_validation_reject_invalid_inputs() -> None:
    with pytest.raises(ValueError, match="selectors"):
        MitigationScope(ScopeKind.FLOW, ())
    with pytest.raises(ValueError, match="both ports"):
        MitigationScope.from_mapping(
            ScopeKind.FLOW,
            {"datapath_id": "1", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "ip_protocol": 6},
        )
    with pytest.raises(ValueError, match=r"within \[0, 1\]"):
        _result(score=1.1)
    with pytest.raises(ValueError, match="finite"):
        EvidenceItem("e", "fixture", "score", float("inf"), NOW)


def test_action_is_created_with_fixed_ttl_and_audit_has_real_inputs_only() -> None:
    policy = _policy()
    result = _result(score=0.6, evidence=_corroboration())
    decision = policy.decide(
        result,
        now=NOW,
        mode=PolicyMode.RISK_AWARE,
        capabilities=_caps(ActionType.QUARANTINE),
    )
    action = policy.create_action(decision)
    proposed = action_proposal_event(action, timestamp=NOW)
    event = build_defense_audit_event(
        event_type="risk_decided",
        timestamp=NOW,
        result=result,
        decision=decision,
    )
    applied = build_action_lifecycle_event(
        action,
        event_type="action_applied",
        timestamp=NOW,
        reason="adapter confirmed exact rule",
    )

    assert action.action is ActionType.QUARANTINE
    assert action.ttl_seconds == 15
    assert action.expires_at == NOW + timedelta(seconds=15)
    assert proposed.to_dict()["action_id"] == action.action_id
    assert event.to_dict()["classification"] == "ATTACK"
    assert event.to_dict()["confidence"] == 0.6
    assert applied.to_dict()["action_id"] == action.action_id
    assert applied.to_dict()["rollback_state"] == "PROPOSED"


def test_stale_detection_is_uncertain_and_cannot_act() -> None:
    result = _result(score=0.99, evidence=_corroboration(), persistence=2)
    stale = DetectionResult(
        event_id=result.event_id,
        classification=result.classification,
        confidence=result.confidence,
        attack_score=result.attack_score,
        observed_at=NOW - timedelta(seconds=10),
        provenance=result.provenance,
        model_id=result.model_id,
        evidence=result.evidence,
        scope=result.scope,
        persistence_count=result.persistence_count,
    )
    decision = _decide(stale)

    assert decision.risk_level is RiskLevel.UNCERTAIN
    assert decision.action is ActionType.MONITOR
