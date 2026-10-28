"""Synthetic detector-to-policy integration tests; no ML/data/network needed."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from services.detection.synthetic_fixtures import (
    SYNTHETIC_POLICY_THRESHOLDS,
    SYNTHETIC_TIME,
    SyntheticCase,
    make_synthetic_detection,
)
from services.mitigation.integration import DetectionEnforcementService
from services.mitigation.orchestrator import (
    MitigationOrchestrator,
    OrchestrationConfig,
    SwitchObservation,
)
from services.mitigation.policy import PolicyMode, ProtectedFlow, RiskPolicy, RiskPolicyConfig
from src.sdn_defense.contracts import (
    ActionType,
    AdapterCapabilities,
    AdapterResult,
    AdapterStatus,
    EnforcementStatus,
    MitigationAction,
    RiskLevel,
    ScopeKind,
    ShiftState,
)


def _policy() -> RiskPolicy:
    protocol = json.loads(Path("experiments/stage7/defense-protocol.json").read_text())
    from src.sdn_defense.contracts import ConfidenceThresholds

    thresholds = ConfidenceThresholds(*SYNTHETIC_POLICY_THRESHOLDS, "synthetic-only-not-calibrated")
    return RiskPolicy(
        RiskPolicyConfig.from_protocol(
            protocol,
            thresholds,
            persistence_observations=2,
            observation_interval_seconds=2.0,
        )
    )


def _capabilities() -> AdapterCapabilities:
    scopes = (ScopeKind.TUPLE, ScopeKind.FLOW, ScopeKind.HOST)
    return AdapterCapabilities(
        (
            (ActionType.MONITOR, tuple(ScopeKind)),
            (ActionType.RATE_LIMIT, scopes),
            (ActionType.QUARANTINE, scopes),
            (ActionType.BLOCK, scopes),
        )
    )


class _FakeAdapter:
    capabilities = _capabilities()

    def __init__(self) -> None:
        self.applied: list[MitigationAction] = []
        self.rolled_back: list[str] = []

    def apply(self, action: MitigationAction) -> AdapterResult:
        self.applied.append(action)
        return AdapterResult(action.action_id, AdapterStatus.SUCCESS, "synthetic submission", 17)

    def rollback(self, action_id: str) -> AdapterResult:
        self.rolled_back.append(action_id)
        return AdapterResult(action_id, AdapterStatus.SUCCESS, "synthetic rollback", 17)


class _FakeVerifier:
    def wait_for_present(
        self, cookie: int, scope: object, timeout_seconds: float
    ) -> SwitchObservation:
        return SwitchObservation(True, SYNTHETIC_TIME + timedelta(milliseconds=2), "fake present")

    def wait_for_absent(self, cookie: int, timeout_seconds: float) -> SwitchObservation:
        return SwitchObservation(False, SYNTHETIC_TIME + timedelta(milliseconds=4), "fake absent")


def _service(adapter: _FakeAdapter | None = None) -> DetectionEnforcementService:
    selected = adapter or _FakeAdapter()
    orchestrator = MitigationOrchestrator(
        selected,
        _FakeVerifier(),
        config=OrchestrationConfig(0.1),
        clock=lambda: SYNTHETIC_TIME,
        monotonic_clock=lambda: 1.0,
    )
    return DetectionEnforcementService(_policy(), orchestrator, selected.capabilities)


def test_synthetic_fixtures_are_explicit_reproducible_and_cover_required_cases() -> None:
    cases = tuple(SyntheticCase)
    first = [make_synthetic_detection(case) for case in cases]
    second = [make_synthetic_detection(case) for case in cases]
    assert first == second
    assert {item.provenance for item in first} == {"synthetic_test_fixture_only"}
    assert len({item.event_id for item in first}) == len(cases)


def test_synthetic_detection_cases_map_through_frozen_risk_policy() -> None:
    expected = {
        SyntheticCase.BENIGN: (RiskLevel.LOW, ActionType.MONITOR),
        SyntheticCase.LOW_ATTACK: (RiskLevel.LOW, ActionType.MONITOR),
        SyntheticCase.MEDIUM_ATTACK: (RiskLevel.MEDIUM, ActionType.RATE_LIMIT),
        SyntheticCase.HIGH_ATTACK: (RiskLevel.HIGH, ActionType.QUARANTINE),
        SyntheticCase.VERY_HIGH_ATTACK: (RiskLevel.VERY_HIGH, ActionType.BLOCK),
        SyntheticCase.UNKNOWN: (RiskLevel.UNCERTAIN, ActionType.MONITOR),
        SyntheticCase.UNCERTAIN: (RiskLevel.UNCERTAIN, ActionType.MONITOR),
    }
    service = _service()
    for case, (level, action) in expected.items():
        trace = service.process(
            make_synthetic_detection(case, event_id=f"result-{case.value}"),
            now=SYNTHETIC_TIME,
            mode=PolicyMode.RISK_AWARE_REVERSIBLE,
        )
        assert (trace.decision.risk_level, trace.decision.action) == (level, action)
        assert trace.decision.decision_id
        assert trace.decision.policy_version
        assert trace.decision.policy_arm == PolicyMode.RISK_AWARE_REVERSIBLE.value
        assert trace.decision.result_id == trace.detection.event_id
        assert bool(trace.action) is (action is not ActionType.MONITOR)


def test_policy_arm_identity_and_policy_a_to_d_decisions_are_preserved() -> None:
    policy = _policy()
    result = make_synthetic_detection(SyntheticCase.VERY_HIGH_ATTACK, event_id="all-arms")
    decisions = [
        policy.decide(
            result,
            now=SYNTHETIC_TIME,
            mode=mode,
            capabilities=_capabilities(),
        )
        for mode in PolicyMode
    ]
    assert [item.policy_arm for item in decisions] == [item.value for item in PolicyMode]
    assert decisions[0].action is ActionType.BLOCK
    assert decisions[1].action is ActionType.BLOCK
    assert decisions[2].action is ActionType.BLOCK
    assert decisions[3].action is ActionType.BLOCK
    assert len({item.decision_id for item in decisions}) == len(PolicyMode)


def test_unknown_uncertain_shift_only_and_stale_results_fail_safely() -> None:
    service = _service()
    unknown = make_synthetic_detection(SyntheticCase.UNKNOWN)
    uncertain = make_synthetic_detection(SyntheticCase.UNCERTAIN)
    shift_only = replace(
        uncertain, event_id="shift-only", attack_score=None, shift_state=ShiftState.SIGNAL
    )
    stale = replace(unknown, event_id="stale", observed_at=SYNTHETIC_TIME - timedelta(seconds=10))
    for result in (unknown, uncertain, shift_only, stale):
        trace = service.process(result, now=SYNTHETIC_TIME, mode=PolicyMode.RISK_AWARE)
        assert trace.decision.action is ActionType.MONITOR
        assert trace.action is None
    assert (
        "UNKNOWN is not ATTACK"
        in service.process(unknown, now=SYNTHETIC_TIME, mode=PolicyMode.RISK_AWARE).decision.reason
    )


def test_shift_signal_does_not_escalate_an_attack_without_attack_score() -> None:
    result = replace(
        make_synthetic_detection(SyntheticCase.MEDIUM_ATTACK),
        attack_score=None,
        shift_state=ShiftState.SIGNAL,
    )
    trace = _service().process(result, now=SYNTHETIC_TIME, mode=PolicyMode.RISK_AWARE)
    assert trace.decision.action is ActionType.MONITOR
    assert trace.decision.uncertain


def test_missing_scope_datapath_protected_and_unsupported_action_fail_safe() -> None:
    missing_scope = make_synthetic_detection(SyntheticCase.VERY_HIGH_ATTACK, include_scope=False)
    trace = _service().process(missing_scope, now=SYNTHETIC_TIME, mode=PolicyMode.RISK_AWARE)
    assert trace.decision.action is ActionType.MONITOR
    assert trace.action is None

    missing_datapath = make_synthetic_detection(SyntheticCase.VERY_HIGH_ATTACK, datapath_id=None)
    assert (
        _service()
        .process(missing_datapath, now=SYNTHETIC_TIME, mode=PolicyMode.RISK_AWARE)
        .decision.action
        is ActionType.MONITOR
    )

    protected_result = make_synthetic_detection(SyntheticCase.VERY_HIGH_ATTACK)
    assert protected_result.scope is not None
    protected_trace = _service().process(
        protected_result,
        now=SYNTHETIC_TIME,
        mode=PolicyMode.RISK_AWARE,
        protected_flows=(ProtectedFlow(protected_result.scope, "synthetic protected flow"),),
    )
    assert protected_trace.decision.action is ActionType.MONITOR
    assert "protected scope" in protected_trace.decision.reason

    monitor_only = AdapterCapabilities(((ActionType.MONITOR, tuple(ScopeKind)),))
    result = make_synthetic_detection(SyntheticCase.MEDIUM_ATTACK)
    decision = _policy().decide(
        result, now=SYNTHETIC_TIME, mode=PolicyMode.RISK_AWARE, capabilities=monitor_only
    )
    assert decision.action is ActionType.MONITOR
    assert "does not support" in decision.reason


def test_action_and_audit_correlation_include_synthetic_provenance_and_policy_arm() -> None:
    trace = _service().process(
        make_synthetic_detection(SyntheticCase.VERY_HIGH_ATTACK, event_id="correlated-fixture"),
        now=SYNTHETIC_TIME,
        mode=PolicyMode.RISK_AWARE_REVERSIBLE,
    )
    action = trace.action
    assert action is not None
    assert action.action_id
    assert action.decision_id == trace.decision.decision_id
    assert action.policy_version == trace.decision.policy_version
    assert action.evidence_refs == trace.decision.evidence_refs
    assert dict(action.scope.selectors)["datapath_id"] == "0000000000000001"
    assert action.ttl_seconds == 10
    assert action.extension_count == 0
    assert action.created_at == SYNTHETIC_TIME
    assert action.expires_at == SYNTHETIC_TIME + timedelta(seconds=10)
    assert trace.enforcement_events[-1].status is EnforcementStatus.CONFIRMED
    assert all(event.decision_id == action.decision_id for event in trace.enforcement_events)
    decision_audit, action_audit = trace.audit_events
    assert decision_audit.result_id == trace.detection.event_id
    assert decision_audit.provenance == "synthetic_test_fixture_only"
    assert decision_audit.evidence_refs == action.evidence_refs
    assert decision_audit.policy_arm == PolicyMode.RISK_AWARE_REVERSIBLE.value
    assert action_audit.decision_id == decision_audit.decision_id
    assert action_audit.action_id == action.action_id
    assert action_audit.policy_arm == decision_audit.policy_arm


def test_unbounded_scope_is_not_constructible() -> None:
    from src.sdn_defense.contracts import MitigationScope

    try:
        MitigationScope(ScopeKind.TUPLE, ())
    except ValueError:
        pass
    else:
        raise AssertionError("an empty/global scope must not be representable")
