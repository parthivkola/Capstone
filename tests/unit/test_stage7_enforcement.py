"""Deterministic orchestration and OVS verifier tests without root or networking."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from networking.ovs.verification import OvsFlowVerifier
from services.mitigation.orchestrator import (
    MitigationOrchestrator,
    OrchestrationConfig,
    SwitchObservation,
)
from src.sdn_defense.contracts import (
    ActionType,
    AdapterResult,
    AdapterStatus,
    EnforcementStatus,
    MitigationAction,
    MitigationScope,
    ScopeKind,
)

NOW = datetime(2026, 10, 8, 12, 0, tzinfo=UTC)


def action(action_id: str = "enforcement-test") -> MitigationAction:
    return MitigationAction(
        action_id=action_id,
        action=ActionType.BLOCK,
        scope=MitigationScope.from_mapping(
            ScopeKind.TUPLE,
            {
                "datapath_id": "0000000000000001",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "ip_protocol": 17,
                "dst_port": 18081,
            },
        ),
        created_at=NOW,
        expires_at=NOW + timedelta(seconds=10),
        ttl_seconds=10,
        reason="unit test exact tuple",
        evidence_refs=("unit-evidence",),
        policy_version="stage7-test",
        decision_id="decision-test",
    )


class FakeAdapter:
    def __init__(self, status: AdapterStatus = AdapterStatus.SUCCESS) -> None:
        self.status = status
        self.applied: list[MitigationAction] = []
        self.rollbacks: list[str] = []

    def apply(self, target: MitigationAction) -> AdapterResult:
        self.applied.append(target)
        cookie = 0x1234 if self.status is AdapterStatus.SUCCESS else None
        return AdapterResult(target.action_id, self.status, "fake submission", cookie)

    def rollback(self, action_id: str) -> AdapterResult:
        self.rollbacks.append(action_id)
        return AdapterResult(action_id, AdapterStatus.SUCCESS, "fake rollback", 0x1234)


class FakeVerifier:
    def __init__(
        self,
        *,
        present: bool = True,
        fail: bool = False,
        absent_failure: bool = False,
        absent_at: datetime = NOW + timedelta(milliseconds=5),
    ) -> None:
        self.present = present
        self.fail = fail
        self.absent_failure = absent_failure
        self.absent_at = absent_at

    def wait_for_present(
        self, cookie: int, scope: MitigationScope, timeout_seconds: float
    ) -> SwitchObservation:
        if self.fail:
            raise RuntimeError("fake state source unavailable")
        return SwitchObservation(self.present, NOW + timedelta(milliseconds=5), "fake observation")

    def wait_for_absent(self, cookie: int, timeout_seconds: float) -> SwitchObservation:
        if self.absent_failure:
            raise RuntimeError("fake rollback state source unavailable")
        return SwitchObservation(False, self.absent_at, "fake absent observation")


def orchestrator(adapter: FakeAdapter, verifier: FakeVerifier) -> MitigationOrchestrator:
    return MitigationOrchestrator(
        adapter,
        verifier,
        config=OrchestrationConfig(0.1),
        clock=lambda: NOW,
        monotonic_clock=lambda: 20.0,
    )


def test_submitted_is_recorded_before_independent_confirmation() -> None:
    target = action()
    subject = orchestrator(FakeAdapter(), FakeVerifier())

    result = subject.apply(target)

    assert result.status is EnforcementStatus.CONFIRMED
    assert [event.status for event in subject.events] == [
        EnforcementStatus.SUBMITTED,
        EnforcementStatus.CONFIRMED,
    ]
    assert subject.events[0].confirmation_timestamp is None
    assert subject.events[1].observed_present is True
    assert subject.events[1].rule_cookie == 0x1234


def test_protected_overlap_rejects_before_adapter_submission() -> None:
    target = action()
    adapter = FakeAdapter()
    subject = orchestrator(adapter, FakeVerifier())

    result = subject.apply(target, protected_scopes=((target.scope, "controller endpoint"),))

    assert result.status is EnforcementStatus.REJECTED
    assert "protected" in result.reason
    assert adapter.applied == []


def test_unconfirmed_or_unavailable_verification_fails_and_submits_cleanup() -> None:
    target = action()
    adapter = FakeAdapter()
    subject = orchestrator(adapter, FakeVerifier(present=False))

    result = subject.apply(target)

    assert result.status is EnforcementStatus.FAILED
    assert result.observed_present is False
    assert adapter.rollbacks == [target.action_id]
    assert not any(event.status is EnforcementStatus.CONFIRMED for event in subject.events)


def test_verifier_exception_is_not_misreported_as_confirmation() -> None:
    target = action()
    adapter = FakeAdapter()
    result = orchestrator(adapter, FakeVerifier(fail=True)).apply(target)

    assert result.status is EnforcementStatus.FAILED
    assert "verification failed" in result.reason
    assert adapter.rollbacks == [target.action_id]


def test_rollback_requires_independent_absence_observation() -> None:
    target = action()
    subject = orchestrator(FakeAdapter(), FakeVerifier())
    subject.apply(target)

    result = subject.rollback(target.action_id)

    assert result.status is EnforcementStatus.ROLLED_BACK
    assert result.observed_present is False
    assert result.confirmation_timestamp is not None
    assert subject.events[-1].status is EnforcementStatus.ROLLED_BACK


def test_ttl_expiry_is_recorded_before_verified_rollback() -> None:
    target = action()
    adapter = FakeAdapter()
    verifier = FakeVerifier(absent_at=NOW + timedelta(seconds=12))
    subject = orchestrator(adapter, verifier)
    subject.apply(target)

    result = subject.expire(target.action_id, now=NOW + timedelta(seconds=11))

    assert result.status is EnforcementStatus.ROLLED_BACK
    assert [event.status for event in subject.events[-3:]] == [
        EnforcementStatus.EXPIRED,
        EnforcementStatus.SUBMITTED,
        EnforcementStatus.ROLLED_BACK,
    ]


def test_rollback_verification_failure_is_not_reported_as_rollback() -> None:
    target = action()
    subject = orchestrator(FakeAdapter(), FakeVerifier(absent_failure=True))
    subject.apply(target)

    result = subject.rollback(target.action_id)

    assert result.status is EnforcementStatus.FAILED
    assert "rollback verification failed" in result.reason


def test_unsupported_adapter_action_is_not_promoted_to_submitted() -> None:
    target = action()
    result = orchestrator(FakeAdapter(AdapterStatus.UNSUPPORTED), FakeVerifier()).apply(target)

    assert result.status is EnforcementStatus.UNSUPPORTED


def test_invalid_empty_scope_is_rejected_by_contract() -> None:
    with pytest.raises(ValueError, match="unique, non-empty"):
        MitigationScope(ScopeKind.FLOW, ())


def test_confirmed_outcome_requires_observed_switch_state() -> None:
    from src.sdn_defense.contracts import EnforcementEvent

    target = action()
    with pytest.raises(ValueError, match="CONFIRMED requires"):
        EnforcementEvent(
            event_id="confirmed-without-evidence",
            action_id=target.action_id,
            decision_id=target.decision_id,
            timestamp=NOW,
            status=EnforcementStatus.CONFIRMED,
            datapath_id=1,
            rule_cookie=7,
            exact_scope=target.scope,
            reason="must be rejected",
        )


class StaticFlowVerifier(OvsFlowVerifier):
    def __init__(self, dump: str) -> None:
        super().__init__("s1", clock=lambda: NOW)
        self.dump = dump

    def dump_flows(self) -> str:
        return self.dump


def test_ovs_verifier_requires_cookie_exact_match_and_drop_action() -> None:
    scope = action().scope
    line = (
        " cookie=0x1234, duration=1.0s, table=0, n_packets=1, priority=40000,"
        "udp,nw_src=10.0.0.1,nw_dst=10.0.0.2,tp_dst=18081 actions=drop"
    )
    verifier = StaticFlowVerifier(line)
    observed = verifier.wait_for_present(0x1234, scope, 0.1)
    assert observed.present is True
    assert verifier.wait_for_absent(0x1234, 0.1).present is True

    wrong_cookie = StaticFlowVerifier(line.replace("0x1234", "0x5678"))
    assert wrong_cookie.wait_for_present(0x1234, scope, 0.1).present is False

    wrong_match = StaticFlowVerifier(line.replace("tp_dst=18081", "tp_dst=18082"))
    assert wrong_match.wait_for_present(0x1234, scope, 0.1).present is False


def test_ovs_absence_observation_returns_actual_absent_state() -> None:
    verifier = StaticFlowVerifier(" cookie=0x9, table=0, actions=drop")
    observation = verifier.wait_for_absent(0x1234, 0.1)
    assert observation.present is False
