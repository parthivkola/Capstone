"""Adapter tests use a fake OpenFlow parser; no switch or Ryu runtime is needed."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

from networking.ryu.mitigation_adapter import RyuAdapterConfig, RyuOpenFlowMitigationAdapter
from src.sdn_defense.contracts import (
    ActionType,
    AdapterStatus,
    DefenseAuditEvent,
    MitigationAction,
    MitigationScope,
    RollbackState,
    ScopeKind,
)

NOW = datetime(2026, 10, 8, 12, 0, tzinfo=UTC)


class FakeParser:
    def OFPMatch(self, **fields: Any) -> dict[str, Any]:
        return fields

    def OFPFlowMod(self, **fields: Any) -> SimpleNamespace:
        return SimpleNamespace(**fields)


class FakeDatapath:
    def __init__(self, *, fail_send: bool = False) -> None:
        self.id = 1
        self.ofproto_parser = FakeParser()
        self.ofproto = SimpleNamespace(
            OFPFC_ADD=0,
            OFPFC_DELETE_STRICT=4,
            OFPP_ANY=0xFFFFFFFF,
            OFPG_ANY=0xFFFFFFFF,
        )
        self.messages: list[SimpleNamespace] = []
        self.fail_send = fail_send

    def send_msg(self, message: SimpleNamespace) -> None:
        if self.fail_send:
            raise RuntimeError("fake switch send failure")
        self.messages.append(message)


def _scope() -> MitigationScope:
    return MitigationScope.from_mapping(
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


def _action(action: ActionType = ActionType.BLOCK) -> MitigationAction:
    return MitigationAction(
        action_id="immutable-action-id",
        action=action,
        scope=_scope(),
        created_at=NOW,
        expires_at=NOW + timedelta(seconds=10),
        ttl_seconds=10,
        reason="approved exact flow test action",
        evidence_refs=("event-evidence-1",),
        policy_version="stage7-v1",
        decision_id="decision-1",
    )


def _adapter(datapath: FakeDatapath, *, flow_verified: bool = True) -> RyuOpenFlowMitigationAdapter:
    return RyuOpenFlowMitigationAdapter(
        {1: datapath},
        RyuAdapterConfig(
            table_id=0,
            priority=30000,
            flow_mod_support_verified=flow_verified,
        ),
        clock=lambda: NOW,
    )


def test_supported_exact_flow_action_is_correlated_to_delete_rule() -> None:
    datapath = FakeDatapath()
    events: list[DefenseAuditEvent] = []
    adapter = RyuOpenFlowMitigationAdapter(
        {1: datapath},
        RyuAdapterConfig(table_id=0, priority=30000, flow_mod_support_verified=True),
        clock=lambda: NOW,
        audit_sink=events.append,
    )
    action = _action()

    result = adapter.apply(action)

    assert result.status is AdapterStatus.SUCCESS
    assert result.action_id == action.action_id
    assert result.rule_cookie is not None
    add = datapath.messages[0]
    assert add.command == datapath.ofproto.OFPFC_ADD
    assert add.cookie == result.rule_cookie
    assert add.hard_timeout == 10
    assert add.priority == 30000
    assert add.match == {
        "ipv4_src": "10.0.0.2",
        "ipv4_dst": "10.0.0.3",
        "ip_proto": 6,
        "tcp_src": 40000,
        "tcp_dst": 18080,
        "eth_type": 0x0800,
    }

    rollback = adapter.rollback(action.action_id)
    assert rollback.status is AdapterStatus.SUCCESS
    delete = datapath.messages[1]
    assert delete.command == datapath.ofproto.OFPFC_DELETE_STRICT
    assert delete.cookie == result.rule_cookie
    assert delete.cookie_mask == 0xFFFFFFFFFFFFFFFF
    assert delete.match == add.match
    assert [event.event_type for event in events] == ["action_applied", "rollback_submitted"]
    assert events[0].action_id == action.action_id
    assert events[0].rule_cookie == result.rule_cookie
    assert events[0].rollback_state is RollbackState.ACTIVE
    assert events[1].adapter_status is AdapterStatus.SUCCESS
    assert events[1].rollback_state is RollbackState.ROLLED_BACK
    assert adapter.rollback(action.action_id).status is AdapterStatus.REJECTED


def test_unverified_action_and_unrepresentable_scope_are_unsupported() -> None:
    datapath = FakeDatapath()
    unverified = _adapter(datapath, flow_verified=False)
    assert unverified.apply(_action()).status is AdapterStatus.UNSUPPORTED
    assert datapath.messages == []

    fixture = MitigationScope.from_mapping(
        ScopeKind.SCENARIO_FIXTURE,
        {"scenario_id": "dns-anomaly", "fixture_id": "h3-dns"},
    )
    fixture_action = MitigationAction(
        action_id="fixture-action",
        action=ActionType.QUARANTINE,
        scope=fixture,
        created_at=NOW,
        expires_at=NOW + timedelta(seconds=15),
        ttl_seconds=15,
        reason="fixture scope test",
        evidence_refs=(),
        policy_version="stage7-v1",
        decision_id="decision-fixture",
    )
    result = _adapter(datapath).apply(fixture_action)
    assert result.status is AdapterStatus.UNSUPPORTED
    assert datapath.messages == []
    assert not _adapter(datapath).capabilities.supports(ActionType.BLOCK, fixture)


def test_rate_limit_is_unsupported_and_never_fakes_meter_success() -> None:
    datapath = FakeDatapath()
    result = _adapter(datapath).apply(_action(ActionType.RATE_LIMIT))

    assert result.status is AdapterStatus.UNSUPPORTED
    assert "meter" in result.reason
    assert datapath.messages == []


def test_adapter_failure_is_not_reported_as_success() -> None:
    datapath = FakeDatapath(fail_send=True)
    result = _adapter(datapath).apply(_action())

    assert result.status is AdapterStatus.FAILED
    assert result.rule_cookie is None
    assert "send failure" in result.reason


def test_adapter_rejects_expired_action_and_missing_datapath() -> None:
    datapath = FakeDatapath()
    expired = RyuOpenFlowMitigationAdapter(
        {1: datapath},
        RyuAdapterConfig(0, 30000, flow_mod_support_verified=True),
        clock=lambda: NOW + timedelta(seconds=10),
    )
    assert expired.apply(_action()).status is AdapterStatus.REJECTED

    missing = RyuOpenFlowMitigationAdapter(
        {}, RyuAdapterConfig(0, 30000, flow_mod_support_verified=True), clock=lambda: NOW
    )
    assert missing.apply(_action()).status is AdapterStatus.UNSUPPORTED
