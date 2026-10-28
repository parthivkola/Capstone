"""Structured Stage 7 audit-event construction."""

from __future__ import annotations

import hashlib
from datetime import datetime

from src.sdn_defense.contracts import (
    AdapterResult,
    DefenseAuditEvent,
    DetectionResult,
    MitigationAction,
    RiskDecision,
    RollbackState,
)


def build_defense_audit_event(
    *,
    event_type: str,
    timestamp: datetime,
    result: DetectionResult,
    decision: RiskDecision,
    action: MitigationAction | None = None,
    adapter_result: AdapterResult | None = None,
    rollback_state: RollbackState | None = None,
) -> DefenseAuditEvent:
    """Bind real detector output, policy decision, and optional adapter result."""

    event_id = hashlib.sha256(
        f"{decision.decision_id}:{event_type}:{timestamp.isoformat()}".encode()
    ).hexdigest()
    return DefenseAuditEvent(
        event_id=event_id,
        timestamp=timestamp,
        event_type=event_type,
        decision_id=decision.decision_id,
        action_id=None if action is None else action.action_id,
        action=decision.action if action is None else action.action,
        scope=decision.scope if action is None else action.scope,
        reason=decision.reason if action is None else action.reason,
        policy_version=decision.policy_version,
        adapter_status=None if adapter_result is None else adapter_result.status,
        ttl_seconds=None if action is None else action.ttl_seconds,
        rollback_state=rollback_state if action is None else action.rollback_state,
        rule_cookie=None if adapter_result is None else adapter_result.rule_cookie,
        result_id=result.event_id,
        classification=result.classification,
        confidence=result.confidence,
        attack_score=result.attack_score,
        novelty_score=result.novelty_score,
        shift_state=result.shift_state,
        risk_level=decision.risk_level,
        provenance=result.provenance,
        policy_arm=decision.policy_arm,
        evidence_refs=decision.evidence_refs,
    )


def build_action_lifecycle_event(
    action: MitigationAction,
    *,
    event_type: str,
    timestamp: datetime,
    reason: str,
    adapter_result: AdapterResult | None = None,
    rollback_state: RollbackState | None = None,
) -> DefenseAuditEvent:
    """Record extension/expiry/rollback lifecycle without adding detector data."""

    event_id = hashlib.sha256(
        f"{action.action_id}:{event_type}:{timestamp.isoformat()}".encode()
    ).hexdigest()
    return DefenseAuditEvent(
        event_id=event_id,
        timestamp=timestamp,
        event_type=event_type,
        decision_id=action.decision_id,
        action_id=action.action_id,
        action=action.action,
        scope=action.scope,
        reason=reason,
        policy_version=action.policy_version,
        adapter_status=None if adapter_result is None else adapter_result.status,
        ttl_seconds=action.ttl_seconds,
        rollback_state=rollback_state or action.rollback_state,
        rule_cookie=None if adapter_result is None else adapter_result.rule_cookie,
    )


def action_proposal_event(
    action: MitigationAction,
    *,
    timestamp: datetime,
    policy_arm: str | None = None,
) -> DefenseAuditEvent:
    """Create an action-proposed event before adapter execution."""

    event_id = hashlib.sha256(
        f"{action.action_id}:action_proposed:{timestamp.isoformat()}".encode()
    ).hexdigest()
    return DefenseAuditEvent(
        event_id=event_id,
        timestamp=timestamp,
        event_type="action_proposed",
        decision_id=action.decision_id,
        action_id=action.action_id,
        action=action.action,
        scope=action.scope,
        reason=action.reason,
        policy_version=action.policy_version,
        adapter_status=None,
        ttl_seconds=action.ttl_seconds,
        rollback_state=action.rollback_state,
        policy_arm=policy_arm,
    )
