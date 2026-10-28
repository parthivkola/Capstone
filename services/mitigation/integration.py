"""Application boundary joining detector results to the existing policy/orchestrator."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from services.mitigation.audit import action_proposal_event, build_defense_audit_event
from services.mitigation.orchestrator import MitigationOrchestrator
from services.mitigation.policy import PolicyMode, ProtectedFlow, RiskPolicy
from src.sdn_defense.contracts import (
    AdapterCapabilities,
    DefenseAuditEvent,
    DetectionResult,
    EnforcementEvent,
    MitigationAction,
    RiskDecision,
)


@dataclass(frozen=True, slots=True)
class DetectionEnforcementTrace:
    """Correlated immutable records for one policy-to-enforcement pass."""

    detection: DetectionResult
    decision: RiskDecision
    action: MitigationAction | None
    enforcement_events: tuple[EnforcementEvent, ...]
    audit_events: tuple[DefenseAuditEvent, ...]


class DetectionEnforcementService:
    """Pass detector output through policy and orchestrator without Ryu coupling."""

    def __init__(
        self,
        policy: RiskPolicy,
        orchestrator: MitigationOrchestrator,
        capabilities: AdapterCapabilities,
    ) -> None:
        self._policy = policy
        self._orchestrator = orchestrator
        self._capabilities = capabilities

    def process(
        self,
        result: DetectionResult,
        *,
        now: datetime,
        mode: PolicyMode,
        protected_flows: tuple[ProtectedFlow, ...] = (),
    ) -> DetectionEnforcementTrace:
        """Decide first, then materialize and execute only a policy-approved action."""

        decision = self._policy.decide(
            result,
            now=now,
            mode=mode,
            capabilities=self._capabilities,
            protected_flows=protected_flows,
        )
        audit_events = [
            build_defense_audit_event(
                event_type="detection_decision",
                timestamp=now,
                result=result,
                decision=decision,
            )
        ]
        if decision.action.value == "MONITOR":
            return DetectionEnforcementTrace(result, decision, None, (), tuple(audit_events))

        action = self._policy.create_action(decision)
        audit_events.append(
            action_proposal_event(action, timestamp=now, policy_arm=decision.policy_arm)
        )
        first_event = len(self._orchestrator.events)
        enforcement = self._orchestrator.apply(
            action,
            protected_scopes=tuple((item.scope, item.reason) for item in protected_flows),
        )
        action_events = self._orchestrator.events[first_event:]
        return DetectionEnforcementTrace(
            result,
            decision,
            action,
            action_events or (enforcement,),
            tuple(audit_events),
        )
