"""Deterministic Stage 7 risk policy, independent of Ryu/OpenFlow."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from src.sdn_defense.contracts import (
    ActionType,
    AdapterCapabilities,
    Classification,
    ConfidenceThresholds,
    DetectionResult,
    MitigationAction,
    MitigationScope,
    RiskDecision,
    RiskLevel,
)


class PolicyMode(StrEnum):
    """Frozen policy comparison arms A through D."""

    ALWAYS_BLOCK = "A_always_block"
    CONFIDENCE = "B_confidence"
    RISK_AWARE = "C_risk_aware"
    RISK_AWARE_REVERSIBLE = "D_risk_aware_reversible"


@dataclass(frozen=True, slots=True)
class ProtectedFlow:
    """Explicitly protected scope; no implicit host importance is inferred."""

    scope: MitigationScope
    reason: str

    def __post_init__(self) -> None:
        if not self.reason:
            raise ValueError("protected flow reason is required")


@dataclass(frozen=True, slots=True)
class RiskPolicyConfig:
    """Runtime policy settings loaded from the frozen protocol plus calibration."""

    policy_version: str
    thresholds: ConfidenceThresholds
    ttl_seconds: tuple[tuple[ActionType, int], ...]
    max_evidence_age_seconds: float
    persistence_observations: int
    observation_interval_seconds: float

    def __post_init__(self) -> None:
        if not self.policy_version:
            raise ValueError("policy_version is required")
        ttl = dict(self.ttl_seconds)
        required = {ActionType.RATE_LIMIT, ActionType.QUARANTINE, ActionType.BLOCK}
        if set(ttl) != required or any(value <= 0 for value in ttl.values()):
            raise ValueError("positive TTLs are required for all disruptive actions")
        if self.max_evidence_age_seconds <= 0:
            raise ValueError("evidence age limit must be positive")
        if self.persistence_observations < 2 or self.observation_interval_seconds <= 0:
            raise ValueError("persistence requires at least two positive-interval observations")

    @classmethod
    def from_protocol(
        cls,
        protocol: dict[str, Any],
        thresholds: ConfidenceThresholds,
        *,
        persistence_observations: int,
        observation_interval_seconds: float,
    ) -> RiskPolicyConfig:
        """Load frozen TTL/persistence values; thresholds come from validation."""

        lifecycle = protocol["mitigation_lifecycle"]
        return cls(
            policy_version=str(protocol["protocol_id"]),
            thresholds=thresholds,
            ttl_seconds=tuple(
                sorted(
                    (
                        (ActionType(action), int(ttl))
                        for action, ttl in lifecycle["ttl_seconds"].items()
                    ),
                    key=lambda item: item[0].value,
                )
            ),
            max_evidence_age_seconds=float(lifecycle["evidence_stale_after_seconds"]),
            persistence_observations=persistence_observations,
            observation_interval_seconds=observation_interval_seconds,
        )

    def ttl_for(self, action: ActionType) -> int:
        return dict(self.ttl_seconds)[action]


class RiskPolicy:
    """Pure risk decision component; it has no adapter or network dependency."""

    def __init__(self, config: RiskPolicyConfig) -> None:
        self._config = config

    def decide(
        self,
        result: DetectionResult,
        *,
        now: datetime,
        mode: PolicyMode,
        capabilities: AdapterCapabilities,
        protected_flows: tuple[ProtectedFlow, ...] = (),
    ) -> RiskDecision:
        """Select a safe action from a supported result and explicit capabilities."""

        _require_aware(now)
        score = result.attack_score
        evidence_refs = tuple(item.evidence_id for item in result.evidence)
        corroborated = any(
            item.source.lower() not in {"model", "rf", "detector"}
            and 0
            <= (now - item.observed_at).total_seconds()
            <= self._config.max_evidence_age_seconds
            for item in result.evidence
        )
        persistent = (
            result.persistence_count is not None
            and result.persistence_count >= self._config.persistence_observations
        )

        risk, action, reason, uncertain = self._select(
            result, score, corroborated, persistent, now, mode
        )

        if action is not ActionType.MONITOR:
            if result.scope is None:
                risk, action, reason, uncertain = (
                    RiskLevel.UNCERTAIN,
                    ActionType.MONITOR,
                    "missing exact mitigation scope; fail closed",
                    True,
                )
            else:
                protected = next(
                    (item for item in protected_flows if result.scope.overlaps(item.scope)), None
                )
                if protected is not None:
                    risk, action, reason, uncertain = (
                        RiskLevel.LOW,
                        ActionType.MONITOR,
                        f"protected scope: {protected.reason}",
                        False,
                    )
                elif not capabilities.supports(action, result.scope):
                    reason = f"adapter does not support {action.value} for this scope; fail closed"
                    action = ActionType.MONITOR
                    uncertain = True

        decision_payload = {
            "event_id": result.event_id,
            "risk": risk.value,
            "action": action.value,
            "reason": reason,
            "policy": self._config.policy_version,
            "policy_arm": mode.value,
            "decided_at": now.isoformat(),
        }
        decision_id = hashlib.sha256(
            json.dumps(decision_payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return RiskDecision(
            decision_id=decision_id,
            result_id=result.event_id,
            risk_level=risk,
            action=action,
            reason=reason,
            evidence_refs=evidence_refs,
            policy_version=self._config.policy_version,
            decided_at=now,
            uncertain=uncertain,
            scope=result.scope,
            policy_arm=mode.value,
        )

    def create_action(self, decision: RiskDecision) -> MitigationAction:
        """Materialize a bounded action only after a non-monitor decision."""

        if decision.action is ActionType.MONITOR:
            raise ValueError("MONITOR decisions do not create mitigation actions")
        if decision.uncertain and decision.action not in (ActionType.RATE_LIMIT,):
            raise ValueError("uncertain decisions cannot create quarantine/block actions")
        if decision.scope is None:
            raise ValueError("dangerous action requires an exact scope")
        ttl = self._config.ttl_for(decision.action)
        expires = decision.decided_at.timestamp() + ttl
        expires_at = datetime.fromtimestamp(expires, tz=UTC)
        action_id = hashlib.sha256(
            f"{decision.decision_id}:{decision.action.value}:{decision.scope}".encode()
        ).hexdigest()
        return MitigationAction(
            action_id=action_id,
            action=decision.action,
            scope=decision.scope,
            created_at=decision.decided_at,
            expires_at=expires_at,
            ttl_seconds=ttl,
            reason=decision.reason,
            evidence_refs=decision.evidence_refs,
            policy_version=decision.policy_version,
            decision_id=decision.decision_id,
        )

    def _select(
        self,
        result: DetectionResult,
        score: float | None,
        corroborated: bool,
        persistent: bool,
        now: datetime,
        mode: PolicyMode,
    ) -> tuple[RiskLevel, ActionType, str, bool]:
        age = (now - result.observed_at).total_seconds()
        if age < 0 or age > self._config.max_evidence_age_seconds:
            return RiskLevel.UNCERTAIN, ActionType.MONITOR, "stale/future detection result", True
        if result.classification is Classification.UNKNOWN:
            if persistent and corroborated and result.scope is not None:
                return RiskLevel.UNCERTAIN, ActionType.RATE_LIMIT, "repeated scoped UNKNOWN", True
            return RiskLevel.UNCERTAIN, ActionType.MONITOR, "UNKNOWN is not ATTACK", True
        if result.classification is Classification.BENIGN:
            return RiskLevel.LOW, ActionType.MONITOR, "detector classified BENIGN", False
        if mode is PolicyMode.ALWAYS_BLOCK:
            return (
                RiskLevel.VERY_HIGH,
                ActionType.BLOCK,
                "Policy A: ATTACK -> exact-scope block",
                False,
            )
        if result.shift_state.value == "SIGNAL" and score is None:
            return (
                RiskLevel.LOW,
                ActionType.MONITOR,
                "distribution shift alone is not attack evidence",
                True,
            )
        if result.confidence is None:
            return RiskLevel.UNCERTAIN, ActionType.MONITOR, "confidence unavailable", True
        if score is None:
            return RiskLevel.UNCERTAIN, ActionType.MONITOR, "attack score unavailable", True

        thresholds = self._config.thresholds
        if thresholds.tau_rate is None or score < thresholds.tau_rate:
            return (
                RiskLevel.LOW,
                ActionType.MONITOR,
                "attack score below calibrated rate-limit cutoff",
                False,
            )
        if mode is PolicyMode.CONFIDENCE:
            if thresholds.tau_block is not None and score >= thresholds.tau_block:
                return (
                    RiskLevel.VERY_HIGH,
                    ActionType.BLOCK,
                    "Policy B: calibrated block confidence",
                    False,
                )
            if thresholds.tau_quarantine is not None and score >= thresholds.tau_quarantine:
                return (
                    RiskLevel.HIGH,
                    ActionType.QUARANTINE,
                    "Policy B: calibrated quarantine confidence",
                    False,
                )
            return (
                RiskLevel.MEDIUM,
                ActionType.RATE_LIMIT,
                "Policy B: calibrated rate-limit confidence",
                False,
            )

        if thresholds.tau_block is not None and score >= thresholds.tau_block:
            if persistent and corroborated:
                return (
                    RiskLevel.VERY_HIGH,
                    ActionType.BLOCK,
                    "high confidence, persistent and corroborated",
                    False,
                )
            return (
                RiskLevel.HIGH,
                ActionType.QUARANTINE,
                "high score without all block evidence",
                False,
            )
        if thresholds.tau_quarantine is not None and score >= thresholds.tau_quarantine:
            if corroborated:
                return (
                    RiskLevel.HIGH,
                    ActionType.QUARANTINE,
                    "quarantine confidence with corroboration",
                    False,
                )
            return (
                RiskLevel.MEDIUM,
                ActionType.RATE_LIMIT,
                "quarantine score lacks corroboration",
                False,
            )
        return RiskLevel.MEDIUM, ActionType.RATE_LIMIT, "medium calibrated attack score", False


def _require_aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("decision time must be timezone-aware")
