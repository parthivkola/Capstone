"""Deterministic TTL, re-evaluation, extension, and rollback state machine."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime

from src.sdn_defense.contracts import MitigationAction, MitigationScope, RollbackState


class InvalidLifecycleTransition(ValueError):
    """Raised when a mitigation action attempts an invalid state transition."""


@dataclass(frozen=True, slots=True)
class ExtensionEvidence:
    """The complete fresh evidence predicate required for one extension."""

    observed_at: datetime
    scope: MitigationScope
    still_attack_at_tier: bool
    independently_corroborated: bool
    protected: bool
    adapter_confirms_active: bool


@dataclass(frozen=True, slots=True)
class RollbackRequest:
    """Deterministic request for removal of exactly one action's rule."""

    request_id: str
    action_id: str
    reason: str
    requested_at: datetime


class MitigationLifecycle:
    """Pure state machine. It never calls an adapter or reads wall-clock time."""

    def __init__(self, action: MitigationAction, *, max_evidence_age_seconds: float = 5.0) -> None:
        if max_evidence_age_seconds <= 0:
            raise ValueError("max evidence age must be positive")
        self.action = action
        self.max_evidence_age_seconds = max_evidence_age_seconds

    @property
    def state(self) -> RollbackState:
        return self.action.rollback_state

    def activate(self, now: datetime) -> MitigationAction:
        self._require_state(RollbackState.PROPOSED)
        self._check_time(now)
        if now >= self.action.expires_at:
            raise InvalidLifecycleTransition("expired proposed action cannot activate")
        self.action = replace(self.action, rollback_state=RollbackState.ACTIVE)
        return self.action

    def extend(self, evidence: ExtensionEvidence, *, now: datetime) -> MitigationAction:
        self._require_state(RollbackState.ACTIVE)
        self._check_time(now)
        if self.action.extension_count >= 1:
            raise InvalidLifecycleTransition("only one conditional extension is allowed")
        midpoint = self.action.created_at.timestamp() + self.action.ttl_seconds / 2
        if now.timestamp() < midpoint or now >= self.action.expires_at:
            raise InvalidLifecycleTransition("extension is allowed only at the TTL midpoint")
        self._check_time(evidence.observed_at)
        age = (now - evidence.observed_at).total_seconds()
        if age < 0 or age > self.max_evidence_age_seconds:
            raise InvalidLifecycleTransition("stale extension evidence")
        if evidence.scope != self.action.scope:
            raise InvalidLifecycleTransition("extension evidence scope changed")
        if not (
            evidence.still_attack_at_tier
            and evidence.independently_corroborated
            and not evidence.protected
            and evidence.adapter_confirms_active
        ):
            raise InvalidLifecycleTransition("extension safety predicates are not all satisfied")
        expires_at = (
            self.action.created_at.replace() + (self.action.expires_at - self.action.created_at) * 2
        )
        self.action = replace(
            self.action,
            expires_at=expires_at,
            extension_count=1,
            rollback_state=RollbackState.EXTENDED,
        )
        return self.action

    def expire(self, now: datetime) -> RollbackRequest | None:
        if self.state not in (RollbackState.ACTIVE, RollbackState.EXTENDED):
            raise InvalidLifecycleTransition(f"cannot expire action in {self.state.value}")
        self._check_time(now)
        if now < self.action.expires_at:
            return None
        self.action = replace(self.action, rollback_state=RollbackState.EXPIRED)
        return RollbackRequest(
            request_id=f"rollback:{self.action.action_id}:expiry",
            action_id=self.action.action_id,
            reason="TTL expired",
            requested_at=now,
        )

    def rollback(self, now: datetime, *, reason: str) -> RollbackRequest:
        if self.state not in (
            RollbackState.PROPOSED,
            RollbackState.ACTIVE,
            RollbackState.EXTENDED,
            RollbackState.EXPIRED,
        ):
            raise InvalidLifecycleTransition(f"cannot roll back action in {self.state.value}")
        self._check_time(now)
        if not reason:
            raise ValueError("rollback reason is required")
        self.action = replace(self.action, rollback_state=RollbackState.ROLLED_BACK)
        return RollbackRequest(
            request_id=f"rollback:{self.action.action_id}:{reason}",
            action_id=self.action.action_id,
            reason=reason,
            requested_at=now,
        )

    def _require_state(self, expected: RollbackState) -> None:
        if self.state is not expected:
            raise InvalidLifecycleTransition(f"expected {expected.value}, got {self.state.value}")

    @staticmethod
    def _check_time(value: datetime) -> None:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("lifecycle times must be timezone-aware")
