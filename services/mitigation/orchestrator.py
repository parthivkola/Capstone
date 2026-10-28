"""Enforcement orchestration boundary, independent of Ryu and OpenFlow."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from time import monotonic
from typing import Protocol

from services.mitigation.lifecycle import InvalidLifecycleTransition, MitigationLifecycle
from src.sdn_defense.contracts import (
    AdapterResult,
    AdapterStatus,
    EnforcementEvent,
    EnforcementStatus,
    MitigationAction,
    MitigationScope,
    RollbackState,
)


@dataclass(frozen=True, slots=True)
class SwitchObservation:
    """Independent view of one cookie's switch-table state."""

    present: bool
    observed_at: datetime
    detail: str


class SwitchStateVerifier(Protocol):
    """Poll an independent switch-state source until state or timeout."""

    def wait_for_present(
        self, cookie: int, scope: MitigationScope, timeout_seconds: float
    ) -> SwitchObservation: ...

    def wait_for_absent(self, cookie: int, timeout_seconds: float) -> SwitchObservation: ...


class SubmissionAdapter(Protocol):
    """Adapter contract consumed by the orchestrator."""

    def apply(self, action: MitigationAction) -> AdapterResult: ...

    def rollback(self, action_id: str) -> AdapterResult: ...


@dataclass(frozen=True, slots=True)
class OrchestrationConfig:
    verification_timeout_seconds: float = 3.0

    def __post_init__(self) -> None:
        if self.verification_timeout_seconds <= 0:
            raise ValueError("verification timeout must be positive")


class MitigationOrchestrator:
    """Submits, independently verifies, tracks, and exactly rolls back actions."""

    def __init__(
        self,
        adapter: SubmissionAdapter,
        verifier: SwitchStateVerifier,
        *,
        config: OrchestrationConfig | None = None,
        clock: Callable[[], datetime] | None = None,
        monotonic_clock: Callable[[], float] | None = None,
    ) -> None:
        self._adapter = adapter
        self._verifier = verifier
        self._config = config or OrchestrationConfig()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._monotonic = monotonic_clock or monotonic
        self._lifecycles: dict[str, MitigationLifecycle] = {}
        self._cookies: dict[str, int] = {}
        self._actions: dict[str, MitigationAction] = {}
        self._events: list[EnforcementEvent] = []

    @property
    def events(self) -> tuple[EnforcementEvent, ...]:
        return tuple(self._events)

    def apply(
        self,
        action: MitigationAction,
        *,
        protected_scopes: tuple[tuple[MitigationScope, str], ...] = (),
    ) -> EnforcementEvent:
        """Submit only exact unprotected actions and confirm via switch observation."""

        if action.action_id in self._actions:
            return self._event(action, EnforcementStatus.REJECTED, "duplicate action ID")
        if action.rollback_state is not RollbackState.PROPOSED:
            return self._event(action, EnforcementStatus.REJECTED, "action is not proposed")
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None or now >= action.expires_at:
            return self._event(
                action, EnforcementStatus.EXPIRED, "action expired before submission"
            )
        if not dict(action.scope.selectors).get("datapath_id"):
            return self._event(
                action, EnforcementStatus.UNSUPPORTED, "scope lacks datapath identity"
            )
        protected = next(
            ((scope, reason) for scope, reason in protected_scopes if action.scope.overlaps(scope)),
            None,
        )
        if protected is not None:
            return self._event(
                action,
                EnforcementStatus.REJECTED,
                f"protected scope: {protected[1]}",
            )

        started = self._monotonic()
        submission = self._adapter.apply(action)
        if submission.status is not AdapterStatus.SUCCESS:
            mapped = {
                AdapterStatus.REJECTED: EnforcementStatus.REJECTED,
                AdapterStatus.UNSUPPORTED: EnforcementStatus.UNSUPPORTED,
                AdapterStatus.FAILED: EnforcementStatus.FAILED,
            }[submission.status]
            return self._event(action, mapped, submission.reason, submission.rule_cookie)
        self._event(action, EnforcementStatus.SUBMITTED, submission.reason, submission.rule_cookie)
        assert submission.rule_cookie is not None

        try:
            observation = self._verifier.wait_for_present(
                submission.rule_cookie,
                action.scope,
                self._config.verification_timeout_seconds,
            )
        except Exception as error:
            self._adapter.rollback(action.action_id)
            return self._event(
                action,
                EnforcementStatus.FAILED,
                f"independent verification failed: {error}",
                submission.rule_cookie,
                observed_present=False,
            )
        elapsed_ms = max(0.0, (self._monotonic() - started) * 1000.0)
        if not observation.present:
            # Best-effort exact cleanup prevents a delayed request remaining active.
            self._adapter.rollback(action.action_id)
            return self._event(
                action,
                EnforcementStatus.FAILED,
                f"switch state not confirmed: {observation.detail}",
                submission.rule_cookie,
                observed_at=observation.observed_at,
                latency_ms=elapsed_ms,
                observed_present=False,
            )

        lifecycle = MitigationLifecycle(action)
        lifecycle.activate(observation.observed_at)
        self._lifecycles[action.action_id] = lifecycle
        self._cookies[action.action_id] = submission.rule_cookie
        self._actions[action.action_id] = action
        return self._event(
            action,
            EnforcementStatus.CONFIRMED,
            observation.detail,
            submission.rule_cookie,
            observed_at=observation.observed_at,
            latency_ms=elapsed_ms,
            observed_present=True,
        )

    def rollback(self, action_id: str, *, reason: str = "operator rollback") -> EnforcementEvent:
        """Submit exact rollback and confirm the cookie is absent from the switch."""

        action = self._actions.get(action_id)
        cookie = self._cookies.get(action_id)
        lifecycle = self._lifecycles.get(action_id)
        if action is None or cookie is None or lifecycle is None:
            raise KeyError(f"no confirmed action is tracked for {action_id}")
        if lifecycle.state not in (
            RollbackState.ACTIVE,
            RollbackState.EXTENDED,
            RollbackState.EXPIRED,
        ):
            raise InvalidLifecycleTransition(f"cannot roll back {lifecycle.state.value} action")

        started = self._monotonic()
        result = self._adapter.rollback(action_id)
        if result.status is not AdapterStatus.SUCCESS:
            return self._event(
                action,
                EnforcementStatus.FAILED,
                f"rollback submission failed: {result.reason}",
                cookie,
            )
        self._event(action, EnforcementStatus.SUBMITTED, result.reason, cookie)
        try:
            observation = self._verifier.wait_for_absent(
                cookie, self._config.verification_timeout_seconds
            )
        except Exception as error:
            return self._event(
                action,
                EnforcementStatus.FAILED,
                f"independent rollback verification failed: {error}",
                cookie,
                observed_present=True,
            )
        elapsed_ms = max(0.0, (self._monotonic() - started) * 1000.0)
        if observation.present:
            return self._event(
                action,
                EnforcementStatus.FAILED,
                f"switch still reports mitigation rule: {observation.detail}",
                cookie,
                observed_at=observation.observed_at,
                latency_ms=elapsed_ms,
                observed_present=True,
            )
        lifecycle.rollback(observation.observed_at, reason=reason)
        event = self._event(
            action,
            EnforcementStatus.ROLLED_BACK,
            observation.detail,
            cookie,
            observed_at=observation.observed_at,
            latency_ms=elapsed_ms,
            observed_present=False,
        )
        self._lifecycles.pop(action_id, None)
        self._cookies.pop(action_id, None)
        self._actions.pop(action_id, None)
        return event

    def expire(self, action_id: str, *, now: datetime | None = None) -> EnforcementEvent:
        """Issue rollback only after lifecycle TTL expiry, then verify switch absence."""

        lifecycle = self._lifecycles.get(action_id)
        if lifecycle is None:
            raise KeyError(f"no active action is tracked for {action_id}")
        expired_at = now or self._clock()
        expiration = lifecycle.expire(expired_at)
        if expiration is None:
            raise InvalidLifecycleTransition("action TTL has not expired")
        action = self._actions[action_id]
        self._event(
            action,
            EnforcementStatus.EXPIRED,
            expiration.reason,
            self._cookies[action_id],
            observed_at=expired_at,
        )
        # The switch hard timeout may already have removed the rule. Ryu adapter
        # still needs its correlation entry to submit strict delete safely.
        return self.rollback(action_id, reason=expiration.reason)

    def _event(
        self,
        action: MitigationAction,
        status: EnforcementStatus,
        reason: str,
        cookie: int | None = None,
        *,
        observed_at: datetime | None = None,
        latency_ms: float | None = None,
        observed_present: bool | None = None,
    ) -> EnforcementEvent:
        timestamp = observed_at or self._clock()
        datapath = dict(action.scope.selectors).get("datapath_id", 0)
        datapath_id = int(str(datapath), 16) if isinstance(datapath, str) else int(datapath)
        event_id = hashlib.sha256(
            f"{action.action_id}:{status.value}:{timestamp.isoformat()}:{len(self._events)}".encode()
        ).hexdigest()
        event = EnforcementEvent(
            event_id=event_id,
            action_id=action.action_id,
            decision_id=action.decision_id,
            timestamp=timestamp,
            status=status,
            datapath_id=datapath_id,
            rule_cookie=cookie,
            exact_scope=action.scope,
            reason=reason,
            confirmation_timestamp=timestamp if observed_present is not None else None,
            latency_ms=latency_ms,
            observed_present=observed_present,
        )
        self._events.append(event)
        return event
