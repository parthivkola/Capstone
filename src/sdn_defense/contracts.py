"""Technology-neutral interfaces for future adapter implementations."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol


@dataclass(frozen=True, slots=True)
class DecisionRecord:
    """Legacy decision envelope retained for compatibility with Stage 1 callers.

    New Stage 7 code uses :class:`DetectionResult`, :class:`RiskDecision`, and
    :class:`MitigationAction` so detection and action selection remain separate.
    """

    event_id: str
    risk_level: str
    action: str
    expires_at: str | None
    evidence: Mapping[str, float | str]


class Classification(StrEnum):
    """Detector output classes; UNKNOWN is not silently treated as ATTACK."""

    BENIGN = "BENIGN"
    ATTACK = "ATTACK"
    UNKNOWN = "UNKNOWN"


class ShiftState(StrEnum):
    """Optional source/window-level input-distribution observation."""

    NO_SIGNAL = "NO_SIGNAL"
    SIGNAL = "SIGNAL"
    UNAVAILABLE = "UNAVAILABLE"


class RiskLevel(StrEnum):
    """Policy risk categories, including the policy abstention state."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    VERY_HIGH = "VERY_HIGH"
    UNCERTAIN = "UNCERTAIN"


class ActionType(StrEnum):
    """Actions available to a policy-approved mitigation adapter."""

    MONITOR = "MONITOR"
    RATE_LIMIT = "RATE_LIMIT"
    QUARANTINE = "QUARANTINE"
    BLOCK = "BLOCK"


class ScopeKind(StrEnum):
    """Constrained scopes that can be represented without a global wildcard."""

    FLOW = "FLOW"
    HOST = "HOST"
    TUPLE = "TUPLE"
    SCENARIO_FIXTURE = "SCENARIO_FIXTURE"


class RollbackState(StrEnum):
    """Lifecycle state stored with an immutable mitigation action."""

    PROPOSED = "PROPOSED"
    ACTIVE = "ACTIVE"
    EXTENDED = "EXTENDED"
    EXPIRED = "EXPIRED"
    ROLLED_BACK = "ROLLED_BACK"


class AdapterStatus(StrEnum):
    """Explicit result of a mitigation adapter operation."""

    SUCCESS = "SUCCESS"
    REJECTED = "REJECTED"
    UNSUPPORTED = "UNSUPPORTED"
    FAILED = "FAILED"


class EnforcementStatus(StrEnum):
    """Observed lifecycle outcome; SUBMITTED is distinct from switch confirmation."""

    SUBMITTED = "SUBMITTED"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    FAILED = "FAILED"
    UNSUPPORTED = "UNSUPPORTED"
    EXPIRED = "EXPIRED"
    ROLLED_BACK = "ROLLED_BACK"


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    """One provenance-bearing observation; it is not an explanation by itself."""

    evidence_id: str
    source: str
    name: str
    value: float | str | bool
    observed_at: datetime

    def __post_init__(self) -> None:
        if not self.evidence_id or not self.source or not self.name:
            raise ValueError("evidence ID, source, and name must be non-empty")
        _require_aware(self.observed_at, "evidence observed_at")
        if isinstance(self.value, float) and not math.isfinite(self.value):
            raise ValueError("numeric evidence must be finite")


@dataclass(frozen=True, slots=True)
class MitigationScope:
    """Immutable exact selector set for one flow, host, tuple, or fixture."""

    kind: ScopeKind
    selectors: tuple[tuple[str, str | int], ...]

    def __post_init__(self) -> None:
        names = [name for name, _ in self.selectors]
        if not self.selectors or len(names) != len(set(names)):
            raise ValueError("mitigation scope must have unique, non-empty selectors")
        allowed = {
            "datapath_id",
            "src_ip",
            "dst_ip",
            "src_mac",
            "dst_mac",
            "ip_protocol",
            "src_port",
            "dst_port",
            "in_port",
            "host_id",
            "scenario_id",
            "fixture_id",
        }
        if any(name not in allowed for name in names):
            raise ValueError("scope contains an unsupported selector")
        values = dict(self.selectors)
        if self.kind is ScopeKind.FLOW:
            if not {"datapath_id", "src_ip", "dst_ip", "ip_protocol"}.issubset(values):
                raise ValueError(
                    "flow scope requires datapath, source/destination IP, and protocol"
                )
            if values["ip_protocol"] in (6, 17) and not {
                "src_port",
                "dst_port",
            }.issubset(values):
                raise ValueError("TCP/UDP flow scope requires both ports")
        elif self.kind is ScopeKind.TUPLE:
            if not {"datapath_id", "src_ip", "dst_ip", "ip_protocol"}.issubset(values):
                raise ValueError("tuple scope requires datapath and both endpoints/protocol")
        elif self.kind is ScopeKind.HOST:
            if "datapath_id" not in values or not {
                "host_id",
                "src_ip",
                "dst_ip",
                "src_mac",
                "dst_mac",
                "in_port",
            }.intersection(values):
                raise ValueError("host scope requires datapath and an explicit host selector")
        elif self.kind is ScopeKind.SCENARIO_FIXTURE:
            if not {"scenario_id", "fixture_id"}.issubset(values):
                raise ValueError("fixture scope requires scenario_id and fixture_id")

    @classmethod
    def from_mapping(cls, kind: ScopeKind, selectors: Mapping[str, str | int]) -> MitigationScope:
        """Build a canonical selector tuple from a mapping."""

        return cls(kind, tuple(sorted(selectors.items())))

    def overlaps(self, other: MitigationScope) -> bool:
        """Return true unless a shared selector proves the scopes disjoint."""

        left = dict(self.selectors)
        right = dict(other.selectors)
        return not any(key in right and right[key] != value for key, value in left.items())


@dataclass(frozen=True, slots=True)
class DetectionResult:
    """Detector-only output; it cannot carry or execute a mitigation action."""

    event_id: str
    classification: Classification
    confidence: float | None
    attack_score: float | None
    observed_at: datetime
    provenance: str
    model_id: str | None = None
    novelty_score: float | None = None
    novelty_state: Classification | None = None
    shift_state: ShiftState = ShiftState.UNAVAILABLE
    shift_window_id: str | None = None
    evidence: tuple[EvidenceItem, ...] = ()
    scope: MitigationScope | None = None
    persistence_count: int | None = None

    def __post_init__(self) -> None:
        if not self.event_id or not self.provenance:
            raise ValueError("event_id and provenance must be non-empty")
        _require_aware(self.observed_at, "detection observed_at")
        if self.confidence is not None and (
            not math.isfinite(self.confidence) or not 0.0 <= self.confidence <= 1.0
        ):
            raise ValueError("confidence must be finite and within [0, 1]")
        if self.attack_score is not None and (
            not math.isfinite(self.attack_score) or not 0.0 <= self.attack_score <= 1.0
        ):
            raise ValueError("attack_score must be finite and within [0, 1]")
        if self.novelty_score is not None and not math.isfinite(self.novelty_score):
            raise ValueError("novelty_score must be finite")
        if self.persistence_count is not None and self.persistence_count < 1:
            raise ValueError("persistence_count must be positive when provided")


@dataclass(frozen=True, slots=True)
class ConfidenceThresholds:
    """Validation-fitted cutoffs; absent cutoffs mean no action at that tier."""

    tau_rate: float | None
    tau_quarantine: float | None
    tau_block: float | None
    calibration_id: str

    def __post_init__(self) -> None:
        if not self.calibration_id:
            raise ValueError("calibration_id is required")
        values = (self.tau_rate, self.tau_quarantine, self.tau_block)
        if any(
            value is not None and (not math.isfinite(value) or not 0 <= value <= 1)
            for value in values
        ):
            raise ValueError("thresholds must be finite values within [0, 1]")
        if self.tau_rate is None and any(value is not None for value in values[1:]):
            raise ValueError("higher action thresholds require tau_rate")
        if self.tau_quarantine is None and self.tau_block is not None:
            raise ValueError("tau_block requires tau_quarantine")
        ordered = [value for value in values if value is not None]
        if ordered != sorted(ordered):
            raise ValueError("action thresholds must be nondecreasing by severity")


@dataclass(frozen=True, slots=True)
class AdapterCapabilities:
    """Actions and scope kinds verified by a particular adapter configuration."""

    action_scopes: tuple[tuple[ActionType, tuple[ScopeKind, ...]], ...]
    unsupported_selectors: tuple[str, ...] = ()

    def supports(self, action: ActionType, scope: MitigationScope | None) -> bool:
        if action is ActionType.MONITOR:
            return True
        if scope is None:
            return False
        supported = dict(self.action_scopes).get(action, ())
        names = {name for name, _ in scope.selectors}
        return scope.kind in supported and not names.intersection(self.unsupported_selectors)


@dataclass(frozen=True, slots=True)
class RiskDecision:
    """Policy decision separate from detector output and adapter execution."""

    decision_id: str
    result_id: str
    risk_level: RiskLevel
    action: ActionType
    reason: str
    evidence_refs: tuple[str, ...]
    policy_version: str
    decided_at: datetime
    uncertain: bool
    scope: MitigationScope | None
    policy_arm: str | None = None

    def __post_init__(self) -> None:
        if not all((self.decision_id, self.result_id, self.reason, self.policy_version)):
            raise ValueError("decision identifiers, reason, and policy version are required")
        if self.policy_arm is not None and not self.policy_arm:
            raise ValueError("policy arm must be non-empty when provided")
        _require_aware(self.decided_at, "decision timestamp")
        if (self.uncertain or self.risk_level is RiskLevel.UNCERTAIN) and self.action not in (
            ActionType.MONITOR,
            ActionType.RATE_LIMIT,
        ):
            raise ValueError("uncertain decisions cannot quarantine or block")


@dataclass(frozen=True, slots=True)
class MitigationAction:
    """Immutable action request with exact scope and bounded TTL metadata."""

    action_id: str
    action: ActionType
    scope: MitigationScope
    created_at: datetime
    expires_at: datetime
    ttl_seconds: int
    reason: str
    evidence_refs: tuple[str, ...]
    policy_version: str
    decision_id: str
    extension_count: int = 0
    rollback_state: RollbackState = RollbackState.PROPOSED

    def __post_init__(self) -> None:
        if self.action is ActionType.MONITOR:
            raise ValueError("MONITOR does not create a mitigation action")
        if not all((self.action_id, self.reason, self.policy_version, self.decision_id)):
            raise ValueError("action identifiers and reason are required")
        _require_aware(self.created_at, "action created_at")
        _require_aware(self.expires_at, "action expires_at")
        if self.ttl_seconds <= 0:
            raise ValueError("TTL must be positive")
        expected_lifetime = self.ttl_seconds * (1 + self.extension_count)
        if (self.expires_at - self.created_at).total_seconds() != expected_lifetime:
            raise ValueError("expiry must match the original TTL and extension count")
        if self.extension_count not in (0, 1):
            raise ValueError("at most one conditional extension is allowed")


@dataclass(frozen=True, slots=True)
class AdapterResult:
    """Explicit adapter outcome; success requires action/rule correlation."""

    action_id: str
    status: AdapterStatus
    reason: str
    rule_cookie: int | None = None

    def __post_init__(self) -> None:
        if not self.action_id or not self.reason:
            raise ValueError("adapter result requires action ID and reason")
        if self.status is AdapterStatus.SUCCESS and self.rule_cookie is None:
            raise ValueError("successful dangerous action must identify its rule cookie")


@dataclass(frozen=True, slots=True)
class EnforcementEvent:
    """Auditable adapter submission or independently observed switch outcome."""

    event_id: str
    action_id: str
    decision_id: str
    timestamp: datetime
    status: EnforcementStatus
    datapath_id: int
    rule_cookie: int | None
    exact_scope: MitigationScope
    reason: str
    confirmation_timestamp: datetime | None = None
    latency_ms: float | None = None
    observed_present: bool | None = None

    def __post_init__(self) -> None:
        _require_aware(self.timestamp, "enforcement event timestamp")
        if self.confirmation_timestamp is not None:
            _require_aware(self.confirmation_timestamp, "confirmation timestamp")
        if self.latency_ms is not None and (
            not math.isfinite(self.latency_ms) or self.latency_ms < 0
        ):
            raise ValueError("enforcement latency must be finite and non-negative")
        if not all((self.event_id, self.action_id, self.decision_id, self.reason)):
            raise ValueError("enforcement event identifiers and reason are required")
        if self.status is EnforcementStatus.CONFIRMED and (
            self.confirmation_timestamp is None or self.observed_present is not True
        ):
            raise ValueError("CONFIRMED requires an observed switch state and timestamp")
        if self.status is EnforcementStatus.ROLLED_BACK and (
            self.confirmation_timestamp is None or self.observed_present is not False
        ):
            raise ValueError("ROLLED_BACK requires an observed rule absence and timestamp")

    def to_dict(self) -> dict[str, object]:
        """Serialize actual enforcement observations without implying ACK semantics."""

        return {
            "event_id": self.event_id,
            "action_id": self.action_id,
            "decision_id": self.decision_id,
            "timestamp": self.timestamp.isoformat(),
            "status": self.status.value,
            "datapath_id": f"{self.datapath_id:016x}",
            "rule_cookie": None if self.rule_cookie is None else f"0x{self.rule_cookie:x}",
            "exact_scope": {
                "kind": self.exact_scope.kind.value,
                "selectors": dict(self.exact_scope.selectors),
            },
            "reason": self.reason,
            "confirmation_timestamp": None
            if self.confirmation_timestamp is None
            else self.confirmation_timestamp.isoformat(),
            "latency_ms": self.latency_ms,
            "observed_present": self.observed_present,
        }


@dataclass(frozen=True, slots=True)
class DefenseAuditEvent:
    """Structured event for reconstructing result-to-action lifecycle."""

    event_id: str
    timestamp: datetime
    event_type: str
    decision_id: str
    action_id: str | None
    action: ActionType
    scope: MitigationScope | None
    reason: str
    policy_version: str
    adapter_status: AdapterStatus | None
    ttl_seconds: int | None
    rollback_state: RollbackState | None
    rule_cookie: int | None = None
    result_id: str | None = None
    classification: Classification | None = None
    confidence: float | None = None
    attack_score: float | None = None
    novelty_score: float | None = None
    shift_state: ShiftState | None = None
    risk_level: RiskLevel | None = None
    provenance: str | None = None
    policy_arm: str | None = None
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_aware(self.timestamp, "audit timestamp")
        if not all((self.event_id, self.event_type, self.decision_id, self.reason)):
            raise ValueError("audit event identity and reason are required")
        if self.confidence is not None and (
            not math.isfinite(self.confidence) or not 0 <= self.confidence <= 1
        ):
            raise ValueError("audit confidence must be finite and within [0, 1]")
        if self.attack_score is not None and (
            not math.isfinite(self.attack_score) or not 0 <= self.attack_score <= 1
        ):
            raise ValueError("audit attack score must be finite and within [0, 1]")
        if self.novelty_score is not None and not math.isfinite(self.novelty_score):
            raise ValueError("audit novelty score must be finite")

    def to_dict(self) -> dict[str, object]:
        """Return JSON-compatible event data without inventing detector scores."""

        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "decision_id": self.decision_id,
            "action_id": self.action_id,
            "action": self.action.value,
            "scope": None
            if self.scope is None
            else {"kind": self.scope.kind.value, "selectors": dict(self.scope.selectors)},
            "reason": self.reason,
            "policy_version": self.policy_version,
            "adapter_status": None if self.adapter_status is None else self.adapter_status.value,
            "ttl_seconds": self.ttl_seconds,
            "rollback_state": None if self.rollback_state is None else self.rollback_state.value,
            "rule_cookie": self.rule_cookie,
            "result_id": self.result_id,
            "classification": None if self.classification is None else self.classification.value,
            "confidence": self.confidence,
            "attack_score": self.attack_score,
            "novelty_score": self.novelty_score,
            "shift_state": None if self.shift_state is None else self.shift_state.value,
            "risk_level": None if self.risk_level is None else self.risk_level.value,
            "provenance": self.provenance,
            "policy_arm": self.policy_arm,
            "evidence_refs": list(self.evidence_refs),
        }


class DetectionPort(Protocol):
    """Boundary for a detector that reports evidence but never selects actions."""

    def assess(self, event_id: str, features: Mapping[str, float]) -> DetectionResult:
        """Return a typed detection result without applying mitigation."""


class MitigationPort(Protocol):
    """Legacy boundary retained for callers using the Stage 1 decision envelope."""

    def apply(self, decision: DecisionRecord) -> None:
        """Apply a policy-approved action through an external adapter."""

    def rollback(self, event_id: str) -> None:
        """Reverse a previously applied action through an external adapter."""


class MitigationAdapter(Protocol):
    """Stage 7 adapter boundary for policy-approved, exact-scope actions."""

    @property
    def capabilities(self) -> AdapterCapabilities:
        """Return only capabilities verified for this adapter configuration."""

    def apply(self, action: MitigationAction) -> AdapterResult:
        """Apply one bounded action and report an explicit outcome."""

    def rollback(self, action_id: str) -> AdapterResult:
        """Remove only the exact rule correlated with this action ID."""


def _require_aware(value: datetime, name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")
