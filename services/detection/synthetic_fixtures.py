"""Deterministic synthetic Stage 7 detections for integration validation only.

These fixtures do not come from Random Forest, Stage 5 data, packet capture, or
the Mininet traffic generator. They exercise policy contracts, not detection.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from src.sdn_defense.contracts import (
    Classification,
    DetectionResult,
    EvidenceItem,
    MitigationScope,
    ScopeKind,
    ShiftState,
)


class SyntheticCase(StrEnum):
    BENIGN = "benign"
    LOW_ATTACK = "low_attack"
    MEDIUM_ATTACK = "medium_attack"
    HIGH_ATTACK = "high_attack"
    VERY_HIGH_ATTACK = "very_high_attack"
    UNKNOWN = "unknown"
    UNCERTAIN = "uncertain"


SYNTHETIC_TIME = datetime(2026, 10, 8, 12, 0, tzinfo=UTC)
SYNTHETIC_POLICY_THRESHOLDS = (0.2, 0.5, 0.8)


def make_synthetic_detection(
    case: SyntheticCase,
    *,
    event_id: str | None = None,
    observed_at: datetime = SYNTHETIC_TIME,
    datapath_id: str | None = "0000000000000001",
    destination_port: int = 18081,
    include_scope: bool = True,
) -> DetectionResult:
    """Create a reproducible, explicitly synthetic exact-UDP-flow observation."""

    scope = (
        MitigationScope.from_mapping(
            ScopeKind.TUPLE,
            {
                "datapath_id": datapath_id or "",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "ip_protocol": 17,
                "dst_port": destination_port,
            },
        )
        if include_scope and datapath_id is not None
        else None
    )
    classification, score, confidence, persistent, evidence = {
        SyntheticCase.BENIGN: (Classification.BENIGN, 0.01, 0.99, None, False),
        SyntheticCase.LOW_ATTACK: (Classification.ATTACK, 0.1, 0.9, None, False),
        SyntheticCase.MEDIUM_ATTACK: (Classification.ATTACK, 0.3, 0.7, None, False),
        SyntheticCase.HIGH_ATTACK: (Classification.ATTACK, 0.6, 0.9, None, True),
        SyntheticCase.VERY_HIGH_ATTACK: (Classification.ATTACK, 0.9, 0.99, 2, True),
        SyntheticCase.UNKNOWN: (Classification.UNKNOWN, None, None, None, False),
        SyntheticCase.UNCERTAIN: (Classification.ATTACK, None, None, None, False),
    }[case]
    evidence_items = (
        (
            EvidenceItem(
                evidence_id=f"{event_id or 'synthetic-' + case.value}:corroboration",
                source="synthetic_fixture_corroboration",
                name="bounded_observation_count",
                value=2,
                observed_at=observed_at,
            ),
        )
        if evidence
        else ()
    )
    return DetectionResult(
        event_id=event_id or f"synthetic-{case.value}",
        classification=classification,
        confidence=confidence,
        attack_score=score,
        observed_at=observed_at,
        provenance="synthetic_test_fixture_only",
        model_id=None,
        shift_state=ShiftState.NO_SIGNAL,
        evidence=evidence_items,
        scope=scope,
        persistence_count=persistent,
    )
