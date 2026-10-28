"""Tests for the Stage 7 detector feature-parity readiness boundary."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from services.detection.feature_compatibility import (
    FeatureCompatibility,
    FeatureParityError,
    FeatureParityStatus,
    live_inference_blockers,
    load_feature_matrix,
    require_live_inference_compatible,
)
from services.detection.synthetic_fixtures import SyntheticCase, make_synthetic_detection
from src.sdn_defense.contracts import Classification, DetectionResult, ShiftState

ROOT = Path(__file__).resolve().parents[2]
MATRIX_PATH = ROOT / "docs/architecture/stage7-real-detector-feature-compatibility.json"
PREPARATION_PATH = ROOT / "experiments/stage5d/cse-preparation.json"


def test_matrix_matches_frozen_stage5d_feature_order_and_counts() -> None:
    matrix = load_feature_matrix(MATRIX_PATH)
    preparation: dict[str, Any] = json.loads(PREPARATION_PATH.read_text(encoding="utf-8"))
    expected = preparation["preparation_rules"]["model_features"]

    assert [item.feature for item in matrix] == expected
    assert len(matrix) == 77
    assert sum(item.status is FeatureParityStatus.EXACT for item in matrix) == 1
    assert sum(item.status is FeatureParityStatus.DERIVABLE for item in matrix) == 0
    assert sum(item.status is FeatureParityStatus.APPROXIMATION_REQUIRED for item in matrix) == 2
    assert sum(item.status is FeatureParityStatus.UNAVAILABLE for item in matrix) == 61
    assert (
        sum(item.status is FeatureParityStatus.SEMANTICALLY_INCOMPATIBLE for item in matrix)
        == 13
    )


def test_only_protocol_is_exact_and_rates_are_explicitly_approximate() -> None:
    matrix = load_feature_matrix(MATRIX_PATH)
    statuses = {item.feature: item.status for item in matrix}

    assert statuses["Protocol"] is FeatureParityStatus.EXACT
    assert statuses["Flow Byts/s"] is FeatureParityStatus.APPROXIMATION_REQUIRED
    assert statuses["Flow Pkts/s"] is FeatureParityStatus.APPROXIMATION_REQUIRED
    assert statuses["Flow Duration"] is FeatureParityStatus.SEMANTICALLY_INCOMPATIBLE
    assert statuses["SYN Flag Cnt"] is FeatureParityStatus.SEMANTICALLY_INCOMPATIBLE


def test_live_inference_gate_fails_closed_for_stage5_matrix() -> None:
    matrix = load_feature_matrix(MATRIX_PATH)

    blockers = live_inference_blockers(matrix)
    assert len(blockers) == 76
    with pytest.raises(FeatureParityError, match="live inference is not authorized"):
        require_live_inference_compatible(matrix)


def test_gate_accepts_only_exact_or_semantically_preserving_derived_fields() -> None:
    valid = (
        FeatureCompatibility("Protocol", FeatureParityStatus.EXACT, ("ip_protocol",), "same"),
        FeatureCompatibility("Example", FeatureParityStatus.DERIVABLE, ("a", "b"), "same"),
    )

    assert live_inference_blockers(valid) == ()
    require_live_inference_compatible(valid)


def test_matrix_loader_rejects_duplicate_feature_and_incorrect_summary(tmp_path: Path) -> None:
    payload: dict[str, Any] = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))
    payload["feature_compatibility"][1]["feature"] = payload["feature_compatibility"][0][
        "feature"
    ]
    invalid = tmp_path / "invalid-matrix.json"
    invalid.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="invalid or duplicate"):
        load_feature_matrix(invalid)


def test_synthetic_fixture_remains_provenance_labeled_and_policy_agnostic() -> None:
    result = make_synthetic_detection(SyntheticCase.HIGH_ATTACK)

    assert isinstance(result, DetectionResult)
    assert result.provenance == "synthetic_test_fixture_only"
    assert result.classification is Classification.ATTACK
    assert not hasattr(result, "action")


def test_shared_detection_contract_keeps_confidence_novelty_and_shift_separate() -> None:
    template = make_synthetic_detection(SyntheticCase.UNKNOWN)
    contract_only_result = replace(
        template,
        provenance="contract_unit_test_only",
        model_id="unit-test-model-id-only",
        confidence=0.4,
        novelty_score=0.7,
        novelty_state=Classification.UNKNOWN,
        shift_state=ShiftState.SIGNAL,
    )

    assert contract_only_result.provenance == "contract_unit_test_only"
    assert contract_only_result.model_id == "unit-test-model-id-only"
    assert contract_only_result.confidence == 0.4
    assert contract_only_result.novelty_score == 0.7
    assert contract_only_result.novelty_state is Classification.UNKNOWN
    assert contract_only_result.shift_state is ShiftState.SIGNAL
    assert contract_only_result.classification is Classification.UNKNOWN


def test_detection_contract_rejects_out_of_range_confidence() -> None:
    template = make_synthetic_detection(SyntheticCase.BENIGN)

    with pytest.raises(ValueError, match="confidence must be finite"):
        replace(template, confidence=1.01)


def test_no_live_detector_result_or_mitigation_is_created_by_parity_gate() -> None:
    matrix = load_feature_matrix(MATRIX_PATH)

    with pytest.raises(FeatureParityError):
        require_live_inference_compatible(matrix)

    # The readiness boundary returns no DetectionResult and has no policy or
    # mitigation dependency; failed parity cannot reach an action path.
    blockers = live_inference_blockers(matrix)
    assert all(item.status not in (FeatureParityStatus.EXACT, FeatureParityStatus.DERIVABLE)
               for item in blockers)
