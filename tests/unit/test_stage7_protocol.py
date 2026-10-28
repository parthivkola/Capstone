"""Structural checks for the frozen Stage 7 research protocol."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

PROTOCOL_PATH = Path("experiments/stage7/defense-protocol.json")


def _protocol() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(PROTOCOL_PATH.read_text(encoding="utf-8")))


def test_protocol_is_design_only_and_keeps_graphsage_deferred() -> None:
    protocol = _protocol()

    assert protocol["status"] == "frozen_protocol_design_implementation_not_started"
    assert protocol["stage6"]["graphsage"] == "deferred"
    assert protocol["readiness"]["end_to_end_defense_evaluation_ready"] is False


def test_detection_decision_and_execution_are_separate() -> None:
    protocol = _protocol()
    separation = protocol["result_separation"]

    assert separation["detection_states"] == ["BENIGN", "ATTACK", "UNKNOWN"]
    assert separation["policy_abstention_state"] == "UNCERTAIN"
    assert separation["detector_may_execute_action"] is False
    assert separation["risk_states"] == ["LOW", "MEDIUM", "HIGH", "VERY_HIGH"]
    assert separation["actions"] == ["MONITOR", "RATE_LIMIT", "QUARANTINE", "BLOCK"]


def test_all_four_policy_baselines_are_defined() -> None:
    policies = _protocol()["policies"]

    assert set(policies) == {
        "A_always_block",
        "B_confidence",
        "C_risk_aware",
        "D_risk_aware_reversible",
    }
    assert "immediate exact-scope BLOCK" in policies["A_always_block"]
    assert "frozen risk_policy" in policies["C_risk_aware"]
    assert "midpoint re-evaluation" in policies["D_risk_aware_reversible"]


def test_uncertainty_and_context_cannot_escalate_without_limits() -> None:
    protocol = _protocol()
    risk = protocol["risk_policy"]

    assert risk["uncertain_maximum"].startswith("MEDIUM")
    assert risk["novelty_alone_maximum"] == "MEDIUM"
    assert risk["psi_alone_action"] == "MONITOR; PSI may enter adaptation gate only"
    assert risk["protected_flow"] == (
        "h1<->h3 is never disrupted; matching protected flow forces MONITOR"
    )
    assert risk["missing_exact_action_scope"] == "MONITOR"


def test_thresholds_are_calibrated_without_final_test_access() -> None:
    protocol = _protocol()
    calibration = protocol["threshold_calibration"]

    assert calibration["data"] == "disjoint validation/calibration partition only"
    assert calibration["test_data_may_select_threshold"] is False
    assert calibration["freeze_before_final_test"] is True
    assert calibration["benign_action_rate_upper_bounds"] == {
        "RATE_LIMIT": 0.05,
        "QUARANTINE": 0.01,
        "BLOCK": 0.001,
    }


def test_mitigation_is_bounded_reversible_and_scoped() -> None:
    lifecycle = _protocol()["mitigation_lifecycle"]

    assert lifecycle["ttl_seconds"] == {"RATE_LIMIT": 30, "QUARANTINE": 15, "BLOCK": 10}
    assert lifecycle["maximum_extensions"] == 1
    assert lifecycle["maximum_total_duration_multiplier"] == 2
    assert "TTL expiry" in lifecycle["rollback_on"]
    assert "no escalation or scope broadening" in lifecycle["install_failure"]
    assert "never flush unrelated flows" in lifecycle["rollback_failure"]


def test_adaptation_gate_keeps_shift_separate_from_update_and_labels() -> None:
    gate = _protocol()["adaptation_gate"]

    assert gate["psi_alone_authorizes_update"] is False
    assert gate["buffer_max_rows"] == 100000
    assert gate["sealed_anchor_used_for_fit"] is False
    assert "current-window labels cannot trigger or fit" in gate["label_delay"]
    assert gate["decision_states"] == ["HOLD", "UPDATE"]
    assert gate["candidate_rollback"].startswith("reject if anchor")


def test_metrics_and_cost_protocol_are_present() -> None:
    evaluation = _protocol()["evaluation"]
    metrics = _protocol()["metrics"]

    assert len(evaluation["scenarios"]) == 6
    assert metrics["detection_primary"] == [
        "macro_f1",
        "per_class_f1",
        "benign_fpr",
        "attack_fnr_as_benign",
    ]
    assert "attack_containment_rate" in metrics["defense"]
    assert "cpu" in metrics["resources"]
    assert metrics["utility"].startswith("multi-objective")


def test_frozen_stages_and_datasets_are_read_only_by_protocol() -> None:
    protocol = _protocol()
    reproducibility = protocol["reproducibility"]

    assert reproducibility["stage5_artifacts_mutable"] is False
    assert reproducibility["stage6_graphsage"] is False
    assert reproducibility["raw_or_prepared_data_mutable"] is False
    assert reproducibility["final_test_leakage_allowed"] is False
