from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[2]
PROTOCOL_PATH = ROOT / "experiments/stage5f/drift-adaptation-protocol.json"
PREPARATION_PATH = ROOT / "experiments/stage5d/cse-preparation.json"
STAGE5D_RESULTS_PATH = ROOT / "experiments/stage5d/cse-source-holdout-rf.json"


def _load(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def test_protocol_source_hashes_and_feature_schema_match_frozen_stage5d() -> None:
    protocol = _load(PROTOCOL_PATH)
    preparation = _load(PREPARATION_PATH)
    expected = {item["file"]: item for item in preparation["source_statistics"]}
    sources = protocol["frozen_inputs"]["sources"]

    assert len(sources) == 7
    assert protocol["frozen_inputs"]["feature_count"] == 77
    for source in sources:
        frozen = expected[source["file"]]
        assert source["raw_sha256"] == frozen["sha256"]
        assert source["prepared_sha256"] == frozen["output_sha256"]
        assert source["prepared_rows"] == frozen["final_usable_row_count"]
        assert source["prepared_path"].startswith("data/processed/")
    assert (
        protocol["frozen_inputs"]["ordered_model_features"]
        == expected[sources[0]["file"]]["feature_names"]
    )


def test_source_roles_are_disjoint_and_order_is_not_claimed_as_time() -> None:
    protocol = _load(PROTOCOL_PATH)
    design = protocol["source_and_window_design"]
    initial = set(design["initial_training_sources"])
    windows = design["sequential_evaluation_windows"]
    evaluated = [window["source_file"] for window in windows]
    assert len(initial) == 3
    assert len(evaluated) == 4
    assert not initial.intersection(evaluated)
    assert len(set(evaluated)) == len(evaluated)
    manifest_sources = protocol["frozen_inputs"]["sources"]
    remaining_in_manifest_order = [
        source["file"] for source in manifest_sources if source["file"] not in initial
    ]
    assert evaluated == remaining_in_manifest_order
    assert protocol["study_claim"]["temporal_order_supported"] is False
    assert protocol["study_claim"]["concept_drift_claim_allowed"] is False
    assert all(
        window["order_basis"].endswith("not timestamp or filename chronology") for window in windows
    )


def test_task_and_rf_configuration_are_frozen_and_consistent() -> None:
    protocol = _load(PROTOCOL_PATH)
    stage5d = _load(STAGE5D_RESULTS_PATH)
    expected_rf = stage5d["holdouts"][0]["model"]
    model = protocol["model"]
    assert model["architecture"] == "sklearn RandomForestClassifier for all strategies"
    assert model["parameters"] == {
        **{
            key: value
            for key, value in expected_rf.items()
            if key != "name" and key != "random_state"
        },
        "random_state": "run_seed",
    }
    assert model["parameters"]["random_state"] == "run_seed"
    assert model["seeds"] == [2026, 2027, 2028, 2029, 2030]
    assert protocol["task_definition"]["label_mapping"] == {
        "Benign": "Benign",
        "every_other_frozen_source_label": "Attack",
    }
    assert protocol["task_definition"]["label_vocabulary"] == ["Benign", "Attack"]


def test_strategy_rules_and_adaptation_buffer_obey_leakage_bounds() -> None:
    protocol = _load(PROTOCOL_PATH)
    strategies = protocol["strategies"]
    assert set(strategies) == {"static", "periodic", "drift_triggered"}
    assert "never update" in strategies["static"]["rule"]
    assert "independently of drift output" in strategies["periodic"]["rule"]
    assert "current-window X only" in strategies["drift_triggered"]["rule"]

    adaptation = protocol["adaptation"]
    buffer = adaptation["fit_buffer"]
    assert buffer["maximum_total_rows"] == 100000
    assert "current or future" in adaptation["labels_forbidden"]
    assert "at most one model rebuild at a boundary" in adaptation["frequency_limit"]
    assert "no terminal update" in adaptation["frequency_limit"]
    replay_rows_cap = 2 * buffer["initial_replay_rows_per_class"]
    recent_rows_cap = (
        2 * buffer["recent_rows_per_class_per_window"] * buffer["maximum_recent_windows"]
    )
    assert replay_rows_cap + recent_rows_cap == buffer["maximum_total_rows"]


def test_psi_rule_and_metrics_are_preregistered() -> None:
    protocol = _load(PROTOCOL_PATH)
    detector = protocol["drift_detector"]
    assert detector["name"] == "Population Stability Index (PSI)"
    assert detector["per_feature_threshold"] == 0.2
    assert detector["window_trigger"] == (
        "trigger when at least 5 of 77 monitored features have PSI >= 0.20 "
        "in the same comparison window"
    )
    assert detector["minimum_sample_size"] == {
        "reference_rows": 50000,
        "comparison_rows": 10000,
    }
    metrics = protocol["evaluation"]
    assert metrics["primary_metrics"] == [
        "macro_f1",
        "per_class_f1",
        "benign_fpr",
        "attack_fnr_as_benign",
    ]
    assert "fixed_forgetting_anchor_after_each_update" in metrics["required_phases"]
    assert protocol["implementation_boundary"].startswith("Protocol only.")
