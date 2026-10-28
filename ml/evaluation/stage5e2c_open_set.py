"""Confidence-based open-set rejection using the frozen CSE Random Forest."""

from __future__ import annotations

import csv
import gzip
import hashlib
import json
import time
from collections import Counter
from collections.abc import Iterator
from itertools import islice
from pathlib import Path
from typing import Any, cast

import numpy as np
from sklearn.ensemble import RandomForestClassifier

from ml.evaluation.stage5d_cse import EXPECTED_FEATURE_COUNT, SEED, _peak_rss_bytes, preflight
from ml.evaluation.stage5e2a_cse import TEST_SOURCE, UNSEEN_LABEL
from ml.evaluation.stage5e2b_novelty import (
    BENIGN_LABEL,
    OPERATING_POINTS,
    validation_positions,
)
from ml.evaluation.stage5e2b_novelty import (
    verify_preflight as verify_prepared_artifacts,
)

PRIMARY_OPERATING_POINT = 0.01
VALIDATION_FRACTION = 0.20
CHUNK_ROWS = 50_000
RF_CONFIGURATION: dict[str, Any] = {
    "name": "RandomForestClassifier",
    "n_estimators": 100,
    "max_depth": 18,
    "max_features": "sqrt",
    "min_samples_leaf": 2,
    "class_weight": "balanced_subsample",
    "random_state": SEED,
    "n_jobs": 1,
}


def verify_rf_configuration(result_path: Path) -> dict[str, Any]:
    """Confirm the frozen Stage 5D runs used the exact required RF configuration."""
    with result_path.open(encoding="utf-8") as stream:
        prior = cast(dict[str, Any], json.load(stream))
    models = [holdout["model"] for holdout in prior["holdouts"]]
    if not models or any(model != RF_CONFIGURATION for model in models):
        raise ValueError("frozen Stage 5D RF configuration differs from Stage 5E.2C")
    return {
        "passed": True,
        "source_artifact": "experiments/stage5d/cse-source-holdout-rf.json",
        "configuration": dict(RF_CONFIGURATION),
    }


def verify_stage_preflight(
    root: Path, integrity: dict[str, Any], manifest: dict[str, Any]
) -> dict[str, Any]:
    """Check frozen data, source partition, model config, and test isolation."""
    data_checks = verify_prepared_artifacts(integrity, manifest)
    model_check = verify_rf_configuration(root / "experiments/stage5d/cse-source-holdout-rf.json")
    train_names = [item["file"] for item in data_checks["training_sources"]]
    train_vocabulary = sorted(
        {
            label
            for item in manifest["source_statistics"]
            if item["file"] in train_names
            for label in item["class_counts"]
        }
    )
    if TEST_SOURCE in train_names:
        raise ValueError("Tuesday test source is present in training sources")
    if UNSEEN_LABEL in train_vocabulary:
        raise ValueError("LOIC-HTTP occurs in the training label vocabulary")
    if data_checks["feature_count"] != EXPECTED_FEATURE_COUNT:
        raise ValueError("frozen predictor schema must have exactly 77 features")
    return {
        **data_checks,
        "training_sources_disjoint_from_tuesday": True,
        "training_label_vocabulary": train_vocabulary,
        "loic_http_absent_from_training_labels": True,
        "rf_configuration": model_check,
        "preprocessing_check": {
            "passed": True,
            "feature_conversion": "fixed CSV numeric text to float32",
            "fitted_preprocessing": "none",
            "tuesday_used_for_preprocessing_fit": False,
        },
        "threshold_selection_input_check": {
            "passed": True,
            "selector_accepts_validation_benign_confidences_and_target_only": True,
            "tuesday_test_labels_are_not_an_input": True,
        },
    }


def select_confidence_threshold(
    benign_validation_confidences: np.ndarray, target_rejection_rate: float
) -> dict[str, Any]:
    """Select p_max cutoff from benign validation scores only.

    Decision direction is strict: p_max < threshold means UNKNOWN. Confidence
    ties form indivisible groups; equally close rejection counts choose fewer
    rejections. This function accepts no test rows or labels.
    """
    confidence = np.asarray(benign_validation_confidences, dtype=np.float64)
    if confidence.ndim != 1 or not len(confidence) or not np.isfinite(confidence).all():
        raise ValueError("benign validation confidences must be non-empty finite 1-D values")
    if np.any((confidence < 0) | (confidence > 1)):
        raise ValueError("Random Forest class confidences must be in [0, 1]")
    if not 0 < target_rejection_rate < 1:
        raise ValueError("target rejection rate must be between 0 and 1")
    ordered = np.sort(confidence)
    group_ends = np.concatenate(
        (np.flatnonzero(ordered[:-1] != ordered[1:]) + 1, np.asarray([len(ordered)]))
    )
    rejection_counts = np.concatenate((np.asarray([0]), group_ends))
    thresholds = np.concatenate(
        (np.asarray([ordered[0]]), np.nextafter(ordered[group_ends - 1], np.inf))
    )
    target_count = target_rejection_rate * len(ordered)
    differences = np.abs(rejection_counts - target_count)
    min_difference = differences.min()
    # Candidate counts are ascending, so first index resolves ties conservatively.
    selected_index = int(np.flatnonzero(differences == min_difference)[0])
    rejected = int(rejection_counts[selected_index])
    return {
        "target_benign_rejection_rate": target_rejection_rate,
        "threshold": float(thresholds[selected_index]),
        "validation_benign_rows": int(len(ordered)),
        "validation_benign_rejected_count": rejected,
        "validation_benign_rejection_rate": rejected / len(ordered),
        "decision_rule": "p_max < threshold -> UNKNOWN; otherwise keep RF predicted class",
        "tie_policy": (
            "confidence ties are indivisible; equally close counts choose fewer rejections"
        ),
    }


def apply_confidence_threshold(max_class_probability: np.ndarray, threshold: float) -> np.ndarray:
    """Mark low-confidence observations as UNKNOWN using the strict cutoff."""
    confidence = np.asarray(max_class_probability, dtype=np.float64)
    if not np.isfinite(confidence).all() or not np.isfinite(threshold):
        raise ValueError("confidence values and threshold must be finite")
    if np.any((confidence < 0) | (confidence > 1)):
        raise ValueError("Random Forest class confidences must be in [0, 1]")
    return confidence < threshold


def summarize_open_set_predictions(
    actual_labels: list[str],
    max_probabilities: np.ndarray,
    rf_predictions: list[str],
    thresholds: dict[str, dict[str, Any]],
    known_classes: list[str],
) -> dict[str, dict[str, Any]]:
    """Aggregate one chunk into binary metrics inputs and known-class counts."""
    if len(actual_labels) != len(rf_predictions) or len(actual_labels) != len(max_probabilities):
        raise ValueError("actual labels, probabilities, and RF outputs must have equal length")
    actual = np.asarray(actual_labels, dtype=object)
    benign_mask = actual == BENIGN_LABEL
    loic_mask = actual == UNSEEN_LABEL
    if not np.logical_or(benign_mask, loic_mask).all():
        raise ValueError("Tuesday test contains an unexpected label")
    predicted = np.asarray(rf_predictions, dtype=object)
    result: dict[str, dict[str, Any]] = {}
    for name, threshold_record in thresholds.items():
        unknown = apply_confidence_threshold(
            max_probabilities, float(threshold_record["threshold"])
        )
        loic_known_mask = loic_mask & ~unknown
        loic_distribution = Counter(predicted[loic_known_mask].tolist())
        result[name] = {
            "benign_known": int(np.count_nonzero(benign_mask & ~unknown)),
            "benign_unknown": int(np.count_nonzero(benign_mask & unknown)),
            "loic_known": int(np.count_nonzero(loic_known_mask)),
            "loic_unknown": int(np.count_nonzero(loic_mask & unknown)),
            "loic_predicted_known_class_distribution": {
                label: int(loic_distribution.get(label, 0)) for label in known_classes
            },
        }
    return result


def open_set_metrics(counts: dict[str, int]) -> dict[str, Any]:
    benign_known = counts["benign_known"]
    benign_unknown = counts["benign_unknown"]
    loic_known = counts["loic_known"]
    loic_unknown = counts["loic_unknown"]
    benign_total = benign_known + benign_unknown
    loic_total = loic_known + loic_unknown
    unknown_total = benign_unknown + loic_unknown
    benign_rejection = benign_unknown / benign_total if benign_total else 0.0
    unknown_recall = loic_unknown / loic_total if loic_total else 0.0
    unknown_precision = loic_unknown / unknown_total if unknown_total else 0.0
    unknown_f1 = (
        2 * unknown_precision * unknown_recall / (unknown_precision + unknown_recall)
        if unknown_precision + unknown_recall
        else 0.0
    )
    benign_specificity = benign_known / benign_total if benign_total else 0.0
    return {
        "benign_test_rows": benign_total,
        "loic_http_test_rows": loic_total,
        "benign_known_count": benign_known,
        "benign_unknown_count": benign_unknown,
        "loic_http_known_count": loic_known,
        "loic_http_unknown_count": loic_unknown,
        "benign_rejection_rate_fpr": benign_rejection,
        "loic_http_unknown_recall": unknown_recall,
        "loic_http_known_rate": loic_known / loic_total if loic_total else 0.0,
        "unknown_precision": unknown_precision,
        "unknown_f1": unknown_f1,
        "balanced_accuracy": (benign_specificity + unknown_recall) / 2,
        "confusion_matrix_actual_rows_benign_then_loic_http_predicted_columns_known_then_unknown": [
            [benign_known, benign_unknown],
            [loic_known, loic_unknown],
        ],
    }


def _iter_prepared_rows(path: Path) -> Iterator[list[str]]:
    with gzip.open(path, "rt", encoding="utf-8", newline="") as stream:
        reader = csv.reader(stream)
        header = next(reader, None)
        if header is None or len(header) != EXPECTED_FEATURE_COUNT + 1 or header[-1] != "Label":
            raise ValueError(f"prepared feature schema changed after preflight: {path}")
        for row in reader:
            if len(row) != len(header):
                raise ValueError(f"invalid row width in prepared source: {path}")
            yield row


def _split_plan(
    source_stats: dict[str, dict[str, Any]], train_sources: list[dict[str, Any]]
) -> tuple[dict[str, dict[str, np.ndarray]], dict[str, Any]]:
    masks: dict[str, dict[str, np.ndarray]] = {}
    training_rows = 0
    validation_rows = 0
    validation_benign_rows = 0
    validation_attack_rows = 0
    per_source: list[dict[str, Any]] = []
    for source_order, source_info in enumerate(train_sources):
        name = source_info["file"]
        counts: dict[str, int] = source_stats[name]["class_counts"]
        masks[name] = {}
        source_validation = 0
        class_validation: dict[str, int] = {}
        position_hashes: dict[str, str] = {}
        for label, count_value in sorted(counts.items()):
            count = int(count_value)
            positions = validation_positions(
                count,
                seed=SEED,
                source_name=f"{name}\0{label}",
                fraction=VALIDATION_FRACTION,
            )
            mask = np.zeros(count, dtype=bool)
            mask[positions] = True
            masks[name][label] = mask
            selected = int(mask.sum())
            class_validation[label] = selected
            source_validation += selected
            position_hashes[label] = hashlib.sha256(positions.tobytes()).hexdigest()
        total = int(source_stats[name]["final_usable_row_count"])
        validation_rows += source_validation
        training_rows += total - source_validation
        benign_validation = class_validation.get(BENIGN_LABEL, 0)
        validation_benign_rows += benign_validation
        validation_attack_rows += source_validation - benign_validation
        per_source.append(
            {
                "file": name,
                "source_order": source_order,
                "source_rows": total,
                "training_rows": total - source_validation,
                "validation_rows": source_validation,
                "validation_class_counts": class_validation,
                "validation_row_ordinals_sha256_by_class": position_hashes,
            }
        )
    return masks, {
        "training_rows": training_rows,
        "validation_rows": validation_rows,
        "benign_validation_rows": validation_benign_rows,
        "attack_validation_rows_excluded_from_threshold_fitting": validation_attack_rows,
        "per_source": per_source,
    }


def _load_train_and_validation_benign(
    root: Path,
    source_stats: dict[str, dict[str, Any]],
    preflight_result: dict[str, Any],
    masks: dict[str, dict[str, np.ndarray]],
    split_summary: dict[str, Any],
    training_labels: list[str],
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    train_x = np.empty(
        (int(split_summary["training_rows"]), EXPECTED_FEATURE_COUNT), dtype=np.float32
    )
    train_y = np.empty(int(split_summary["training_rows"]), dtype=np.int8)
    validation_x = np.empty(
        (int(split_summary["benign_validation_rows"]), EXPECTED_FEATURE_COUNT), dtype=np.float32
    )
    codes = {label: code for code, label in enumerate(training_labels)}
    train_offset = 0
    validation_offset = 0
    for source_info in preflight_result["training_sources"]:
        name = source_info["file"]
        path = root / source_stats[name]["output_path"]
        ordinals = {label: 0 for label in masks[name]}
        observed_rows = 0
        for row in _iter_prepared_rows(path):
            observed_rows += 1
            label = row[-1]
            if label not in masks[name]:
                raise ValueError(f"unexpected training label {label!r} in {name}")
            ordinal = ordinals[label]
            ordinals[label] += 1
            values = np.asarray(row[:-1], dtype=np.float32)
            if masks[name][label][ordinal]:
                if label == BENIGN_LABEL:
                    validation_x[validation_offset] = values
                    validation_offset += 1
                continue
            train_x[train_offset] = values
            train_y[train_offset] = codes[label]
            train_offset += 1
        if observed_rows != int(source_stats[name]["final_usable_row_count"]):
            raise ValueError(f"prepared source row count changed: {name}")
        for label, count in source_stats[name]["class_counts"].items():
            if ordinals[label] != int(count):
                raise ValueError(f"prepared class support changed for {name}: {label}")
    if train_offset != len(train_y) or validation_offset != len(validation_x):
        raise ValueError("loaded train or validation rows differ from deterministic split plan")
    return train_x, train_y, validation_x


def _evaluate_tuesday_once(
    path: Path,
    model: RandomForestClassifier,
    train_labels: list[str],
    thresholds: dict[str, dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], int, float]:
    aggregate = {
        name: {
            "counts": {
                key: 0 for key in ("benign_known", "benign_unknown", "loic_known", "loic_unknown")
            },
            "loic_predicted_known_class_distribution": {label: 0 for label in train_labels},
        }
        for name in thresholds
    }
    rows_seen = 0
    inference_seconds = 0.0
    with gzip.open(path, "rt", encoding="utf-8", newline="") as stream:
        reader = csv.reader(stream)
        header = next(reader, None)
        if header is None or len(header) != EXPECTED_FEATURE_COUNT + 1 or header[-1] != "Label":
            raise ValueError("Tuesday prepared feature schema changed after preflight")
        while rows := list(islice(reader, CHUNK_ROWS)):
            if any(len(row) != len(header) for row in rows):
                raise ValueError("invalid row width in Tuesday prepared source")
            matrix = np.asarray([row[:-1] for row in rows], dtype=np.float32)
            actual_labels = [row[-1] for row in rows]
            started = time.perf_counter()
            probabilities = model.predict_proba(matrix)
            inference_seconds += time.perf_counter() - started
            p_max = probabilities.max(axis=1)
            class_codes = model.classes_[probabilities.argmax(axis=1)].astype(np.int64)
            prediction_names = [train_labels[int(code)] for code in class_codes]
            chunk_summary = summarize_open_set_predictions(
                actual_labels, p_max, prediction_names, thresholds, train_labels
            )
            for name, values in chunk_summary.items():
                for key in aggregate[name]["counts"]:
                    aggregate[name]["counts"][key] += values[key]
                for label, count in values["loic_predicted_known_class_distribution"].items():
                    aggregate[name]["loic_predicted_known_class_distribution"][label] += count
            rows_seen += len(rows)
    return aggregate, rows_seen, inference_seconds


def run_experiment(
    root: Path,
    integrity: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    preflight_result = verify_stage_preflight(root, integrity, manifest)
    source_stats = {item["file"]: item for item in manifest["source_statistics"]}
    masks, split_summary = _split_plan(source_stats, preflight_result["training_sources"])
    train_labels = preflight_result["training_label_vocabulary"]
    x_train, y_train, x_validation_benign = _load_train_and_validation_benign(
        root, source_stats, preflight_result, masks, split_summary, train_labels
    )
    model = RandomForestClassifier(
        n_estimators=RF_CONFIGURATION["n_estimators"],
        max_depth=RF_CONFIGURATION["max_depth"],
        max_features=RF_CONFIGURATION["max_features"],
        min_samples_leaf=RF_CONFIGURATION["min_samples_leaf"],
        class_weight=RF_CONFIGURATION["class_weight"],
        random_state=RF_CONFIGURATION["random_state"],
        n_jobs=RF_CONFIGURATION["n_jobs"],
    )
    started = time.perf_counter()
    model.fit(x_train, y_train)
    training_seconds = time.perf_counter() - started
    del x_train, y_train

    started = time.perf_counter()
    validation_probabilities = model.predict_proba(x_validation_benign)
    validation_inference_seconds = time.perf_counter() - started
    validation_confidences = validation_probabilities.max(axis=1)
    del validation_probabilities, x_validation_benign
    thresholds: dict[str, dict[str, Any]] = {}
    for operating_point in OPERATING_POINTS:
        name = f"{operating_point * 100:g}%"
        thresholds[name] = select_confidence_threshold(validation_confidences, operating_point)
    del validation_confidences

    test_path = root / source_stats[TEST_SOURCE]["output_path"]
    aggregate, test_rows, test_inference_seconds = _evaluate_tuesday_once(
        test_path, model, train_labels, thresholds
    )
    expected_test_rows = int(source_stats[TEST_SOURCE]["final_usable_row_count"])
    if test_rows != expected_test_rows:
        raise ValueError("Tuesday test row count differs from frozen preparation manifest")
    expected_test_labels = source_stats[TEST_SOURCE]["class_counts"]
    if set(expected_test_labels) != {BENIGN_LABEL, UNSEEN_LABEL}:
        raise ValueError("Tuesday source labels differ from frozen unseen-class condition")

    sensitivity: list[dict[str, Any]] = []
    for name, threshold in thresholds.items():
        data = aggregate[name]
        metrics = open_set_metrics(data["counts"])
        sensitivity.append(
            {
                "target_benign_rejection": name,
                "threshold": threshold["threshold"],
                "validation_benign_rejection": threshold["validation_benign_rejection_rate"],
                "test_benign_rejection": metrics["benign_rejection_rate_fpr"],
                "loic_http_unknown_recall": metrics["loic_http_unknown_recall"],
                "unknown_precision": metrics["unknown_precision"],
                "unknown_f1": metrics["unknown_f1"],
                "balanced_accuracy": metrics["balanced_accuracy"],
            }
        )
    primary_name = f"{PRIMARY_OPERATING_POINT * 100:g}%"
    primary = open_set_metrics(aggregate[primary_name]["counts"])
    primary["loic_http_predicted_known_class_distribution"] = aggregate[primary_name][
        "loic_predicted_known_class_distribution"
    ]
    train_source_names = [item["file"] for item in preflight_result["training_sources"]]
    train_source_attack_rows = sum(
        int(source_stats[name]["final_usable_row_count"])
        - int(source_stats[name]["class_counts"].get(BENIGN_LABEL, 0))
        for name in train_source_names
    )
    test_class_counts = {
        label: int(aggregate[primary_name]["counts"][key])
        + int(aggregate[primary_name]["counts"][unknown_key])
        for label, key, unknown_key in (
            (BENIGN_LABEL, "benign_known", "benign_unknown"),
            (UNSEEN_LABEL, "loic_known", "loic_unknown"),
        )
    }
    if test_class_counts != expected_test_labels:
        raise ValueError("Tuesday test label counts differ from frozen preparation manifest")
    return {
        "experiment_id": "CSE-5E2C-TUESDAY-LOIC-HTTP-RF-CONFIDENCE-OPEN-SET",
        "stage": "5E.2C",
        "research_question": (
            "Does RF max-probability confidence support explicit UNKNOWN rejection for held-out "
            "LOIC-HTTP at a controlled benign rejection rate?"
        ),
        "condition": (
            "empirical confidence-based open-set evaluation for one CSE source-held-out unseen "
            "class; not a general zero-day claim"
        ),
        "preflight": preflight_result,
        "model": dict(RF_CONFIGURATION),
        "feature_schema": {
            "count": preflight_result["feature_count"],
            "ordered_names": preflight_result["feature_names"],
            "dtype": preflight_result["feature_dtype"],
        },
        "preprocessing": {
            "configuration": (
                "frozen Stage 5D common ordered 77-feature schema; CSV numeric text cast to float32"
            ),
            "learned_preprocessing": "none",
            "tuesday_used_for_preprocessing_fit": False,
        },
        "validation_protocol": {
            "method": (
                "within each non-Tuesday source and each training class, deterministic exact "
                "20% row-ordinal sample without replacement; remaining rows fit RF"
            ),
            "seed": SEED,
            "fraction_per_source_class": VALIDATION_FRACTION,
            "validation_rows": split_summary["validation_rows"],
            "benign_validation_rows": split_summary["benign_validation_rows"],
            "attack_validation_rows_excluded_from_threshold_fitting": split_summary[
                "attack_validation_rows_excluded_from_threshold_fitting"
            ],
            "threshold_uses_only_benign_validation_p_max": True,
            "per_source_partition": split_summary["per_source"],
        },
        "training_rows": split_summary["training_rows"],
        "attack_rows_in_six_training_sources_excluded_from_threshold_fitting": (
            train_source_attack_rows
        ),
        "validation_attack_rows_excluded_from_training_and_threshold_fitting": split_summary[
            "attack_validation_rows_excluded_from_threshold_fitting"
        ],
        "test_source": TEST_SOURCE,
        "test_rows": test_rows,
        "test_evaluated_once_after_threshold_freeze": True,
        "test_labels_used_for_training_or_threshold_selection": False,
        "training_class_vocabulary": train_labels,
        "loic_http_absent_from_training_vocabulary": UNSEEN_LABEL not in train_labels,
        "score_and_decision": {
            "confidence": "p_max = maximum Random Forest class probability",
            "decision": "p_max < threshold -> UNKNOWN; otherwise retain RF argmax class",
            "low_confidence_interpretation": (
                "low confidence is tested as a rejection signal; it is not assumed to mean novelty"
            ),
        },
        "threshold_selection": {
            "primary_pre_registered_benign_rejection": PRIMARY_OPERATING_POINT,
            "method": (
                "select confidence group boundary nearest the requested benign validation "
                "rejection count; strict p_max < threshold rejects; ties choose fewer rejections"
            ),
            "thresholds": thresholds,
            "primary": thresholds[primary_name],
        },
        "primary_metrics": primary,
        "sensitivity": sensitivity,
        "test_class_distribution": test_class_counts,
        "training_seconds": training_seconds,
        "validation_inference_seconds_predict_proba_only": validation_inference_seconds,
        "test_inference_seconds_predict_proba_only": test_inference_seconds,
        "test_inference_seconds_per_row": test_inference_seconds / max(test_rows, 1),
        "peak_process_rss_bytes": _peak_rss_bytes(),
        "peak_memory_measurement": (
            "process peak RSS via getrusage; includes preflight and data loading"
        ),
        "comparisons": {
            "stage5e2a": {
                "condition": "closed-set RF without UNKNOWN output",
                "direct_accuracy_comparison": False,
            },
            "stage5e2b": {
                "condition": "benign-only Isolation Forest novelty baseline",
                "direct_accuracy_comparison": False,
            },
            "interpretation": (
                "Compare the targeted open-set rejection metrics only; do not claim broad "
                "superiority."
            ),
        },
        "reproducibility": {
            "seed": SEED,
            "source_hashes": [
                *preflight_result["training_sources"],
                preflight_result["test_source"],
            ],
            "software": {},
            "raw_datasets_modified": False,
            "prior_experiment_artifacts_modified": False,
        },
    }


def load_manifests(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    with (root / "experiments/stage5d/cse-preparation.json").open(encoding="utf-8") as stream:
        manifest = cast(dict[str, Any], json.load(stream))
    integrity = preflight(root)
    return integrity, manifest


def load_stage5e2a_context(root: Path) -> dict[str, Any]:
    with (root / "experiments/stage5e/cse-unseen-loic-http-closed-set-rf.json").open(
        encoding="utf-8"
    ) as stream:
        result = cast(dict[str, Any], json.load(stream))
    unseen = result["unseen_label"]
    total = int(unseen["test_flows"])
    benign_count = int(unseen["predicted_class_distribution"].get(BENIGN_LABEL, 0))
    return {
        "condition": "closed-set RF with no UNKNOWN output",
        "loic_http_test_flows": total,
        "all_flows_received_known_class_prediction": sum(
            unseen["predicted_class_distribution"].values()
        )
        == total,
        "loic_http_assigned_to_benign_count": benign_count,
        "loic_http_assigned_to_benign_rate": benign_count / total if total else 0.0,
        "known_class_distribution": unseen["predicted_class_distribution"],
        "comparison_scope": "contextual only; not direct accuracy comparison",
    }


def load_stage5e2b_context(root: Path) -> dict[str, Any]:
    with (root / "experiments/stage5e/cse-unseen-loic-http-isolation-forest.json").open(
        encoding="utf-8"
    ) as stream:
        result = cast(dict[str, Any], json.load(stream))
    return {
        "condition": "benign-only Isolation Forest novelty baseline",
        "primary_operating_point": result["threshold_selection"]["primary"]["target_benign_fpr"],
        "primary_benign_test_rejection_rate": result["primary_metrics"]["benign_fpr"],
        "primary_loic_http_unknown_recall": result["primary_metrics"]["loic_http_unknown_recall"],
        "comparison_scope": "contextual only; not direct accuracy comparison",
    }
