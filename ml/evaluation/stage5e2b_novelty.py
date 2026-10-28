"""Validation-calibrated Isolation Forest for the held-out CSE LOIC-HTTP source."""

from __future__ import annotations

import csv
import gzip
import hashlib
import json
import time
from collections.abc import Iterator
from itertools import islice
from pathlib import Path
from typing import Any, cast

import numpy as np
from sklearn.ensemble import IsolationForest

from ml.evaluation.stage5d_cse import EXPECTED_FEATURE_COUNT, SEED, _peak_rss_bytes
from ml.evaluation.stage5e2a_cse import TEST_SOURCE, UNSEEN_LABEL

BENIGN_LABEL = "Benign"
VALIDATION_FRACTION = 0.20
OPERATING_POINTS = (0.005, 0.01, 0.02, 0.05)
PRIMARY_OPERATING_POINT = 0.01
CHUNK_ROWS = 50_000
ISOLATION_FOREST_CONFIGURATION: dict[str, Any] = {
    "name": "IsolationForest",
    "n_estimators": 100,
    "max_samples": 256,
    "contamination": "auto",
    "max_features": 1.0,
    "bootstrap": False,
    "random_state": SEED,
    "n_jobs": 1,
}


def verify_preflight(integrity: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    """Fail closed unless all six training artifacts and the 77-feature schema verify."""
    if not integrity.get("passed"):
        raise ValueError(f"Stage 5D prepared-data preflight failed: {integrity.get('failures')}")
    stats = {item["file"]: item for item in manifest["source_statistics"]}
    files = {item["file"]: item for item in integrity["files"]}
    if len(stats) != 7 or set(stats) != set(files):
        raise ValueError("expected the seven frozen Stage 5D prepared source artifacts")
    training_sources = sorted(name for name in stats if name != TEST_SOURCE)
    if len(training_sources) != 6 or TEST_SOURCE in training_sources:
        raise ValueError("Tuesday-20-02 must be held out; expected six non-Tuesday sources")
    ref_schema: tuple[str, ...] | None = None
    verified_sources: list[dict[str, Any]] = []
    benign_training_support = 0
    total_prepared_training_rows = 0
    for name in training_sources:
        source = stats[name]
        checked = files[name]
        if checked["sha256"] != source["output_sha256"]:
            raise ValueError(f"prepared artifact hash differs from manifest: {name}")
        if not source.get("source_hash_matches_frozen_audit"):
            raise ValueError(f"raw source hash was not verified against frozen audit: {name}")
        if source["sha256"] != source["frozen_expected_sha256"]:
            raise ValueError(f"raw source hash differs from frozen audit hash: {name}")
        schema = tuple(checked["feature_names"])
        if len(schema) != EXPECTED_FEATURE_COUNT:
            raise ValueError(f"{name} does not have exactly 77 predictors")
        if ref_schema is None:
            ref_schema = schema
        elif schema != ref_schema:
            raise ValueError(f"ordered predictor schema differs for {name}")
        if checked["feature_dtype"] != "float32" or checked["target_column"] != "Label":
            raise ValueError(f"unexpected feature/target representation for {name}")
        benign_count = int(source["class_counts"].get(BENIGN_LABEL, 0))
        benign_training_support += benign_count
        total_prepared_training_rows += int(source["final_usable_row_count"])
        verified_sources.append(
            {
                "file": name,
                "raw_sha256": source["sha256"],
                "prepared_sha256": checked["sha256"],
                "prepared_rows": int(source["final_usable_row_count"]),
                "benign_rows_available_for_split": benign_count,
            }
        )
    test_source = stats[TEST_SOURCE]
    test_checked = files[TEST_SOURCE]
    if UNSEEN_LABEL in {
        label for source_name in training_sources for label in stats[source_name]["class_counts"]
    }:
        raise ValueError("LOIC-HTTP occurs in the non-Tuesday novelty-model source labels")
    if test_checked["sha256"] != test_source["output_sha256"]:
        raise ValueError("Tuesday prepared artifact hash differs from manifest")
    if tuple(test_checked["feature_names"]) != ref_schema:
        raise ValueError("Tuesday test schema differs from the frozen training schema")
    return {
        "passed": True,
        "training_sources": verified_sources,
        "training_source_count": len(training_sources),
        "test_source": {
            "file": TEST_SOURCE,
            "raw_sha256": test_source["sha256"],
            "prepared_sha256": test_checked["sha256"],
            "prepared_rows": int(test_source["final_usable_row_count"]),
        },
        "test_source_excluded_from_model_fit_and_threshold_selection": True,
        "loic_http_absent_from_training_source_labels": True,
        "feature_count": len(ref_schema or ()),
        "feature_names": list(ref_schema or ()),
        "feature_dtype": "float32",
        "target_column": "Label",
        "benign_rows_available_for_partition": benign_training_support,
        "all_rows_in_six_training_sources": total_prepared_training_rows,
        "prepared_hashes_match_stage5d_manifest": True,
        "raw_hashes_match_frozen_stage5a_audit_recorded_in_stage5d_manifest": True,
    }


def validation_positions(
    benign_count: int, *, seed: int, source_name: str, fraction: float = VALIDATION_FRACTION
) -> np.ndarray:
    """Choose an exact, repeatable per-source validation subset of benign row ordinals."""
    if benign_count < 1 or not 0 < fraction < 1:
        raise ValueError("benign_count must be positive and fraction must be between 0 and 1")
    source_salt = int.from_bytes(hashlib.sha256(source_name.encode()).digest()[:4], "big")
    source_seed = np.random.SeedSequence([seed, source_salt])
    validation_size = int(np.floor(benign_count * fraction))
    if validation_size == 0:
        raise ValueError("validation partition would be empty")
    positions = np.random.default_rng(source_seed).choice(
        benign_count, size=validation_size, replace=False
    )
    return np.sort(positions.astype(np.int64, copy=False))


def select_threshold(novelty_scores: np.ndarray, target_fpr: float) -> dict[str, Any]:
    """Choose the score >= threshold cutpoint nearest the target validation rejection count.

    Scores must increase with novelty. Ties are indivisible; when two achievable
    counts are equally close, this chooses the lower (more conservative) FPR.
    """
    scores = np.asarray(novelty_scores, dtype=np.float64)
    if scores.ndim != 1 or not len(scores) or not np.isfinite(scores).all():
        raise ValueError("novelty scores must be a non-empty finite 1-D array")
    if not 0 < target_fpr < 1:
        raise ValueError("target FPR must be between 0 and 1")
    descending = np.sort(scores)[::-1]
    group_ends = np.concatenate(
        (np.flatnonzero(descending[:-1] != descending[1:]) + 1, np.asarray([len(scores)]))
    )
    rejection_counts = np.concatenate((np.asarray([0]), group_ends))
    target_count = target_fpr * len(scores)
    differences = np.abs(rejection_counts - target_count)
    min_difference = differences.min()
    best = np.flatnonzero(differences == min_difference)
    best_count = int(rejection_counts[best[0]])
    if best_count == 0:
        threshold = float(np.nextafter(descending[0], np.inf))
    else:
        threshold = float(descending[best_count - 1])
    return {
        "target_benign_fpr": target_fpr,
        "threshold": threshold,
        "validation_benign_rows": int(len(scores)),
        "validation_benign_unknown_count": best_count,
        "validation_benign_fpr": best_count / len(scores),
        "validation_fpr_differs_from_requested": best_count / len(scores) != target_fpr,
        "threshold_rule": "score >= threshold is UNKNOWN",
    }


def apply_threshold(novelty_scores: np.ndarray, threshold: float) -> np.ndarray:
    """Return UNKNOWN decisions; higher novelty scores are more anomalous."""
    scores = np.asarray(novelty_scores, dtype=np.float64)
    if not np.isfinite(scores).all() or not np.isfinite(threshold):
        raise ValueError("scores and threshold must be finite")
    return scores >= threshold


def binary_metrics(counts: dict[str, int]) -> dict[str, Any]:
    benign_known = counts["benign_known"]
    benign_unknown = counts["benign_unknown"]
    loic_known = counts["loic_known"]
    loic_unknown = counts["loic_unknown"]
    benign_total = benign_known + benign_unknown
    loic_total = loic_known + loic_unknown
    unknown_total = benign_unknown + loic_unknown
    benign_fpr = benign_unknown / benign_total if benign_total else 0.0
    loic_recall = loic_unknown / loic_total if loic_total else 0.0
    unknown_precision = loic_unknown / unknown_total if unknown_total else 0.0
    unknown_f1 = (
        2 * unknown_precision * loic_recall / (unknown_precision + loic_recall)
        if unknown_precision + loic_recall
        else 0.0
    )
    specificity = benign_known / benign_total if benign_total else 0.0
    return {
        "benign_test_rows": benign_total,
        "loic_http_test_rows": loic_total,
        "benign_known_count": benign_known,
        "benign_unknown_count": benign_unknown,
        "loic_http_known_count": loic_known,
        "loic_http_unknown_count": loic_unknown,
        "benign_fpr": benign_fpr,
        "benign_rejection_rate": benign_fpr,
        "loic_http_unknown_recall": loic_recall,
        "unknown_precision": unknown_precision,
        "unknown_f1": unknown_f1,
        "balanced_accuracy": (specificity + loic_recall) / 2,
        "confusion_matrix": [
            [benign_known, benign_unknown],
            [loic_known, loic_unknown],
        ],
        "confusion_matrix_rows_actual_benign_then_loic_http_columns_known_then_unknown": True,
    }


def _load_benign_train_validation(
    root: Path,
    preflight: dict[str, Any],
    source_stats: dict[str, dict[str, Any]],
) -> tuple[np.ndarray, np.ndarray, dict[str, Any]]:
    sources = preflight["training_sources"]
    split_masks: dict[str, np.ndarray] = {}
    train_count = 0
    validation_count = 0
    per_source: list[dict[str, Any]] = []
    for ordinal, source_info in enumerate(sources):
        name = source_info["file"]
        benign_count = int(source_stats[name]["class_counts"][BENIGN_LABEL])
        positions = validation_positions(benign_count, seed=SEED, source_name=name)
        mask = np.zeros(benign_count, dtype=bool)
        mask[positions] = True
        split_masks[name] = mask
        val_size = int(mask.sum())
        validation_count += val_size
        train_count += benign_count - val_size
        per_source.append(
            {
                "file": name,
                "source_order": ordinal,
                "benign_total": benign_count,
                "benign_train_rows": benign_count - val_size,
                "benign_validation_rows": val_size,
                "validation_row_ordinals_sha256": hashlib.sha256(positions.tobytes()).hexdigest(),
            }
        )
    feature_count = int(preflight["feature_count"])
    train_x = np.empty((train_count, feature_count), dtype=np.float32)
    validation_x = np.empty((validation_count, feature_count), dtype=np.float32)
    train_offset = 0
    validation_offset = 0
    for source_info in sources:
        name = source_info["file"]
        path = root / source_stats[name]["output_path"]
        mask = split_masks[name]
        benign_ordinal = 0
        observed_rows = 0
        for row in _iter_prepared_rows(path):
            observed_rows += 1
            if row[-1] != BENIGN_LABEL:
                continue
            values = np.asarray(row[:-1], dtype=np.float32)
            if mask[benign_ordinal]:
                validation_x[validation_offset] = values
                validation_offset += 1
            else:
                train_x[train_offset] = values
                train_offset += 1
            benign_ordinal += 1
        if observed_rows != source_stats[name]["final_usable_row_count"]:
            raise ValueError(f"source row count changed during benign partition read: {name}")
        if benign_ordinal != int(source_stats[name]["class_counts"][BENIGN_LABEL]):
            raise ValueError(f"benign count changed during partition read: {name}")
    if (train_offset, validation_offset) != (train_count, validation_count):
        raise ValueError("loaded train/validation counts differ from deterministic split plan")
    return (
        train_x,
        validation_x,
        {
            "train_benign_rows": train_count,
            "validation_benign_rows": validation_count,
            "training_source_rows_including_ignored_attacks": sum(
                int(source_stats[item["file"]]["final_usable_row_count"]) for item in sources
            ),
            "attack_rows_ignored_for_unsupervised_fit": sum(
                int(source_stats[item["file"]]["final_usable_row_count"])
                - int(source_stats[item["file"]]["class_counts"][BENIGN_LABEL])
                for item in sources
            ),
            "per_source_split": per_source,
        },
    )


def _iter_prepared_rows(path: Path) -> Iterator[list[str]]:
    with gzip.open(path, "rt", encoding="utf-8", newline="") as stream:
        reader = csv.reader(stream)
        header = next(reader, None)
        if header is None or len(header) != EXPECTED_FEATURE_COUNT + 1 or header[-1] != "Label":
            raise ValueError(f"prepared schema changed after preflight: {path}")
        for row in reader:
            if len(row) != len(header):
                raise ValueError(f"invalid row width in prepared artifact: {path}")
            yield row


def _evaluate_test_once(
    path: Path, model: IsolationForest, thresholds: dict[str, dict[str, Any]]
) -> tuple[dict[str, dict[str, int]], int, float]:
    counts = {
        name: {
            "benign_known": 0,
            "benign_unknown": 0,
            "loic_known": 0,
            "loic_unknown": 0,
        }
        for name in thresholds
    }
    rows = 0
    inference_seconds = 0.0
    for chunk in _iter_prepared_chunks(path):
        features: list[list[float]] = []
        labels: list[str] = []
        for row in chunk:
            features.append([float(value) for value in row[:-1]])
            labels.append(row[-1])
        feature_matrix = np.asarray(features, dtype=np.float32)
        started = time.perf_counter()
        novelty_scores = -model.score_samples(feature_matrix)
        inference_seconds += time.perf_counter() - started
        for threshold_name, record in thresholds.items():
            is_unknown = apply_threshold(novelty_scores, float(record["threshold"]))
            for label, decision in zip(labels, is_unknown, strict=True):
                if label == BENIGN_LABEL:
                    key = "benign_unknown" if decision else "benign_known"
                elif label == UNSEEN_LABEL:
                    key = "loic_unknown" if decision else "loic_known"
                else:
                    raise ValueError(f"unexpected Tuesday test label: {label}")
                counts[threshold_name][key] += 1
        rows += len(labels)
    return counts, rows, inference_seconds


def _iter_prepared_chunks(path: Path) -> Iterator[list[list[str]]]:
    with gzip.open(path, "rt", encoding="utf-8", newline="") as stream:
        reader = csv.reader(stream)
        header = next(reader, None)
        if header is None or len(header) != EXPECTED_FEATURE_COUNT + 1 or header[-1] != "Label":
            raise ValueError(f"prepared schema changed after preflight: {path}")
        while chunk := list(islice(reader, CHUNK_ROWS)):
            if any(len(row) != len(header) for row in chunk):
                raise ValueError(f"invalid row width in prepared artifact: {path}")
            yield chunk


def run_experiment(
    root: Path, integrity: dict[str, Any], manifest: dict[str, Any]
) -> dict[str, Any]:
    verified = verify_preflight(integrity, manifest)
    source_stats = {item["file"]: item for item in manifest["source_statistics"]}
    train_x, validation_x, split_report = _load_benign_train_validation(
        root, verified, source_stats
    )
    model = IsolationForest(
        n_estimators=ISOLATION_FOREST_CONFIGURATION["n_estimators"],
        max_samples=ISOLATION_FOREST_CONFIGURATION["max_samples"],
        contamination=ISOLATION_FOREST_CONFIGURATION["contamination"],
        max_features=ISOLATION_FOREST_CONFIGURATION["max_features"],
        bootstrap=ISOLATION_FOREST_CONFIGURATION["bootstrap"],
        random_state=ISOLATION_FOREST_CONFIGURATION["random_state"],
        n_jobs=ISOLATION_FOREST_CONFIGURATION["n_jobs"],
    )
    training_started = time.perf_counter()
    model.fit(train_x)
    training_seconds = time.perf_counter() - training_started
    validation_started = time.perf_counter()
    # sklearn score_samples is lower for anomalies; negation makes larger mean
    # more novel and matches the required score >= threshold -> UNKNOWN rule.
    validation_scores = -model.score_samples(validation_x)
    validation_scoring_seconds = time.perf_counter() - validation_started
    del train_x, validation_x

    operating_points: dict[str, dict[str, Any]] = {}
    for target in OPERATING_POINTS:
        name = f"{target * 100:g}%"
        operating_points[name] = select_threshold(validation_scores, target)
    del validation_scores

    test_path = root / source_stats[TEST_SOURCE]["output_path"]
    raw_test_counts, observed_test_rows, inference_seconds = _evaluate_test_once(
        test_path, model, operating_points
    )
    if observed_test_rows != int(source_stats[TEST_SOURCE]["final_usable_row_count"]):
        raise ValueError("Tuesday test row count differs from frozen preparation manifest")
    expected_test_labels = source_stats[TEST_SOURCE]["class_counts"]
    observed_test_labels = {
        "Benign": raw_test_counts["1%"]["benign_known"] + raw_test_counts["1%"]["benign_unknown"],
        UNSEEN_LABEL: raw_test_counts["1%"]["loic_known"] + raw_test_counts["1%"]["loic_unknown"],
    }
    if observed_test_labels != expected_test_labels:
        raise ValueError("Tuesday test class counts differ from frozen preparation manifest")

    sensitivity: list[dict[str, Any]] = []
    for name, threshold_record in operating_points.items():
        metrics = binary_metrics(raw_test_counts[name])
        sensitivity.append(
            {
                "operating_point": name,
                "threshold": threshold_record["threshold"],
                "validation_benign_fpr": threshold_record["validation_benign_fpr"],
                "test_benign_fpr": metrics["benign_fpr"],
                "test_benign_rejection_rate": metrics["benign_rejection_rate"],
                "loic_http_unknown_recall": metrics["loic_http_unknown_recall"],
                "unknown_precision": metrics["unknown_precision"],
                "unknown_f1": metrics["unknown_f1"],
                "balanced_accuracy": metrics["balanced_accuracy"],
                "counts": metrics,
            }
        )
    primary_name = f"{PRIMARY_OPERATING_POINT * 100:g}%"
    primary_threshold = operating_points[primary_name]
    primary_metrics = binary_metrics(raw_test_counts[primary_name])
    return {
        "experiment_id": "CSE-5E2B-TUESDAY-LOIC-HTTP-ISOLATION-FOREST",
        "stage": "5E.2B",
        "condition": "explicit novelty detection for the source-held-out LOIC-HTTP condition",
        "preflight": verified,
        "train_rows": split_report["train_benign_rows"],
        "validation_rows": split_report["validation_benign_rows"],
        "test_rows": observed_test_rows,
        "training_source_rows_including_ignored_attacks": split_report[
            "training_source_rows_including_ignored_attacks"
        ],
        "attack_rows_ignored_for_unsupervised_fit": split_report[
            "attack_rows_ignored_for_unsupervised_fit"
        ],
        "training_class_for_model_fit": "Benign only; no labels passed to IsolationForest.fit",
        "loic_http_used_in_fit": False,
        "validation_split": {
            "method": (
                "within each of the six non-Tuesday source files, deterministic exact 20% "
                "sample of benign row ordinals without replacement"
            ),
            "seed": SEED,
            "fraction_per_source": VALIDATION_FRACTION,
            "threshold_validation_rows_are_benign_only": True,
            "source_disjointness_role": (
                "calibration partition; Tuesday remains the untouched final source-held-out test"
            ),
            "per_source": split_report["per_source_split"],
        },
        "test_evaluated_once": True,
        "test_rows_used_for_threshold_selection": False,
        "feature_schema": {
            "count": verified["feature_count"],
            "ordered_names": verified["feature_names"],
            "dtype": verified["feature_dtype"],
        },
        "preprocessing": {
            "configuration": (
                "frozen Stage 5D model-ready feature order; fixed numeric CSV-to-float32 cast"
            ),
            "learned_preprocessing": "none",
            "fit_scope": (
                "No preprocessing is fit; model fit uses only non-Tuesday benign training rows"
            ),
            "missing_or_nonfinite_handling": (
                "already applied by frozen Stage 5D preparation; no imputation or additional "
                "row filtering"
            ),
        },
        "model": ISOLATION_FOREST_CONFIGURATION,
        "score_direction": {
            "library_score": (
                "sklearn IsolationForest.score_samples; lower values are more anomalous"
            ),
            "novelty_score": "negative score_samples; higher values indicate greater novelty",
            "decision": (
                "novelty_score >= validation-selected threshold -> UNKNOWN; otherwise KNOWN"
            ),
            "isolation_forest_contamination": (
                "auto retained from existing project baseline; estimator offset/predict "
                "threshold is not used"
            ),
        },
        "threshold_selection": {
            "primary_pre_registered_benign_fpr": PRIMARY_OPERATING_POINT,
            "method": (
                "validation benign novelty-score order statistic; select attainable score-group "
                "boundary nearest target rejection count; ties choose the lower FPR"
            ),
            "tie_behavior": (
                "equal novelty scores are indivisible; realized validation FPR may differ "
                "slightly from target"
            ),
            "primary": primary_threshold,
            "sensitivity_operating_points": operating_points,
        },
        "primary_metrics": primary_metrics,
        "sensitivity": sensitivity,
        "test_class_distribution": observed_test_labels,
        "training_seconds": training_seconds,
        "validation_scoring_seconds": validation_scoring_seconds,
        "inference_seconds_total_score_samples_only": inference_seconds,
        "inference_seconds_per_test_row": inference_seconds / max(observed_test_rows, 1),
        "peak_process_rss_bytes": _peak_rss_bytes(),
        "peak_memory_measurement": (
            "process peak RSS from getrusage; includes preflight and data loading; "
            "not accelerator memory"
        ),
        "reproducibility": {
            "random_seed": SEED,
            "software": {},
            "source_hashes": [*verified["training_sources"], verified["test_source"]],
            "raw_datasets_modified": False,
            "previous_experiment_artifacts_modified": False,
        },
    }


def stage5e2a_context(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        prior = cast(dict[str, Any], json.load(stream))
    unknown = prior["unseen_label"]
    return {
        "stage5e2a_condition": prior["condition"],
        "stage5e2a_is_closed_set_without_unknown_reject": True,
        "stage5e2a_loic_test_flows": unknown["test_flows"],
        "stage5e2a_loic_flows_all_received_known_class_prediction": sum(
            unknown["predicted_class_distribution"].values()
        )
        == unknown["test_flows"],
        "stage5e2a_loic_predicted_class_distribution": unknown["predicted_class_distribution"],
        "comparison_note": (
            "Context only: Stage 5E.2A has no UNKNOWN class; Stage 5E.2B adds an explicit "
            "UNKNOWN decision. These are not directly comparable accuracy models."
        ),
    }
