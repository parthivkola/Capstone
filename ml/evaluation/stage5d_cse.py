"""Stage 5D preflight and full source-file Random Forest evaluation."""

from __future__ import annotations

import csv
import gzip
import hashlib
import json
import resource
import time
from collections import Counter
from pathlib import Path
from typing import Any, cast

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix

FORBIDDEN = {"Label", "Flow ID", "Src IP", "Dst IP", "Timestamp", "Dst Port"}
EXPECTED_FEATURE_COUNT = 77
SEED = 2026


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        return cast(dict[str, Any], json.load(stream))


def _data_paths(root: Path, manifest: dict[str, Any]) -> dict[str, Path]:
    return {item["file"]: root / item["output_path"] for item in manifest["source_statistics"]}


def preflight(root: Path) -> dict[str, Any]:
    """Verify all seven prepared artifacts; fail closed before any training."""
    manifest = _load_json(root / "experiments/stage5d/cse-preparation.json")
    protocol = _load_json(root / "experiments/stage5c1/cse-protocol.json")
    expected_features = manifest["preparation_rules"]["model_features"]
    failures: list[str] = []
    if len(expected_features) != EXPECTED_FEATURE_COUNT:
        failures.append(f"manifest feature count is {len(expected_features)}, expected 77")
    if FORBIDDEN.intersection(expected_features):
        failures.append(
            f"forbidden model feature names: {sorted(FORBIDDEN.intersection(expected_features))}"
        )
    if manifest.get("preparation_rules", {}).get("imputation") != "none":
        failures.append("frozen preparation manifest does not specify no imputation")
    source_files = {item["file"] for item in manifest["source_statistics"]}
    if len(source_files) != 7:
        failures.append(f"preparation manifest has {len(source_files)} source files, expected 7")
    schemas: dict[str, list[str]] = {}
    dtypes: dict[str, list[str]] = {}
    labels: dict[str, Counter[str]] = {}
    rows: dict[str, int] = {}
    files_result: list[dict[str, Any]] = []

    for source in manifest["source_statistics"]:
        name = source["file"]
        path = root / source["output_path"]
        if not path.is_file():
            failures.append(f"{name}: prepared artifact missing: {path}")
            continue
        digest = sha256_file(path)
        if digest != source["output_sha256"]:
            failures.append(f"{name}: artifact SHA-256 does not match manifest")
        per_feature_types: list[str] | None = None
        class_counts: Counter[str] = Counter()
        row_count = 0
        with gzip.open(path, "rt", encoding="utf-8", newline="") as stream:
            reader = csv.reader(stream)
            header = next(reader, None)
            if header is None:
                failures.append(f"{name}: empty artifact")
                continue
            schemas[name] = header[:-1]
            if header[:-1] != expected_features:
                failures.append(f"{name}: ordered feature schema differs from preparation manifest")
            if header[-1] != "Label" or header.count("Label") != 1:
                failures.append(f"{name}: Label is not the sole target column")
            present_forbidden = FORBIDDEN.intersection(header[:-1])
            if present_forbidden:
                failures.append(f"{name}: forbidden columns present: {sorted(present_forbidden)}")
            for line_number, row in enumerate(reader, start=2):
                row_count += 1
                if len(row) != len(header):
                    failures.append(f"{name}:{line_number}: width {len(row)} != {len(header)}")
                    break
                if not row[-1]:
                    failures.append(f"{name}:{line_number}: empty target label")
                    break
                class_counts[row[-1]] += 1
                if per_feature_types is None:
                    per_feature_types = ["float32"] * len(expected_features)
                try:
                    numeric = np.asarray(row[:-1], dtype=np.float32)
                except (ValueError, OverflowError):
                    failures.append(f"{name}:{line_number}: non-numeric model feature")
                    break
                if numeric.shape != (EXPECTED_FEATURE_COUNT,) or not np.isfinite(numeric).all():
                    failures.append(
                        f"{name}:{line_number}: invalid/non-finite float32 feature vector"
                    )
                    break
        dtypes[name] = per_feature_types or ["float32"] * EXPECTED_FEATURE_COUNT
        labels[name] = class_counts
        rows[name] = row_count
        if row_count != source["final_usable_row_count"]:
            failures.append(
                f"{name}: {row_count} rows != preparation manifest "
                f"{source['final_usable_row_count']}"
            )
        if dict(sorted(class_counts.items())) != source["class_counts"]:
            failures.append(f"{name}: observed labels/counts differ from preparation manifest")
        files_result.append(
            {
                "file": name,
                "path": str(path),
                "sha256": digest,
                "rows": row_count,
                "feature_count": len(schemas.get(name, [])),
                "feature_names": schemas.get(name, []),
                "feature_dtype": "float32",
                "target_column": "Label",
                "class_counts": dict(sorted(class_counts.items())),
            }
        )

    reference_schema = next(iter(schemas.values()), [])
    if len(reference_schema) != EXPECTED_FEATURE_COUNT:
        failures.append(f"observed schema has {len(reference_schema)} features, expected 77")
    for name, schema in schemas.items():
        if schema != reference_schema:
            failures.append(f"{name}: ordered feature names differ from other prepared files")
        if dtypes[name] != ["float32"] * EXPECTED_FEATURE_COUNT:
            failures.append(f"{name}: feature dtype is not the common float32 representation")

    split_results: dict[str, Any] = {}
    for holdout in protocol["source_file_holdouts"]:
        train = [Path(path).name for path in holdout["train"]]
        test = [Path(path).name for path in holdout["test"]]
        if set(train + test) - source_files:
            failures.append(f"{holdout['id']}: source absent from prepared manifest")
        support = validate_holdout_support(train, test, labels)
        if support["source_overlap"]:
            failures.append(
                f"{holdout['id']}: train/test source overlap: {support['source_overlap']}"
            )
        unsupported = support["test_labels_without_training_support"]
        if unsupported:
            failures.append(f"{holdout['id']}: test labels lack training support: {unsupported}")
        split_results[holdout["id"]] = {
            "train_sources": train,
            "test_sources": test,
            **support,
            "test_labels_without_training_support": unsupported,
            "all_test_labels_supported": not unsupported,
        }

    return {
        "passed": not failures,
        "failures": failures,
        "artifact_count": len(files_result),
        "files": files_result,
        "holdouts": split_results,
        "feature_schema": reference_schema,
        "feature_dtype": "float32",
        "label_dtype": "string",
        "preprocessing": {
            "fitted_transform": "none",
            "fixed_conversion": "numeric CSV text cast to float32; no learned state",
            "train_only_fit_check": (
                "passed: no preprocessing estimator is fit; RF learns only from "
                "listed training sources"
            ),
        },
    }


def validate_holdout_support(
    train_sources: list[str],
    test_sources: list[str],
    class_counts: dict[str, Counter[str]],
) -> dict[str, Any]:
    overlap = sorted(set(train_sources) & set(test_sources))
    if overlap:
        raise ValueError(f"train/test source overlap: {overlap}")
    train_labels = set().union(*(set(class_counts[name]) for name in train_sources))
    test_labels = set().union(*(set(class_counts[name]) for name in test_sources))
    unsupported = sorted(test_labels - train_labels)
    return {
        "source_overlap": overlap,
        "train_test_disjoint": True,
        "test_labels_without_training_support": unsupported,
        "all_test_labels_supported": not unsupported,
    }


def _read_matrix(
    paths: list[Path],
    feature_count: int,
    expected_rows: int,
    label_codes: dict[str, int],
) -> tuple[np.ndarray, np.ndarray]:
    matrix = np.empty((expected_rows, feature_count), dtype=np.float32)
    targets = np.empty(expected_rows, dtype=np.int8)
    row_offset = 0
    for path in paths:
        with gzip.open(path, "rt", encoding="utf-8", newline="") as stream:
            reader = csv.reader(stream)
            header = next(reader)
            if len(header) != feature_count + 1 or header[-1] != "Label":
                raise ValueError(f"Preflighted schema changed during run: {path}")
            for row in reader:
                matrix[row_offset] = np.asarray(row[:-1], dtype=np.float32)
                row_offset += 1
                targets[row_offset - 1] = label_codes[row[-1]]
    if row_offset != expected_rows:
        raise ValueError(
            f"Prepared row count changed after preflight: {row_offset} != {expected_rows}"
        )
    return matrix, targets


def _peak_rss_bytes() -> int:
    raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(raw if sys_platform_is_macos() else raw * 1024)


def sys_platform_is_macos() -> bool:
    import sys

    return sys.platform == "darwin"


def _metrics(y_true: np.ndarray, y_pred: np.ndarray, labels: list[str]) -> dict[str, Any]:
    matrix = confusion_matrix(y_true, y_pred, labels=labels)
    support = matrix.sum(axis=1)
    predicted_count = matrix.sum(axis=0)
    precision = np.divide(
        np.diag(matrix),
        predicted_count,
        out=np.zeros(len(labels), dtype=float),
        where=predicted_count > 0,
    )
    recall = np.divide(
        np.diag(matrix), support, out=np.zeros(len(labels), dtype=float), where=support > 0
    )
    f1 = np.divide(
        2 * precision * recall,
        precision + recall,
        out=np.zeros(len(labels), dtype=float),
        where=(precision + recall) > 0,
    )
    benign_i = labels.index("Benign")
    benign_total = int(matrix[benign_i].sum())
    benign_fp = int(matrix[benign_i].sum() - matrix[benign_i, benign_i])
    attack_total = int(len(y_true) - benign_total)
    attack_as_benign = int(matrix[:, benign_i].sum() - matrix[benign_i, benign_i])
    weighted_f1 = float(np.average(f1, weights=support)) if support.sum() else 0.0
    active = [
        index for index, value in enumerate(support) if value > 0 or matrix[:, index].sum() > 0
    ]
    supported = [index for index, value in enumerate(support) if value > 0]
    f1_values = [float(f1[index]) for index in active]
    supported_f1 = [float(f1[index]) for index in supported]
    active_precision = [float(precision[index]) for index in active]
    active_recall = [float(recall[index]) for index in active]
    return {
        "accuracy": float(np.trace(matrix) / support.sum()) if support.sum() else 0.0,
        "macro_precision": float(np.mean(active_precision)),
        "macro_recall": float(np.mean(active_recall)),
        "macro_f1": float(np.mean(f1_values)),
        "macro_f1_test_supported_classes": float(np.mean(supported_f1)),
        "macro_f1_full_training_vocabulary": float(np.mean(f1)),
        "weighted_f1": float(weighted_f1),
        "per_class": {
            label: {
                "precision": float(precision[index])
                if support[index] > 0 or predicted_count[index] > 0
                else None,
                "recall": float(recall[index]) if support[index] > 0 else None,
                "f1": float(f1[index])
                if support[index] > 0 or predicted_count[index] > 0
                else None,
                "support": int(support[index]),
                "predicted_count": int(predicted_count[index]),
            }
            for index, label in enumerate(labels)
        },
        "confusion_matrix": matrix.tolist(),
        "confusion_matrix_labels": labels,
        "benign_false_positive_rate": benign_fp / benign_total if benign_total else None,
        "attack_false_negative_rate_as_benign": (
            attack_as_benign / attack_total if attack_total else None
        ),
    }


def train_holdout(
    root: Path, holdout: dict[str, Any], preflight_result: dict[str, Any]
) -> dict[str, Any]:
    prep_manifest = _load_json(root / "experiments/stage5d/cse-preparation.json")
    paths = _data_paths(root, prep_manifest)
    expected_rows_by_file = {
        item["file"]: item["final_usable_row_count"] for item in prep_manifest["source_statistics"]
    }
    train_files = [Path(path).name for path in holdout["train"]]
    test_files = [Path(path).name for path in holdout["test"]]
    train_labels = sorted(
        {
            label
            for item in preflight_result["files"]
            if item["file"] in set(train_files)
            for label in item["class_counts"]
        }
    )
    label_codes = {label: index for index, label in enumerate(train_labels)}
    train_x, train_y = _read_matrix(
        [paths[name] for name in train_files],
        EXPECTED_FEATURE_COUNT,
        sum(expected_rows_by_file[name] for name in train_files),
        label_codes,
    )
    test_x, test_y = _read_matrix(
        [paths[name] for name in test_files],
        EXPECTED_FEATURE_COUNT,
        sum(expected_rows_by_file[name] for name in test_files),
        label_codes,
    )
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=18,
        max_features="sqrt",
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        random_state=SEED,
        n_jobs=1,
    )
    started = time.perf_counter()
    model.fit(train_x, train_y)
    training_seconds = time.perf_counter() - started
    started = time.perf_counter()
    prediction = model.predict(test_x)
    inference_seconds = time.perf_counter() - started
    train_label_names = np.asarray(train_labels, dtype=object)[train_y]
    test_label_names = np.asarray(train_labels, dtype=object)[test_y]
    prediction_names = np.asarray(train_labels, dtype=object)[prediction]
    metrics = _metrics(test_label_names, prediction_names, train_labels)
    train_counts = Counter(train_label_names.tolist())
    test_counts = Counter(test_label_names.tolist())
    return {
        "holdout_id": holdout["id"],
        "train_sources": train_files,
        "test_sources": test_files,
        "train_rows": int(len(train_y)),
        "test_rows": int(len(test_y)),
        "feature_count": EXPECTED_FEATURE_COUNT,
        "train_class_distribution": dict(sorted(train_counts.items())),
        "test_class_distribution": dict(sorted(test_counts.items())),
        "metrics": metrics,
        "training_seconds": training_seconds,
        "inference_seconds_total": inference_seconds,
        "inference_seconds_per_row": inference_seconds / max(len(test_y), 1),
        "peak_process_rss_bytes": _peak_rss_bytes(),
        "model": {
            "name": "RandomForestClassifier",
            "n_estimators": 100,
            "max_depth": 18,
            "max_features": "sqrt",
            "min_samples_leaf": 2,
            "class_weight": "balanced_subsample",
            "random_state": SEED,
            "n_jobs": 1,
        },
        "feature_preprocessing": "fixed CSV numeric-to-float32 cast; no fitted preprocessing",
        "preflight_passed": preflight_result["passed"],
        "classes_below_0_5_f1_descriptive": [
            name
            for name, values in metrics["per_class"].items()
            if values["support"] > 0 and values["f1"] < 0.5
        ],
    }
