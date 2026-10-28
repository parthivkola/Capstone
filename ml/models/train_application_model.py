"""Optional bounded offline CSE-CICFlowMeter model training.

Writes new application artifacts under var/models only. Frozen research
manifests, results, and prepared input files are read-only.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import json
import platform
import random
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
import sklearn
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.preprocessing import StandardScaler

from ml.models.application_linear import (
    FEATURE_SCHEMA_ID,
    MODEL_ARTIFACT_FORMAT,
    MODEL_ID,
    MODEL_VERSION,
)

PREPARATION_MANIFEST = Path("experiments/stage5d/cse-preparation.json")
PROTOCOL = Path("experiments/stage5c1/cse-protocol.json")
VALIDATION_SOURCE = "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv"
MAX_RECORDS_PER_CLASS_PER_SOURCE = 1_500
SEED = 20261028
FORBIDDEN = {"Label", "Flow ID", "Src IP", "Dst IP", "Timestamp", "Dst Port"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _stratified_reservoir(
    path: Path, expected_names: list[str], cap: int, seed: int
) -> tuple[list[tuple[list[str], str]], dict[str, int], int]:
    rng = random.Random(seed)
    reservoirs: dict[str, list[list[str]]] = {"BENIGN": [], "INTRUSION": []}
    seen: Counter[str] = Counter()
    with gzip.open(path, "rt", encoding="utf-8-sig", newline="") as stream:
        reader = csv.reader(stream)
        header = next(reader, None)
        if header != [*expected_names, "Label"]:
            raise ValueError(f"ordered feature schema differs from manifest: {path}")
        total = 0
        for row_number, row in enumerate(reader, start=2):
            total += 1
            if len(row) != len(header) or not row[-1]:
                raise ValueError(f"malformed prepared record at {path}:{row_number}")
            label = "BENIGN" if row[-1] == "Benign" else "INTRUSION"
            seen[label] += 1
            bucket = reservoirs[label]
            if len(bucket) < cap:
                bucket.append(row)
            else:
                replacement = rng.randrange(seen[label])
                if replacement < cap:
                    bucket[replacement] = row
    sampled = [
        (row[:-1], "BENIGN" if row[-1] == "Benign" else "INTRUSION")
        for label in ("BENIGN", "INTRUSION")
        for row in reservoirs[label]
    ]
    return sampled, dict(sorted(seen.items())), total


def _features(rows: list[tuple[list[str], str]], names: list[str]) -> tuple[np.ndarray, np.ndarray]:
    matrix = np.empty((len(rows), len(names)), dtype=np.float32)
    target = np.empty(len(rows), dtype=np.int8)
    for index, (values, label) in enumerate(rows):
        try:
            vector = np.asarray(values, dtype=np.float32)
        except (ValueError, OverflowError) as error:
            raise ValueError(f"sampled input row {index} has a non-numeric value") from error
        if vector.shape != (len(names),) or not np.isfinite(vector).all():
            raise ValueError(f"sampled input row {index} has invalid/non-finite features")
        matrix[index] = vector
        target[index] = 0 if label == "BENIGN" else 1
    return matrix, target


def _metrics(truth: np.ndarray, predicted: np.ndarray) -> dict[str, Any]:
    matrix = confusion_matrix(truth, predicted, labels=[0, 1])
    benign_total = int(matrix[0].sum())
    attack_total = int(matrix[1].sum())
    return {
        "label_order": ["BENIGN", "INTRUSION"],
        "confusion_matrix": matrix.tolist(),
        "accuracy": float(np.trace(matrix) / max(int(matrix.sum()), 1)),
        "macro_precision": float(
            precision_score(truth, predicted, average="macro", zero_division=0)
        ),
        "macro_recall": float(recall_score(truth, predicted, average="macro", zero_division=0)),
        "macro_f1": float(f1_score(truth, predicted, average="macro", zero_division=0)),
        "benign_fpr": float(matrix[0, 1] / benign_total) if benign_total else None,
        "attack_fnr": float(matrix[1, 0] / attack_total) if attack_total else None,
        "support": {"BENIGN": benign_total, "INTRUSION": attack_total},
    }


CANDIDATE_SPECS: tuple[dict[str, Any], ...] = (
    {
        "candidate_id": "logreg_l2_c1_lbfgs",
        "solver": "lbfgs",
        "penalty": "l2",
        "C": 1.0,
        "max_iter": 400,
    },
    {
        "candidate_id": "logreg_l2_c0_1_lbfgs",
        "solver": "lbfgs",
        "penalty": "l2",
        "C": 0.1,
        "max_iter": 400,
    },
    {
        "candidate_id": "logreg_l2_c10_lbfgs",
        "solver": "lbfgs",
        "penalty": "l2",
        "C": 10.0,
        "max_iter": 400,
    },
    {
        "candidate_id": "logreg_l1_c1_saga",
        "solver": "saga",
        "penalty": "l1",
        "C": 1.0,
        "max_iter": 800,
    },
)


def _prepare_application_splits(
    root: Path,
    *,
    max_records_per_class_per_source: int,
    seed: int,
) -> dict[str, Any]:
    if max_records_per_class_per_source < 10:
        raise ValueError("max records per class per source must be at least 10")
    prep = json.loads((root / PREPARATION_MANIFEST).read_text(encoding="utf-8"))
    protocol = json.loads((root / PROTOCOL).read_text(encoding="utf-8"))
    names = prep.get("preparation_rules", {}).get("model_features")
    if not isinstance(names, list) or len(names) != 77 or FORBIDDEN.intersection(names):
        raise ValueError("prepared input does not match the supported 77-feature offline schema")
    if any(not isinstance(name, str) for name in names) or len(set(names)) != len(names):
        raise ValueError("prepared feature names are malformed or duplicated")
    holdout = next(
        (
            item
            for item in protocol.get("source_file_holdouts", [])
            if item.get("id") == "CSE-SFH-A"
        ),
        None,
    )
    if not isinstance(holdout, dict):
        raise ValueError("the documented CSE-SFH-A source holdout is unavailable")
    test_sources = [Path(item).name for item in holdout["test"]]
    candidates = [Path(item).name for item in holdout["train"]]
    if VALIDATION_SOURCE not in candidates or len(test_sources) != 1:
        raise ValueError("source holdout cannot be partitioned into disjoint train/validation/test")
    validation_sources = [VALIDATION_SOURCE]
    train_sources = [name for name in candidates if name != VALIDATION_SOURCE]
    source_stats = {item["file"]: item for item in prep.get("source_statistics", [])}
    if set(train_sources + validation_sources + test_sources) - source_stats.keys():
        raise ValueError("source split references files absent from the preparation manifest")

    split_files = {
        "train": train_sources,
        "validation": validation_sources,
        "test": test_sources,
    }
    sampled: dict[str, list[tuple[list[str], str, str, str]]] = {split: [] for split in split_files}
    file_reports: list[dict[str, Any]] = []
    for split_index, (split, files) in enumerate(split_files.items()):
        for file_index, file_id in enumerate(files):
            stats = source_stats[file_id]
            relative = (
                Path("data/processed/stage5d/cse-cic-ids2018")
                / Path(str(stats.get("output_path", ""))).name
            )
            path = (root / relative).resolve()
            if not path.is_relative_to(root) or not path.is_file():
                raise FileNotFoundError(f"prepared file is missing or outside project: {relative}")
            digest = sha256_file(path)
            if digest != stats.get("output_sha256"):
                raise ValueError(
                    f"prepared file SHA-256 does not match frozen manifest: {relative}"
                )
            records, label_totals, total = _stratified_reservoir(
                path,
                names,
                max_records_per_class_per_source,
                seed + split_index * 100_003 + file_index,
            )
            for values, label in records:
                fingerprint = hashlib.sha256(
                    (label + "\0" + "\0".join(values)).encode("utf-8")
                ).hexdigest()
                sampled[split].append((values, label, file_id, fingerprint))
            file_reports.append(
                {
                    "file": file_id,
                    "split": split,
                    "artifact": relative.as_posix(),
                    "sha256": digest,
                    "rows_scanned": total,
                    "source_label_counts": label_totals,
                    "sampled_binary_label_counts": dict(
                        sorted(Counter(label for _values, label in records).items())
                    ),
                }
            )

    seen_fingerprints: set[str] = set()
    duplicate_drops: dict[str, int] = {}
    for split in ("train", "validation", "test"):
        unique: list[tuple[list[str], str, str, str]] = []
        duplicates = 0
        for row in sampled[split]:
            if row[3] in seen_fingerprints:
                duplicates += 1
            else:
                seen_fingerprints.add(row[3])
                unique.append(row)
        sampled[split] = unique
        duplicate_drops[split] = duplicates
        if len(unique) < 20:
            raise ValueError(f"too few unique records remain in {split} after duplicate checks")

    train_x, train_y = _features([(r[0], r[1]) for r in sampled["train"]], names)
    validation_x, validation_y = _features([(r[0], r[1]) for r in sampled["validation"]], names)
    test_x, test_y = _features([(r[0], r[1]) for r in sampled["test"]], names)
    return {
        "names": names,
        "sampled": sampled,
        "duplicate_drops": duplicate_drops,
        "file_reports": file_reports,
        "train_sources": train_sources,
        "validation_sources": validation_sources,
        "test_sources": test_sources,
        "train_x": train_x,
        "train_y": train_y,
        "validation_x": validation_x,
        "validation_y": validation_y,
        "test_x": test_x,
        "test_y": test_y,
    }


def _fit_logistic(
    train_scaled: np.ndarray,
    train_y: np.ndarray,
    *,
    seed: int,
    solver: str,
    penalty: str,
    C: float,
    max_iter: int,
) -> LogisticRegression:
    estimator = LogisticRegression(
        class_weight="balanced",
        max_iter=max_iter,
        random_state=seed,
        solver=solver,
        penalty=penalty,
        C=C,
    )
    estimator.fit(train_scaled, train_y)
    if list(estimator.classes_) != [0, 1]:
        raise ValueError("training did not produce both BENIGN and INTRUSION classes")
    return estimator


def _write_linear_model(
    *,
    root: Path,
    output: Path,
    names: list[str],
    scaler: StandardScaler,
    estimator: LogisticRegression,
    version: str,
    seed: int,
    max_records_per_class_per_source: int,
    duplicate_drops: dict[str, int],
    sampled: dict[str, list[Any]],
    train_sources: list[str],
    validation_sources: list[str],
    test_sources: list[str],
    file_reports: list[dict[str, Any]],
    validation_metrics: dict[str, Any],
    test_metrics: dict[str, Any],
    estimator_meta: dict[str, Any],
    selection_note: str,
    training_seconds: float,
) -> dict[str, Any]:
    means = np.asarray(scaler.mean_, dtype=np.float64)
    scales = np.asarray(scaler.scale_, dtype=np.float64)
    coefficients = np.asarray(estimator.coef_[0], dtype=np.float64)
    artifact = {
        "artifact_format": MODEL_ARTIFACT_FORMAT,
        "model_id": MODEL_ID,
        "version": version,
        "task": "binary benign-versus-intrusion classification",
        "target_mapping": {"Benign": "BENIGN", "all other source labels": "INTRUSION"},
        "feature_schema_id": FEATURE_SCHEMA_ID,
        "feature_schema_version": 1,
        "feature_names": names,
        "preprocessing": {
            "type": "StandardScaler",
            "mean": means.tolist(),
            "scale": scales.tolist(),
            "fit_partition": "train only",
        },
        "mean": means.tolist(),
        "scale": scales.tolist(),
        "classes": ["BENIGN", "INTRUSION"],
        "coefficients": coefficients.tolist(),
        "intercept": float(estimator.intercept_[0]),
        "explanation_method": "exact linear SHAP / log-odds contributions",
        "confidence_semantics": "sigmoid score; no separate calibration procedure was run",
    }
    artifact_bytes = (json.dumps(artifact, sort_keys=True, allow_nan=False) + "\n").encode()
    artifact_hash = hashlib.sha256(artifact_bytes).hexdigest()
    manifest = {
        "registry_version": 1,
        "model_id": MODEL_ID,
        "version": version,
        "status": "OFFLINE_VALIDATED_BASELINE",
        "task": artifact["task"],
        "artifact_format": MODEL_ARTIFACT_FORMAT,
        "artifact": "model.json",
        "artifact_sha256": artifact_hash,
        "feature_schema_id": FEATURE_SCHEMA_ID,
        "feature_schema_version": 1,
        "feature_names": names,
        "supported_labels": ["BENIGN", "INTRUSION"],
        "inference_enabled": True,
        "live_eligible": False,
        "live_ineligibility_reason": (
            "CICFlowMeter 77-feature offline model is incompatible with the four-feature "
            "OpenFlow rule-counter schema and has no live provenance approval."
        ),
        "training": {
            "created_at": datetime.now(UTC).isoformat(),
            "seed": seed,
            "python": platform.python_version(),
            "scikit_learn": sklearn.__version__,
            "numpy": np.__version__,
            "estimator": {
                **estimator_meta,
                "converged_iterations": int(np.max(estimator.n_iter_)),
            },
            "preprocessing_fit": "train partition only",
            "threshold_selection": selection_note,
        },
        "dataset": "CSE-CIC-IDS2018 Stage 5D prepared files",
        "dataset_manifest": PREPARATION_MANIFEST.as_posix(),
        "sampling": {
            "method": "deterministic per-source, per-binary-label reservoir sample",
            "max_records_per_class_per_source": max_records_per_class_per_source,
            "is_representative": False,
            "duplicates_removed_by_partition_priority": duplicate_drops,
            "unique_sample_counts": {key: len(value) for key, value in sampled.items()},
        },
        "split": {
            "train_sources": train_sources,
            "validation_sources": validation_sources,
            "test_sources": test_sources,
            "basis": "CSE-SFH-A source holdout; one training source reserved for validation",
            "overlap": False,
            "test_used_for_fit_or_selection": False,
        },
        "source_artifacts": file_reports,
        "metrics": {
            "validation": validation_metrics,
            "test": test_metrics,
        },
        "limitations": [
            "New application baseline; not a reproduction or replacement of frozen Stage 5 "
            "results.",
            "Binary mapping collapses all non-Benign source labels into INTRUSION.",
            "Deterministic per-source class-stratified samples are not representative sampling.",
            "Sigmoid outputs are not calibration-validated confidence estimates.",
            "Offline CICFlowMeter schema is not valid for live rule-counter telemetry.",
            "Only JSON-exportable linear logistic candidates were compared; tree/ensemble "
            "estimators remain outside the safe offline inference contract.",
        ],
        "training_seconds": round(training_seconds, 3),
    }
    output.mkdir(parents=True, exist_ok=False)
    (output / "model.json").write_bytes(artifact_bytes)
    temporary_manifest = output / "manifest.json.tmp"
    temporary_manifest.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    temporary_manifest.replace(output / "manifest.json")
    return manifest


def train_application_model(
    project_root: Path,
    output_dir: Path,
    *,
    max_records_per_class_per_source: int = MAX_RECORDS_PER_CLASS_PER_SOURCE,
    seed: int = SEED,
) -> dict[str, Any]:
    root = project_root.resolve()
    output = output_dir if output_dir.is_absolute() else root / output_dir
    output = output.resolve()
    models_root = (root / "var/models").resolve()
    if not output.is_relative_to(models_root) or output == models_root:
        raise ValueError("application models must be written under var/models/<new-version>")
    if output.exists():
        raise FileExistsError(f"model output already exists; refusing to overwrite: {output}")

    started = time.monotonic()
    prepared = _prepare_application_splits(
        root,
        max_records_per_class_per_source=max_records_per_class_per_source,
        seed=seed,
    )
    scaler = StandardScaler()
    train_scaled = scaler.fit_transform(prepared["train_x"])
    validation_scaled = scaler.transform(prepared["validation_x"])
    test_scaled = scaler.transform(prepared["test_x"])
    estimator = _fit_logistic(
        train_scaled,
        prepared["train_y"],
        seed=seed,
        solver="lbfgs",
        penalty="l2",
        C=1.0,
        max_iter=300,
    )
    return _write_linear_model(
        root=root,
        output=output,
        names=prepared["names"],
        scaler=scaler,
        estimator=estimator,
        version=MODEL_VERSION,
        seed=seed,
        max_records_per_class_per_source=max_records_per_class_per_source,
        duplicate_drops=prepared["duplicate_drops"],
        sampled=prepared["sampled"],
        train_sources=prepared["train_sources"],
        validation_sources=prepared["validation_sources"],
        test_sources=prepared["test_sources"],
        file_reports=prepared["file_reports"],
        validation_metrics=_metrics(prepared["validation_y"], estimator.predict(validation_scaled)),
        test_metrics=_metrics(prepared["test_y"], estimator.predict(test_scaled)),
        estimator_meta={
            "name": "LogisticRegression",
            "solver": "lbfgs",
            "penalty": "l2",
            "C": 1.0,
            "class_weight": "balanced",
            "max_iter": 300,
        },
        selection_note="none; default probability threshold 0.5",
        training_seconds=time.monotonic() - started,
    )


def compare_application_models(
    project_root: Path,
    output_dir: Path,
    comparison_path: Path,
    *,
    max_records_per_class_per_source: int = 300,
    seed: int = SEED,
    max_benign_fpr: float = 0.25,
    version: str = "2.0.0",
) -> dict[str, Any]:
    """Train linear candidates, select on validation, score test once, write winner."""
    root = project_root.resolve()
    output = output_dir if output_dir.is_absolute() else root / output_dir
    output = output.resolve()
    report_path = comparison_path if comparison_path.is_absolute() else root / comparison_path
    models_root = (root / "var/models").resolve()
    if not output.is_relative_to(models_root) or output == models_root:
        raise ValueError("application models must be written under var/models/<new-version>")
    if output.exists():
        raise FileExistsError(f"model output already exists; refusing to overwrite: {output}")
    if report_path.exists():
        raise FileExistsError(
            f"comparison report already exists; refusing to overwrite: {report_path}"
        )
    if not 0.0 < max_benign_fpr <= 1.0:
        raise ValueError("max_benign_fpr must be in (0, 1]")

    started = time.monotonic()
    prepared = _prepare_application_splits(
        root,
        max_records_per_class_per_source=max_records_per_class_per_source,
        seed=seed,
    )
    scaler = StandardScaler()
    train_scaled = scaler.fit_transform(prepared["train_x"])
    validation_scaled = scaler.transform(prepared["validation_x"])
    test_scaled = scaler.transform(prepared["test_x"])

    candidate_rows: list[dict[str, Any]] = []
    fitted: dict[str, LogisticRegression] = {}
    for spec in CANDIDATE_SPECS:
        estimator = _fit_logistic(
            train_scaled,
            prepared["train_y"],
            seed=seed,
            solver=str(spec["solver"]),
            penalty=str(spec["penalty"]),
            C=float(spec["C"]),
            max_iter=int(spec["max_iter"]),
        )
        validation_metrics = _metrics(
            prepared["validation_y"], estimator.predict(validation_scaled)
        )
        candidate_rows.append(
            {
                "candidate_id": spec["candidate_id"],
                "hyperparameters": {
                    "solver": spec["solver"],
                    "penalty": spec["penalty"],
                    "C": spec["C"],
                    "class_weight": "balanced",
                    "max_iter": spec["max_iter"],
                },
                "validation": validation_metrics,
                "selected": False,
                "disqualified_reason": None,
            }
        )
        fitted[str(spec["candidate_id"])] = estimator

    eligible = [
        row
        for row in candidate_rows
        if row["validation"]["benign_fpr"] is not None
        and row["validation"]["benign_fpr"] <= max_benign_fpr
    ]
    if not eligible:
        # Fall back to lowest validation FPR, then highest macro-F1.
        eligible = sorted(
            candidate_rows,
            key=lambda row: (
                float("inf")
                if row["validation"]["benign_fpr"] is None
                else row["validation"]["benign_fpr"],
                -row["validation"]["macro_f1"],
            ),
        )[:1]
        eligible[0]["disqualified_reason"] = (
            f"no candidate met max_benign_fpr<={max_benign_fpr}; "
            "selected lowest validation benign FPR instead"
        )
    else:
        eligible = sorted(
            eligible,
            key=lambda row: (
                -row["validation"]["macro_f1"],
                row["validation"]["benign_fpr"],
                row["candidate_id"],
            ),
        )
    winner = eligible[0]
    winner["selected"] = True
    winner_estimator = fitted[str(winner["candidate_id"])]
    test_metrics = _metrics(prepared["test_y"], winner_estimator.predict(test_scaled))
    winner["test"] = test_metrics

    manifest = _write_linear_model(
        root=root,
        output=output,
        names=prepared["names"],
        scaler=scaler,
        estimator=winner_estimator,
        version=version,
        seed=seed,
        max_records_per_class_per_source=max_records_per_class_per_source,
        duplicate_drops=prepared["duplicate_drops"],
        sampled=prepared["sampled"],
        train_sources=prepared["train_sources"],
        validation_sources=prepared["validation_sources"],
        test_sources=prepared["test_sources"],
        file_reports=prepared["file_reports"],
        validation_metrics=winner["validation"],
        test_metrics=test_metrics,
        estimator_meta={
            "name": "LogisticRegression",
            "candidate_id": winner["candidate_id"],
            **winner["hyperparameters"],
        },
        selection_note=(
            f"validation macro_f1 maximized among candidates with benign_fpr<={max_benign_fpr}; "
            "test metrics reported once after selection"
        ),
        training_seconds=time.monotonic() - started,
    )

    report = {
        "protocol": "offline-application-linear-model-comparison-v1",
        "created_at": datetime.now(UTC).isoformat(),
        "seed": seed,
        "max_records_per_class_per_source": max_records_per_class_per_source,
        "max_benign_fpr": max_benign_fpr,
        "selection_rule": (
            "Choose the eligible candidate with highest validation macro_f1, breaking ties by "
            "lower benign_fpr then candidate_id. Test metrics are computed only for the winner."
        ),
        "candidates": candidate_rows,
        "winner": {
            "candidate_id": winner["candidate_id"],
            "output_dir": output.relative_to(root).as_posix(),
            "version": version,
            "validation": winner["validation"],
            "test": test_metrics,
            "disqualified_reason": winner.get("disqualified_reason"),
        },
        "limitations": [
            "Comparison is limited to JSON-exportable linear logistic models for safe offline "
            "inference and exact SHAP attributions.",
            "Sampling is not representative of the full CSE-CIC-IDS2018 distribution.",
            "This does not replace frozen Stage 5 research artifacts.",
        ],
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = report_path.with_suffix(report_path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(report_path)
    return {"manifest": manifest, "comparison": report}
