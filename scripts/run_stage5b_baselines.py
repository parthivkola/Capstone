"""Run the pre-registered Stage 5B UNSW-NB15 official-split baselines."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
import sklearn

from ml.evaluation.baselines import (
    TrainOnlyTabularEncoder,
    evaluate_predictions,
    majority_predictions,
    run_isolation_forest,
    run_random_forest,
)
from ml.evaluation.splits import SplitManifest, random_stratified_split

ROOT = Path(__file__).resolve().parents[1]
TRAIN_REL = Path(
    "data/raw/unsw-nb15/CSV Files/Training and Testing Sets/UNSW_NB15_training-set.csv"
)
TEST_REL = Path("data/raw/unsw-nb15/CSV Files/Training and Testing Sets/UNSW_NB15_testing-set.csv")
SEED = 2026
TARGET = "attack_cat"
N_ESTIMATORS = 100
MAX_DEPTH = 18
MIN_SAMPLES_LEAF = 2


def _read_csv(path: Path) -> tuple[list[dict[str, str]], list[str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        rows = [dict(row) for row in reader]
        if reader.fieldnames is None:
            raise ValueError(f"missing header: {path}")
        return rows, list(reader.fieldnames)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _distribution(labels: list[str]) -> dict[str, int]:
    return dict(sorted(Counter(labels).items()))


def _affected_values(rows: list[dict[str, str]], features: tuple[str, ...]) -> dict[str, Any]:
    affected = {name: 0 for name in features}
    rows_affected = 0
    for row in rows:
        row_affected = False
        for name in features:
            token = row.get(name, "").strip()
            if not token or token.casefold() in {"?", "na", "n/a", "null", "none"}:
                affected[name] += 1
                row_affected = True
                continue
            try:
                number = float(token)
            except ValueError:
                continue
            if not np.isfinite(number):
                affected[name] += 1
                row_affected = True
        rows_affected += int(row_affected)
    return {"rows_with_missing_or_nonfinite_feature": rows_affected, "per_feature": affected}


def _metrics_binary(truth: list[str], predictions: list[str]) -> dict[str, Any]:
    binary_truth = ["Normal" if label == "Normal" else "Attack" for label in truth]
    return evaluate_predictions(binary_truth, predictions, class_labels=["Normal", "Attack"])


def run(root: Path, output_dir: Path) -> dict[str, Any]:
    train_path, test_path = root / TRAIN_REL, root / TEST_REL
    if not train_path.is_file() or not test_path.is_file():
        raise FileNotFoundError("both official UNSW-NB15 train and test files are required")
    train_rows, columns = _read_csv(train_path)
    test_rows, test_columns = _read_csv(test_path)
    if columns != test_columns or TARGET not in columns:
        raise ValueError("official train/test schema mismatch or missing target")
    train_labels = [row[TARGET].strip() for row in train_rows]
    test_labels = [row[TARGET].strip() for row in test_rows]

    inner = random_stratified_split(train_labels, seed=SEED, test_fraction=0.2)
    fit_indices = inner.train_indices
    validation_indices = inner.test_indices
    test_indices = tuple(range(len(test_rows)))
    fit_rows = [train_rows[index] for index in fit_indices]
    fit_labels = [train_labels[index] for index in fit_indices]
    validation_rows = [train_rows[index] for index in validation_indices]
    validation_labels = [train_labels[index] for index in validation_indices]
    feature_names = tuple(name for name in columns if name not in {TARGET, "label", "id"})
    encoder = TrainOnlyTabularEncoder(requested_features=feature_names).fit(fit_rows)
    x_fit = encoder.transform(fit_rows)
    x_validation = encoder.transform(validation_rows)
    x_test = encoder.transform(test_rows)

    split = SplitManifest(
        strategy="official_train_test_with_train_only_stratified_validation",
        seed=SEED,
        train_indices=tuple(int(i) for i in fit_indices),
        validation_indices=tuple(int(i) for i in validation_indices),
        test_indices=test_indices,
        input_distribution=_distribution(train_labels),
        train_distribution=_distribution(fit_labels),
        validation_distribution=_distribution(validation_labels),
        test_distribution=_distribution(test_labels),
        notes=(
            "Official testing-set rows are untouched until final evaluation.",
            "The 20% validation partition is sampled only from official training data.",
            "Reference split is stratified and is not treated as source-independent evidence.",
        ),
    )
    test_metrics: dict[str, Any] = {}
    majority = majority_predictions(fit_labels, len(test_labels))
    test_metrics["majority_class"] = {
        "predicted_class": majority[0],
        "metrics": evaluate_predictions(test_labels, majority),
    }
    rf_predictions, rf_timing = run_random_forest(
        x_fit,
        fit_labels,
        x_test,
        seed=SEED,
        n_estimators=N_ESTIMATORS,
        max_depth=MAX_DEPTH,
        min_samples_leaf=MIN_SAMPLES_LEAF,
    )
    test_metrics["random_forest"] = {
        "parameters": {
            "n_estimators": N_ESTIMATORS,
            "max_depth": MAX_DEPTH,
            "max_features": "sqrt",
            "min_samples_leaf": MIN_SAMPLES_LEAF,
            "class_weight": "balanced_subsample",
            "random_state": SEED,
            "n_jobs": 1,
        },
        "timing": rf_timing,
        "metrics": evaluate_predictions(test_labels, rf_predictions),
    }
    truth_binary = ["Normal" if label == "Normal" else "Attack" for label in test_labels]
    anomaly_predictions, anomaly_timing = run_isolation_forest(
        x_fit,
        fit_labels,
        x_validation,
        validation_labels,
        x_test,
        seed=SEED,
    )
    test_metrics["isolation_forest"] = {
        "parameters": {
            "n_estimators": 100,
            "fit_population": "Normal rows in training partition only",
            "threshold": "5th percentile of validation Normal decision_function scores",
            "random_state": SEED,
            "n_jobs": 1,
        },
        "timing": anomaly_timing,
        "metrics": evaluate_predictions(
            truth_binary, anomaly_predictions, class_labels=["Normal", "Attack"]
        ),
    }

    audit = json.loads(
        (root / "docs/research/dataset-audit/stage5a-dataset-audit.json").read_text()
    )
    dataset_audit = next(item for item in audit["datasets"] if item["name"] == "UNSW-NB15")
    inventory = {item["path"]: item for item in dataset_audit["inventory"]}
    artifact: dict[str, Any] = {
        "stage": "5B",
        "generated_at_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "dataset": "UNSW-NB15 official train/test files only",
        "target": TARGET,
        "task": (
            "10-class known-attack classification; Isolation Forest evaluated as benign-vs-attack"
        ),
        "label_mapping": {"attack_cat": "preserved source labels; Normal is benign"},
        "provenance": {
            "training_file": {"path": TRAIN_REL.as_posix(), "sha256": _sha256(train_path)},
            "test_file": {"path": TEST_REL.as_posix(), "sha256": _sha256(test_path)},
            "stage5a_inventory_entries": [inventory[p.as_posix()] for p in (TRAIN_REL, TEST_REL)],
        },
        "split": split.as_dict(),
        "features": {
            "candidate_columns": list(feature_names),
            "fitted_columns": list(encoder.feature_names_),
            "excluded": {
                "id": "row identifier",
                "label": "separate binary target",
                TARGET: "target",
            },
            "numeric": list(encoder.numeric_features_),
            "categorical": list(encoder.categorical_features_),
            "one_hot_feature_names": list(encoder.vectorizer_.get_feature_names_out()),
            "missing_nonfinite_in_training": _affected_values(fit_rows, encoder.feature_names_),
            "policy": (
                "Training-only numeric/categorical inference; numeric median and categorical "
                "mode and one-hot vocabulary fitted on training partition; unseen categories "
                "ignored."
            ),
        },
        "duplicate_policy": {
            "remove_duplicates": False,
            "stage5a_dataset_wide_within_file_duplicates_across_six_analysis_files": 480629,
            "official_training_file_duplicate_rows": 0,
            "official_testing_file_duplicate_rows": 0,
            "official_train_test_exact_shared_row_signatures": 0,
        },
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "numpy": np.__version__,
            "scikit_learn": sklearn.__version__,
        },
        "results": test_metrics,
        "limitations": [
            "This is the official UNSW-NB15 pair only, not the four raw partitions.",
            "The result is not cross-dataset generalization evidence.",
            "Official split provenance is preserved; inner validation is a seeded random "
            "stratified split of official training data.",
        ],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "unsw-nb15-official-baselines.json").write_text(
        json.dumps(artifact, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    return artifact


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("experiments/stage5b"),
    )
    args = parser.parse_args()
    output = args.output_dir if args.output_dir.is_absolute() else args.root / args.output_dir
    report = run(args.root.resolve(), output)
    print(f"Wrote {output / 'unsw-nb15-official-baselines.json'}")
    for name, result in report["results"].items():
        metrics = result["metrics"]
        print(f"{name}: macro_f1={metrics['macro_f1']:.6f}, accuracy={metrics['accuracy']:.6f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
