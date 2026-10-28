"""Run-aware dataset assembly and preliminary evaluation for live rule windows.

Labels are accepted only from a collector-verified scenario journal. This
module never infers labels from detector outputs.
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
from collections import Counter
from pathlib import Path
from typing import Any

from src.sdn_defense.live_anomaly import read_telemetry_windows
from src.sdn_defense.live_features import LIVE_FEATURE_ORDER, LIVE_FEATURE_SCHEMA_ID
from src.sdn_defense.telemetry_audit import audit_telemetry_jsonl


class LiveDatasetError(ValueError):
    """A collection artifact cannot safely contribute labeled live features."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _scenario_journal(path: Path, *, run_id: str, scenario: str) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                raise LiveDatasetError(f"invalid scenario journal line {line_number}") from error
            if isinstance(event, dict):
                events.append(event)
    if scenario == "port-scan":
        started = next((e for e in events if e.get("event_type") == "scenario_started"), None)
        finished = next(
            (e for e in reversed(events) if e.get("event_type") == "run_completed"), None
        )
        if not isinstance(started, dict) or not isinstance(finished, dict):
            raise LiveDatasetError("port-scan journal lacks start/completion records")
        if (
            started.get("run_id") != run_id
            or started.get("scenario") != "port-scan"
            or started.get("target") != "h3"
            or finished.get("run_id") != run_id
            or finished.get("scenario_id") != scenario
        ):
            raise LiveDatasetError("port-scan label/target does not match actual journal")
        scenario_run = started.get("scenario_run")
        destination = (
            scenario_run.get("destination_scope") if isinstance(scenario_run, dict) else None
        )
        if not isinstance(destination, dict) or destination.get("ip") != "10.0.0.3":
            raise LiveDatasetError("port-scan journal does not prove the isolated h3 target")
        process_path = path.with_name("port-scan-process.json")
        try:
            process = json.loads(process_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise LiveDatasetError("port-scan process evidence is unavailable") from error
        if process.get("timeout") is not False or process.get("return_code") != 0:
            raise LiveDatasetError("port-scan workload did not complete successfully")
        return {
            "scenario_id": scenario,
            "target": "10.0.0.3",
            "process_pid": process.get("pid"),
            "process_argv": process.get("argv"),
            "process_return_code": process.get("return_code"),
            "process_timed_out": process.get("timeout"),
            "process_evidence_sha256": sha256(process_path),
        }
    metadata = next((e for e in events if e.get("record_type") == "run_metadata"), None)
    completed = next(
        (
            e
            for e in reversed(events)
            if e.get("record_type") == "run_boundary" and e.get("state") == "ended"
        ),
        None,
    )
    if not isinstance(metadata, dict) or metadata.get("run_id") != run_id:
        raise LiveDatasetError("benign scenario journal does not bind the declared run ID")
    if (
        not isinstance(completed, dict)
        or completed.get("run_id") != run_id
        or completed.get("run_status") != "complete"
    ):
        raise LiveDatasetError("benign scenario journal lacks successful completion")
    return {"scenario_id": scenario, "run_id": run_id, "completed": True}


def build_live_dataset(
    run_directories: list[Path], *, output_directory: Path, max_gap_seconds: float = 30.0
) -> dict[str, Any]:
    """Build deterministic JSONL/CSV data from verified collector outputs."""
    if not math.isfinite(max_gap_seconds) or max_gap_seconds <= 0:
        raise LiveDatasetError("max_gap_seconds must be finite and positive")
    if output_directory.exists():
        raise FileExistsError(f"refusing to overwrite dataset output: {output_directory}")
    if len(run_directories) < 3:
        raise LiveDatasetError("at least three independent collection runs are required")
    rows: list[dict[str, Any]] = []
    run_metadata: dict[str, dict[str, Any]] = {}
    hashes: dict[str, dict[str, str]] = {}
    seen_run_ids: set[str] = set()
    seen_window_ids: set[str] = set()
    for directory in run_directories:
        manifest_path = directory / "run-manifest.json"
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            summary = json.loads(
                (directory / "collection-summary.json").read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as error:
            raise LiveDatasetError(
                f"invalid or missing collection manifest in {directory}"
            ) from error
        if (
            manifest.get("state") != "VERIFIED_FOR_RESEARCH_DATASET"
            or manifest.get("source_type") != "LIVE"
            or manifest.get("cleanup_verified") is not True
        ):
            raise LiveDatasetError(f"run is not verified live evidence: {directory}")
        if manifest.get("summary_sha256") != sha256(directory / "collection-summary.json"):
            raise LiveDatasetError(f"collection summary hash mismatch: {directory}")
        run_ids = summary.get("run_ids")
        scoped_files = summary.get("telemetry_files")
        evidence = manifest.get("scenario_evidence")
        if not all(isinstance(item, dict) for item in (run_ids, scoped_files, evidence)):
            raise LiveDatasetError(f"run lacks scenario/telemetry provenance: {directory}")
        for scenario, label in (
            ("controlled-connectivity-observation", "BENIGN"),
            ("port-scan", "PORT_SCAN"),
        ):
            run_id = run_ids.get(scenario)
            if not isinstance(run_id, str) or not run_id or run_id in seen_run_ids:
                raise LiveDatasetError("missing or duplicate independent run ID")
            seen_run_ids.add(run_id)
            if evidence.get(scenario, {}).get("run_id") != run_id:
                raise LiveDatasetError("scenario evidence run ID mismatch")
            journal_name = "benign-run.jsonl" if label == "BENIGN" else "port-scan-run.jsonl"
            journal_path = directory / journal_name
            scenario_evidence = _scenario_journal(journal_path, run_id=run_id, scenario=scenario)
            telemetry_name = scoped_files.get(scenario)
            if not isinstance(telemetry_name, str) or Path(telemetry_name).name != telemetry_name:
                raise LiveDatasetError("unsafe or missing run-scoped telemetry path")
            telemetry_path = directory / telemetry_name
            audit_summary = manifest.get("scenario_audits", {}).get(scenario, {})
            if audit_summary.get("status") != "AUDIT_COMPLETE":
                raise LiveDatasetError("scenario telemetry audit is not complete")
            if audit_summary.get("telemetry_sha256") != sha256(telemetry_path):
                raise LiveDatasetError("scenario telemetry artifact hash mismatch")
            audit = audit_telemetry_jsonl(telemetry_path)
            if audit.get("status") != "AUDIT_COMPLETE":
                raise LiveDatasetError(f"telemetry audit failed: {audit.get('issues')}")
            windows, _ = read_telemetry_windows(telemetry_path, max_gap_seconds=max_gap_seconds)
            if not windows or any(window.run_id != run_id for window in windows):
                raise LiveDatasetError("no eligible windows or run provenance mismatch")
            hashes[run_id] = {
                "telemetry_sha256": sha256(telemetry_path),
                "journal_sha256": sha256(journal_path),
                "run_manifest_sha256": sha256(manifest_path),
                "collection_summary_sha256": sha256(directory / "collection-summary.json"),
                "scenario": scenario,
            }
            if label == "PORT_SCAN":
                hashes[run_id]["process_evidence_sha256"] = sha256(
                    journal_path.with_name("port-scan-process.json")
                )
            run_metadata[run_id] = {
                "label": label,
                "scenario": scenario,
                "collection_id": manifest.get("collection_id"),
                "artifact": str(telemetry_path),
                "scenario_evidence": scenario_evidence,
                "eligible_windows": len(windows),
            }
            for window in windows:
                if window.window_id in seen_window_ids:
                    raise LiveDatasetError(f"duplicate feature window ID: {window.window_id}")
                seen_window_ids.add(window.window_id)
                features = [window.features[name] for name in LIVE_FEATURE_ORDER]
                if not all(math.isfinite(value) and value >= 0 for value in features):
                    raise LiveDatasetError("feature row contains invalid values")
                rows.append(
                    {
                        "window_id": window.window_id,
                        "run_id": run_id,
                        "scenario": scenario,
                        "ground_truth": label,
                        "source_type": "LIVE",
                        "feature_schema_id": LIVE_FEATURE_SCHEMA_ID,
                        "feature_order": list(LIVE_FEATURE_ORDER),
                        "features": window.features,
                        "source_artifact": str(telemetry_path),
                        "source_sha256": window.source_sha256,
                        "source_record_ids": list(window.source_record_ids),
                        "start_at": window.start_at,
                        "end_at": window.end_at,
                        "datapath_id": window.datapath_id,
                        "datapath_epoch_id": window.datapath_epoch_id,
                        "rule_identity_id": window.rule_identity_id,
                    }
                )
    if {metadata["label"] for metadata in run_metadata.values()} != {"BENIGN", "PORT_SCAN"}:
        raise LiveDatasetError("both verified scenario classes are required")
    output_directory.mkdir(parents=True)
    jsonl = output_directory / "windows.jsonl"
    with jsonl.open("x", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")
    csv_path = output_directory / "windows.csv"
    with csv_path.open("x", encoding="utf-8", newline="") as stream:
        fields = ["window_id", "run_id", "ground_truth", *LIVE_FEATURE_ORDER]
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "window_id": row["window_id"],
                    "run_id": row["run_id"],
                    "ground_truth": row["ground_truth"],
                    **row["features"],
                }
            )
    classes = Counter(str(row["ground_truth"]) for row in rows)
    manifest = {
        "schema_version": 1,
        "dataset_id": output_directory.name,
        "source_type": "LIVE",
        "feature_schema_id": LIVE_FEATURE_SCHEMA_ID,
        "feature_order": list(LIVE_FEATURE_ORDER),
        "label_origin": "collector-verified scenario run journal; never model output",
        "split_method": (
            "complete run IDs assigned to train/validation/test in deterministic SHA-256 order"
        ),
        "run_splits": _assign_run_splits(run_metadata),
        "run_metadata": run_metadata,
        "input_artifacts": hashes,
        "class_counts": dict(sorted(classes.items())),
        "run_sample_counts": dict(sorted(Counter(str(row["run_id"]) for row in rows).items())),
        "window_count": len(rows),
        "rows_sha256": sha256(jsonl),
        "csv_sha256": sha256(csv_path),
        "limitations": [
            "Only controlled benign connectivity and bounded port-scan scenarios are represented.",
            "Windows within a run are correlated; independent unit is the run.",
            "The three runs per scenario support only a preliminary one-run-per-split evaluation.",
            "Port-scan labels describe the orchestrated workload, not arbitrary attack identity.",
        ],
    }
    (output_directory / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def _assign_run_splits(metadata: dict[str, dict[str, Any]]) -> dict[str, str]:
    by_class: dict[str, list[str]] = {}
    for run_id, value in metadata.items():
        by_class.setdefault(str(value["label"]), []).append(run_id)
    splits: dict[str, str] = {}
    for label, run_ids in by_class.items():
        ordered = sorted(run_ids, key=lambda run_id: hashlib.sha256(run_id.encode()).hexdigest())
        if len(ordered) < 3:
            raise LiveDatasetError(f"class {label} needs at least three independent runs")
        for index, run_id in enumerate(ordered):
            split = ("train", "validation", "test")[index] if index < 3 else "train"
            splits[run_id] = split
    return splits


def train_preliminary_live_model(
    *, dataset_manifest_path: Path, output_directory: Path, maximum_validation_fpr: float = 0.10
) -> dict[str, Any]:
    """Fit a transparent logistic baseline using run-separated partitions.

    The returned model is always unapproved. The tiny independent run count in
    this initial lab dataset is not a basis for operational attack detection.
    """
    if not 0 < maximum_validation_fpr < 1:
        raise LiveDatasetError("maximum_validation_fpr must be between zero and one")
    if output_directory.exists():
        raise FileExistsError(f"refusing to overwrite model output: {output_directory}")
    try:
        import joblib
        import sklearn
        from joblib import dump
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import confusion_matrix, f1_score, precision_recall_fscore_support
        from sklearn.preprocessing import StandardScaler
    except ImportError as error:
        raise LiveDatasetError(
            "scikit-learn/joblib are required for live baseline training"
        ) from error
    manifest_path = dataset_manifest_path.resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    data_path = manifest_path.parent / "windows.jsonl"
    if manifest.get("feature_schema_id") != LIVE_FEATURE_SCHEMA_ID:
        raise LiveDatasetError("dataset feature schema is incompatible")
    if manifest.get("rows_sha256") != sha256(data_path):
        raise LiveDatasetError("dataset row artifact hash mismatch")
    if manifest.get("feature_order") != list(LIVE_FEATURE_ORDER):
        raise LiveDatasetError("dataset feature order is incompatible")
    split_by_run = manifest.get("run_splits")
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    with data_path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise LiveDatasetError(f"invalid dataset JSONL line {line_number}") from error
            if (
                not isinstance(record, dict)
                or record.get("feature_schema_id") != LIVE_FEATURE_SCHEMA_ID
            ):
                raise LiveDatasetError(f"incompatible record on dataset line {line_number}")
            window_id = record.get("window_id")
            run_id = record.get("run_id")
            if not isinstance(window_id, str) or window_id in seen:
                raise LiveDatasetError("duplicate or missing window ID")
            if not isinstance(run_id, str) or not isinstance(split_by_run, dict):
                raise LiveDatasetError("dataset run split metadata is missing")
            if record.get("ground_truth") not in {"BENIGN", "PORT_SCAN"}:
                raise LiveDatasetError("unsupported or missing ground-truth label")
            feature_values = record.get("features")
            if not isinstance(feature_values, dict) or set(feature_values) != set(
                LIVE_FEATURE_ORDER
            ):
                raise LiveDatasetError("feature values do not match exact live schema")
            vector = [feature_values[name] for name in LIVE_FEATURE_ORDER]
            if any(
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value < 0
                for value in vector
            ):
                raise LiveDatasetError("dataset contains invalid feature values")
            seen.add(window_id)
            record["split"] = split_by_run.get(run_id)
            records.append(record)
    labels = ["BENIGN", "PORT_SCAN"]
    splits: dict[str, list[dict[str, Any]]] = {
        name: [row for row in records if row["split"] == name]
        for name in ("train", "validation", "test")
    }
    for name, rows in splits.items():
        if {row["ground_truth"] for row in rows} != set(labels):
            raise LiveDatasetError(f"{name} split must contain both ground-truth classes")
    if len({row["run_id"] for row in splits["train"]}) < 2:
        raise LiveDatasetError("training split requires independent runs from both classes")

    def feature_matrix(rows: list[dict[str, Any]]) -> list[list[float]]:
        return [[row["features"][key] for key in LIVE_FEATURE_ORDER] for row in rows]

    def labels_for(rows: list[dict[str, Any]]) -> list[str]:
        return [str(row["ground_truth"]) for row in rows]

    scaler = StandardScaler()
    x_train = scaler.fit_transform(feature_matrix(splits["train"]))
    classifier = LogisticRegression(random_state=42, class_weight="balanced", max_iter=1000)
    classifier.fit(x_train, labels_for(splits["train"]))
    validation_scores = classifier.decision_function(
        scaler.transform(feature_matrix(splits["validation"]))
    )
    validation_y = labels_for(splits["validation"])
    benign_indices = [i for i, label in enumerate(validation_y) if label == "BENIGN"]
    candidate_thresholds = sorted({float(value) for value in validation_scores})
    eligible: list[tuple[float, float, float]] = []
    for threshold in candidate_thresholds:
        predictions = [
            "PORT_SCAN" if value >= threshold else "BENIGN" for value in validation_scores
        ]
        fpr = sum(predictions[i] == "PORT_SCAN" for i in benign_indices) / len(benign_indices)
        recall = sum(
            prediction == label == "PORT_SCAN"
            for prediction, label in zip(predictions, validation_y, strict=True)
        ) / max(1, sum(label == "PORT_SCAN" for label in validation_y))
        if fpr <= maximum_validation_fpr:
            eligible.append((recall, -fpr, threshold))
    threshold = max(candidate_thresholds) if not eligible else max(eligible)[2]
    test_scores = classifier.decision_function(scaler.transform(feature_matrix(splits["test"])))
    test_y = labels_for(splits["test"])
    test_predictions = ["PORT_SCAN" if value >= threshold else "BENIGN" for value in test_scores]
    transformed_test = scaler.transform(feature_matrix(splits["test"]))
    detailed_predictions: list[dict[str, Any]] = []
    for index, row in enumerate(splits["test"]):
        contributions = {
            feature: float(
                classifier.coef_[0][feature_index] * transformed_test[index][feature_index]
            )
            for feature_index, feature in enumerate(LIVE_FEATURE_ORDER)
        }
        reconstructed = float(classifier.intercept_[0] + sum(contributions.values()))
        if not math.isclose(reconstructed, float(test_scores[index]), rel_tol=1e-10, abs_tol=1e-10):
            raise LiveDatasetError("linear explanation does not reconcile with model score")
        detailed_predictions.append(
            {
                "window_id": row["window_id"],
                "run_id": row["run_id"],
                "actual_label": test_y[index],
                "predicted_label": test_predictions[index],
                "decision_score": float(test_scores[index]),
                "threshold": threshold,
                "source_type": row["source_type"],
                "source_artifact": row["source_artifact"],
                "source_sha256": row["source_sha256"],
                "source_record_ids": row["source_record_ids"],
                "features": row["features"],
                "explanation_method": "standardized-logistic-contributions-v1",
                "intercept": float(classifier.intercept_[0]),
                "contributions": contributions,
                "reconstructed_decision_score": reconstructed,
            }
        )
    matrix = confusion_matrix(test_y, test_predictions, labels=labels).tolist()
    precision, recall, f1, support = precision_recall_fscore_support(
        test_y, test_predictions, labels=labels, zero_division=0
    )
    per_run: dict[str, Any] = {}
    for run_id in sorted({str(row["run_id"]) for row in splits["test"]}):
        indices = [i for i, row in enumerate(splits["test"]) if row["run_id"] == run_id]
        per_run[run_id] = {
            "ground_truth": splits["test"][indices[0]]["ground_truth"],
            "sample_count": len(indices),
            "macro_f1": float(
                f1_score(
                    [test_y[i] for i in indices],
                    [test_predictions[i] for i in indices],
                    labels=labels,
                    average="macro",
                    zero_division=0,
                )
            ),
            "predictions": [test_predictions[i] for i in indices],
            "scores": [float(test_scores[i]) for i in indices],
        }
    benign_index, attack_index = labels.index("BENIGN"), labels.index("PORT_SCAN")
    report: dict[str, Any] = {
        "schema_version": 1,
        "status": "TRAINED_UNAPPROVED_PRELIMINARY",
        "model_id": "stage7-live-logistic-preliminary",
        "model_version": "0.1.0",
        "task": "controlled benign-connectivity versus bounded port-scan scenario classification",
        "feature_schema_id": LIVE_FEATURE_SCHEMA_ID,
        "feature_order": list(LIVE_FEATURE_ORDER),
        "training_data_manifest": str(manifest_path),
        "training_data_manifest_sha256": sha256(manifest_path),
        "dataset_sha256": manifest["rows_sha256"],
        "run_counts_by_split": {
            name: len({row["run_id"] for row in rows}) for name, rows in splits.items()
        },
        "training_run_ids": sorted({str(row["run_id"]) for row in splits["train"]}),
        "run_ids_by_split": {
            name: sorted({str(row["run_id"]) for row in rows}) for name, rows in splits.items()
        },
        "sample_counts_by_split": {
            name: dict(sorted(Counter(row["ground_truth"] for row in rows).items()))
            for name, rows in splits.items()
        },
        "threshold": threshold,
        "threshold_selection": {
            "split": "validation",
            "objective": (
                "maximize port-scan recall subject to a benign false-positive rate constraint"
            ),
            "maximum_benign_false_positive_rate": maximum_validation_fpr,
            "fallback": "highest validation decision score if no candidate meets the constraint",
            "score_semantics": "logistic decision function; not a calibrated probability",
        },
        "held_out_test": {
            "labels_order": labels,
            "confusion_matrix": matrix,
            "per_class": {
                label: {
                    "precision": float(precision[index]),
                    "recall": float(recall[index]),
                    "f1": float(f1[index]),
                    "support": int(support[index]),
                }
                for index, label in enumerate(labels)
            },
            "macro_f1": float(
                f1_score(test_y, test_predictions, labels=labels, average="macro", zero_division=0)
            ),
            "benign_false_positive_rate": matrix[benign_index][attack_index]
            / max(1, sum(matrix[benign_index])),
            "port_scan_false_negative_rate": matrix[attack_index][benign_index]
            / max(1, sum(matrix[attack_index])),
            "per_run": per_run,
            "predictions": detailed_predictions,
            "limitations": (
                "One held-out run per class; results are uncertain and not approval evidence."
            ),
        },
        "explanation": {
            "method": "standardized logistic-regression signed feature contributions",
            "reconciliation": "intercept + sum(contribution_i) equals decision_function score",
            "contribution_formula": "coef_i * ((feature_i - train_mean_i) / train_scale_i)",
            "probability_calibration": "not evaluated; score is not a probability",
        },
        "preprocessing": {
            "method": "StandardScaler",
            "fit_split": "train only",
            "feature_order": list(LIVE_FEATURE_ORDER),
        },
        "dependencies": {
            "scikit_learn": sklearn.__version__,
            "joblib": joblib.__version__,
        },
        "live_approved": False,
        "limitations": [
            "Three independent runs per scenario; each split has one run per class.",
            "The test set represents one benign run and one port-scan run only.",
            "This model is deliberately not approved for live operation.",
            "A positive class means the controlled port-scan workload, not arbitrary intrusion.",
        ],
    }
    output_directory.mkdir(parents=True)
    model_path = output_directory / "model.joblib"
    dump(
        {"scaler": scaler, "classifier": classifier, "feature_order": list(LIVE_FEATURE_ORDER)},
        model_path,
    )
    reloaded = joblib.load(model_path)
    first_test_score = float(
        reloaded["classifier"].decision_function(
            reloaded["scaler"].transform(feature_matrix(splits["test"][:1]))
        )[0]
    )
    if not math.isclose(
        first_test_score,
        float(detailed_predictions[0]["decision_score"]),
        rel_tol=1e-12,
        abs_tol=1e-12,
    ):
        raise LiveDatasetError("reloaded artifact score differs from recorded test inference")
    report["artifact"] = model_path.name
    report["artifact_sha256"] = sha256(model_path)
    report["artifact_reload_check"] = {
        "status": "PASS",
        "test_window_id": detailed_predictions[0]["window_id"],
        "decision_score": first_test_score,
    }
    report["model_file_trusted_local_only"] = True
    (output_directory / "manifest.json").write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    return report
