"""Read-only adapters for existing, traceable project artifacts.

No data are copied, normalized, or relabeled. Historical model predictions are
not available as row-level files; prepared dataset labels remain source labels,
and telemetry is exposed only with its audit result.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import json
import math
from pathlib import Path
from typing import Any

RESULT_ARTIFACTS: tuple[tuple[str, str], ...] = (
    ("unsw-stage5b-baselines", "experiments/stage5b/unsw-nb15-official-baselines.json"),
    ("cse-stage5d-holdouts", "experiments/stage5d/cse-source-holdout-rf.json"),
    ("cse-stage5e2a-closed-set", "experiments/stage5e/cse-unseen-loic-http-closed-set-rf.json"),
    (
        "cse-stage5e2b-isolation-forest",
        "experiments/stage5e/cse-unseen-loic-http-isolation-forest.json",
    ),
    ("cse-stage5e2c-open-set", "experiments/stage5e/cse-unseen-loic-http-rf-open-set.json"),
    ("cse-stage5f-source-shift", "experiments/stage5f/source-distribution-shift-results.json"),
)

PREPARATION_MANIFEST = "experiments/stage5d/cse-preparation.json"
TELEMETRY_ROOT = "experiments/stage7-telemetry"
RAW_DATASET_ROOTS: tuple[tuple[str, str], ...] = (
    ("CIC-IDS2017", "data/raw/cicids2017"),
    ("CSE-CIC-IDS2018", "data/raw/cse-cic-ids2018"),
    ("UNSW-NB15", "data/raw/unsw-nb15"),
    ("TON_IoT mirror", "data/raw/ton-iot"),
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _reject_nonfinite(value: Any, *, location: str = "root") -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"non-finite JSON number in {location}")
    if isinstance(value, dict):
        for key, nested in value.items():
            _reject_nonfinite(nested, location=f"{location}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _reject_nonfinite(nested, location=f"{location}[{index}]")


class ProjectDataSources:
    """Discover and load an explicit allowlist of read-only local artifacts."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self._memo: dict[str, dict[str, Any]] = {}

    def _path(self, relative_path: str) -> Path:
        path = (self.root / relative_path).resolve()
        if not path.is_relative_to(self.root):
            raise ValueError("artifact path escapes the project root")
        return path

    def _json_artifact(self, relative_path: str) -> dict[str, Any]:
        path = self._path(relative_path)
        if not path.is_file():
            raise FileNotFoundError(f"required artifact is missing: {relative_path}")
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError(f"artifact must contain a JSON object: {relative_path}")
        _reject_nonfinite(value)
        return value

    def historical_results(self) -> dict[str, Any]:
        if "historical_results" in self._memo:
            return self._memo["historical_results"]
        records: list[dict[str, Any]] = []
        unavailable: list[dict[str, str]] = []
        for source_id, relative_path in RESULT_ARTIFACTS:
            path = self._path(relative_path)
            if not path.is_file():
                unavailable.append({"source_id": source_id, "artifact": relative_path})
                continue
            try:
                document = self._json_artifact(relative_path)
                records.extend(self._result_records(source_id, relative_path, document))
            except (OSError, ValueError, TypeError, AttributeError, json.JSONDecodeError) as error:
                unavailable.append(
                    {"source_id": source_id, "artifact": relative_path, "reason": str(error)}
                )
        result = {
            "source_type": "HISTORICAL_EXPERIMENT_RESULT",
            "records": records,
            "unavailable_artifacts": unavailable,
            "record_semantics": "Recorded aggregate evaluation results; not live detections.",
        }
        self._memo["historical_results"] = result
        return result

    def _result_records(
        self, source_id: str, relative_path: str, document: dict[str, Any]
    ) -> list[dict[str, Any]]:
        base = {
            "source_id": source_id,
            "source_type": "HISTORICAL_EXPERIMENT_RESULT",
            "artifact": relative_path,
            "artifact_sha256": _sha256(self._path(relative_path)),
            "stage": document.get("stage"),
            "experiment_id": document.get("experiment_id"),
            "dataset": document.get("dataset"),
            "condition": document.get("condition"),
            "recorded_at": document.get("generated_at_utc"),
            "limitations": document.get("limitations", []),
            "historical_only": True,
        }
        result: list[dict[str, Any]] = []
        if source_id == "unsw-stage5b-baselines":
            split = document.get("split", {})
            for model_name, output in document.get("results", {}).items():
                if not isinstance(output, dict) or not isinstance(output.get("metrics"), dict):
                    continue
                result.append(
                    {
                        **base,
                        "experiment_id": document.get("experiment_id"),
                        "model": model_name,
                        "model_configuration": output.get("parameters"),
                        "split": {
                            "strategy": split.get("strategy"),
                            "seed": split.get("seed"),
                            "notes": split.get("notes", []),
                        },
                        "metrics": output["metrics"],
                    }
                )
        elif source_id == "cse-stage5d-holdouts":
            for holdout in document.get("holdouts", []):
                if not isinstance(holdout, dict) or not isinstance(holdout.get("metrics"), dict):
                    continue
                result.append(
                    {
                        **base,
                        "experiment_id": holdout.get("holdout_id"),
                        "model": "RandomForestClassifier",
                        "model_configuration": holdout.get("model"),
                        "split": {
                            "holdout_id": holdout.get("holdout_id"),
                            "train_sources": holdout.get("train_sources"),
                            "test_sources": holdout.get("test_sources"),
                        },
                        "metrics": holdout["metrics"],
                    }
                )
        elif source_id == "cse-stage5e2a-closed-set":
            result.append(
                {
                    **base,
                    "model": document.get("model", {}).get("name"),
                    "model_configuration": document.get("model"),
                    "split": {
                        "training_rows": document.get("training_rows"),
                        "test_rows": document.get("test_rows"),
                        "test_source": document.get("unseen_label"),
                    },
                    "metrics": document.get("metrics"),
                }
            )
        elif source_id in {"cse-stage5e2b-isolation-forest", "cse-stage5e2c-open-set"}:
            result.append(
                {
                    **base,
                    "model": document.get("model", {}).get("name"),
                    "model_configuration": document.get("model"),
                    "split": {
                        "training_rows": document.get("train_rows", document.get("training_rows")),
                        "validation_rows": document.get("validation_rows"),
                        "test_rows": document.get("test_rows"),
                        "test_source": document.get("test_source"),
                    },
                    "metrics": document.get("primary_metrics", document.get("metrics")),
                }
            )
        elif source_id == "cse-stage5f-source-shift":
            result.append(
                {
                    **base,
                    "model": document.get("protocol_configuration", {})
                    .get("model", {})
                    .get("architecture"),
                    "model_configuration": document.get("protocol_configuration", {}).get("model"),
                    "split": document.get("protocol_configuration", {}).get("source_order"),
                    "metrics": {
                        "summary_mean_std_across_seeds": document.get(
                            "summary_mean_std_across_seeds"
                        ),
                        "adaptation_summary": document.get("adaptation_summary"),
                    },
                }
            )
        return result

    def dataset_sources(self) -> dict[str, Any]:
        if "dataset_sources" in self._memo:
            return self._memo["dataset_sources"]
        manifest_path = self._path(PREPARATION_MANIFEST)
        if not manifest_path.is_file():
            return {
                "source_type": "PREPARED_LABELED_DATASET",
                "status": "UNAVAILABLE",
                "reason": f"Preparation manifest missing: {PREPARATION_MANIFEST}",
                "files": [],
            }
        try:
            manifest = self._json_artifact(PREPARATION_MANIFEST)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            return {
                "source_type": "PREPARED_LABELED_DATASET",
                "status": "UNAVAILABLE",
                "reason": f"Preparation manifest invalid: {error}",
                "files": [],
            }
        statistics = manifest.get("source_statistics", [])
        if not isinstance(statistics, list):
            return {
                "source_type": "PREPARED_LABELED_DATASET",
                "status": "UNAVAILABLE",
                "reason": "Preparation manifest source_statistics must be a list.",
                "files": [],
            }
        files: list[dict[str, Any]] = []
        for stats in statistics:
            if not isinstance(stats, dict):
                continue
            filename = stats.get("file")
            if not isinstance(filename, str) or Path(filename).name != filename:
                continue
            output_name = Path(str(stats.get("output_path", ""))).name
            if not output_name.endswith(".model-ready.csv.gz"):
                continue
            relative_path = f"data/processed/stage5d/cse-cic-ids2018/{output_name}"
            path = self._path(relative_path)
            exists = path.is_file()
            expected_size = stats.get("output_size_bytes")
            size_matches = (
                exists and isinstance(expected_size, int) and path.stat().st_size == expected_size
            )
            files.append(
                {
                    "file_id": filename,
                    "artifact": relative_path,
                    "available": bool(size_matches),
                    "size_bytes": path.stat().st_size if exists else None,
                    "manifest_size_bytes": expected_size,
                    "artifact_sha256": stats.get("output_sha256"),
                    "manifest_row_count": stats.get("final_usable_row_count"),
                    "label_vocabulary": stats.get("label_vocabulary", []),
                    "feature_count": stats.get("feature_count"),
                    "feature_names": stats.get("feature_names", []),
                }
            )
        result = {
            "source_type": "PREPARED_LABELED_DATASET",
            "source_id": "cse-cic-ids2018-stage5d",
            "status": "AVAILABLE" if any(f["available"] for f in files) else "UNAVAILABLE",
            "dataset": "CSE-CIC-IDS2018",
            "stage": "5D prepared input; no prediction file",
            "preparation_manifest": PREPARATION_MANIFEST,
            "files": files,
            "record_semantics": "Original Label column; not an application prediction.",
            "sampling_policy": (
                "First N data rows of the selected prepared file; deterministic prefix, "
                "not representative sampling."
            ),
        }
        self._memo["dataset_sources"] = result
        return result

    def _prepared_file_context(self, file_id: str) -> dict[str, Any]:
        catalog = self.dataset_sources()
        match = next((item for item in catalog["files"] if item["file_id"] == file_id), None)
        if match is None:
            raise ValueError("unknown prepared dataset file id")
        if not match["available"]:
            raise FileNotFoundError(f"prepared dataset artifact unavailable: {match['artifact']}")
        path = self._path(match["artifact"])
        expected_hash = match.get("artifact_sha256")
        actual_hash = _sha256(path)
        if actual_hash != expected_hash:
            raise ValueError("prepared dataset artifact hash does not match frozen manifest")
        feature_names = match.get("feature_names")
        if not isinstance(feature_names, list) or not feature_names:
            raise ValueError("prepared feature schema missing from manifest")
        return {
            "match": match,
            "path": path,
            "actual_hash": actual_hash,
            "feature_names": feature_names,
            "vocabulary": match.get("label_vocabulary", []),
        }

    @staticmethod
    def _parse_prepared_row(
        *,
        row: dict[str, str | None],
        row_number: int,
        feature_names: list[str],
        vocabulary: list[str],
        artifact: str,
        actual_hash: str,
    ) -> dict[str, Any]:
        if None in row or any(value is None for value in row.values()):
            raise ValueError(f"malformed prepared CSV row {row_number}")
        label = row.pop("Label")
        if label not in vocabulary:
            raise ValueError(f"row {row_number} label is absent from manifest vocabulary")
        if set(row) != set(feature_names):
            raise ValueError(f"row {row_number} feature names do not match frozen schema")
        parsed_features: dict[str, float] = {}
        for feature_name in feature_names:
            raw_value = row[feature_name]
            try:
                value = float(raw_value)  # type: ignore[arg-type]
            except (TypeError, ValueError) as error:
                raise ValueError(f"row {row_number} has non-numeric {feature_name}") from error
            if not math.isfinite(value):
                raise ValueError(f"row {row_number} has non-finite {feature_name}")
            parsed_features[feature_name] = value
        return {
            "record_type": "PREPARED_DATASET_ROW",
            "source_type": "REAL_DATASET_RECORD",
            "source_label": label,
            "label_semantics": "Original dataset Label field; not a model prediction.",
            "prediction": None,
            "source_file": artifact,
            "source_sha256": actual_hash,
            "row_number": row_number,
            "features": parsed_features,
        }

    def dataset_row(self, file_id: str, row_number: int) -> dict[str, Any]:
        """Return one prepared row by absolute 1-based file index."""
        if not isinstance(row_number, int) or isinstance(row_number, bool) or row_number < 1:
            raise ValueError("row_number must be a positive integer")
        context = self._prepared_file_context(file_id)
        try:
            with gzip.open(context["path"], "rt", encoding="utf-8-sig", newline="") as stream:
                reader = csv.DictReader(stream)
                if reader.fieldnames != [*context["feature_names"], "Label"]:
                    raise ValueError("prepared CSV header does not match frozen feature schema")
                for current, row in enumerate(reader, start=1):
                    if current < row_number:
                        continue
                    if current > row_number:
                        break
                    return self._parse_prepared_row(
                        row=row,
                        row_number=current,
                        feature_names=context["feature_names"],
                        vocabulary=context["vocabulary"],
                        artifact=context["match"]["artifact"],
                        actual_hash=context["actual_hash"],
                    )
        except (OSError, EOFError, csv.Error) as error:
            raise ValueError(f"could not read prepared dataset artifact: {error}") from error
        raise ValueError(f"prepared dataset does not contain row {row_number}")

    def dataset_preview(
        self, file_id: str, limit: int = 8, *, mix: str = "prefix"
    ) -> dict[str, Any]:
        if not 1 <= limit <= 20:
            raise ValueError("preview limit must be between 1 and 20")
        if mix not in {"prefix", "balanced"}:
            raise ValueError("mix must be 'prefix' or 'balanced'")
        context = self._prepared_file_context(file_id)
        match = context["match"]
        feature_names = context["feature_names"]
        vocabulary = context["vocabulary"]
        actual_hash = context["actual_hash"]
        benign_quota = limit if mix == "prefix" else (limit + 1) // 2
        attack_quota = 0 if mix == "prefix" else limit - benign_quota
        benign_records: list[dict[str, Any]] = []
        attack_records: list[dict[str, Any]] = []
        prefix_records: list[dict[str, Any]] = []
        try:
            with gzip.open(context["path"], "rt", encoding="utf-8-sig", newline="") as stream:
                reader = csv.DictReader(stream)
                if reader.fieldnames != [*feature_names, "Label"]:
                    raise ValueError("prepared CSV header does not match frozen feature schema")
                for row_number, row in enumerate(reader, start=1):
                    if mix == "prefix" and row_number > limit:
                        break
                    if (
                        mix == "balanced"
                        and len(benign_records) >= benign_quota
                        and len(attack_records) >= attack_quota
                    ):
                        break
                    record = self._parse_prepared_row(
                        row=row,
                        row_number=row_number,
                        feature_names=feature_names,
                        vocabulary=vocabulary,
                        artifact=match["artifact"],
                        actual_hash=actual_hash,
                    )
                    if mix == "prefix":
                        prefix_records.append(record)
                        continue
                    if record["source_label"] == "Benign":
                        if len(benign_records) < benign_quota:
                            benign_records.append(record)
                    elif len(attack_records) < attack_quota:
                        attack_records.append(record)
        except (OSError, EOFError, csv.Error) as error:
            raise ValueError(f"could not read prepared dataset artifact: {error}") from error
        if mix == "prefix":
            records = prefix_records
            sampling_policy = (
                f"First {len(records)} data rows; deterministic prefix, "
                "not representative sampling."
            )
        else:
            records = sorted(
                [*benign_records, *attack_records],
                key=lambda item: int(item["row_number"]),
            )[:limit]
            sampling_policy = (
                f"Deterministic first-{benign_quota}-Benign and first-{attack_quota}-attack "
                f"rows by file order ({len(benign_records)} benign / {len(attack_records)} "
                "attack collected); not representative sampling."
            )
        return {
            "source_id": "cse-cic-ids2018-stage5d",
            "source_type": "REAL_DATASET_RECORD",
            "dataset": "CSE-CIC-IDS2018",
            "source_artifact": match["artifact"],
            "source_sha256": actual_hash,
            "mix": mix,
            "sampling_policy": sampling_policy,
            "records": records,
        }

    def telemetry_runs(self) -> dict[str, Any]:
        if "telemetry_runs" in self._memo:
            return self._memo["telemetry_runs"]
        from src.sdn_defense.telemetry_audit import audit_telemetry_jsonl

        root = self._path(TELEMETRY_ROOT)
        runs: list[dict[str, Any]] = []
        for path in sorted(root.glob("*/telemetry.jsonl")):
            relative_path = path.relative_to(self.root).as_posix()
            run_id: str | None = None
            started_at: str | None = None
            ended_at: str | None = None
            record_count = 0
            first_issue: str | None = None
            try:
                with path.open(encoding="utf-8") as stream:
                    for line in stream:
                        record_count += 1
                        if run_id is None:
                            try:
                                record = json.loads(line)
                            except json.JSONDecodeError:
                                continue
                            if not isinstance(record, dict):
                                continue
                            metadata = record.get("metadata") or {}
                            if not isinstance(metadata, dict):
                                metadata = {}
                            run_id = record.get("run_id") or metadata.get("run_id")
                            started_at = record.get("timestamp") or metadata.get("start_at")
                            ended_at = metadata.get("end_at")
                audit = audit_telemetry_jsonl(path)
                provenance_status = audit.get("status", "AUDIT_INCOMPLETE")
                issues = audit.get("issues", [])
                if issues:
                    first_issue = str(issues[0])
            except (OSError, ValueError, json.JSONDecodeError) as error:
                provenance_status = "INVALID"
                first_issue = str(error)
            summary_path = path.parent / "collection-summary.json"
            if summary_path.is_file():
                try:
                    summary = json.loads(summary_path.read_text(encoding="utf-8"))
                    if isinstance(summary, dict):
                        run_id = run_id or summary.get("run_id")
                        started_at = started_at or summary.get("run_started_at")
                        ended_at = ended_at or summary.get("run_ended_at")
                except (OSError, json.JSONDecodeError):
                    pass
            runs.append(
                {
                    "source_id": path.parent.name,
                    "source_type": "RECORDED_TELEMETRY",
                    "artifact": relative_path,
                    "artifact_sha256": _sha256(path),
                    "run_id": run_id,
                    "started_at": started_at,
                    "ended_at": ended_at,
                    "record_count": record_count,
                    "provenance_status": provenance_status,
                    "complete": provenance_status == "AUDIT_COMPLETE",
                    "issue": first_issue,
                    "usable_as_detection_evidence": False,
                }
            )
        result = {
            "source_type": "RECORDED_TELEMETRY",
            "runs": runs,
            "available_valid_runs": sum(run["complete"] for run in runs),
            "record_semantics": (
                "Historical OpenFlow observations only; no detection classifications."
            ),
        }
        self._memo["telemetry_runs"] = result
        return result

    def sources(self) -> dict[str, Any]:
        results = self.historical_results()
        dataset = self.dataset_sources()
        telemetry = self.telemetry_runs()
        raw: list[dict[str, Any]] = []
        for dataset_name, directory in RAW_DATASET_ROOTS:
            path = self._path(directory)
            files = sorted(p for p in path.rglob("*") if p.is_file()) if path.is_dir() else []
            raw.append(
                {
                    "dataset": dataset_name,
                    "directory": directory,
                    "status": "AVAILABLE_AS_LOCAL_FILES" if files else "UNAVAILABLE",
                    "file_count": len(files),
                    "files": [
                        {
                            "path": p.relative_to(self.root).as_posix(),
                            "size_bytes": p.stat().st_size,
                        }
                        for p in files
                    ],
                    "loaded_into_dashboard": False,
                }
            )
        return {
            "items": [
                {
                    "source_id": "historical-results",
                    "source_type": "HISTORICAL_EXPERIMENT_RESULTS",
                    "status": "AVAILABLE" if results["records"] else "UNAVAILABLE",
                    "artifact_count": len(RESULT_ARTIFACTS) - len(results["unavailable_artifacts"]),
                    "record_count": len(results["records"]),
                    "description": results["record_semantics"],
                },
                {
                    "source_id": dataset.get("source_id", "cse-cic-ids2018-stage5d"),
                    "source_type": "PREPARED_LABELED_DATASET",
                    "status": dataset["status"],
                    "artifact_count": len(dataset["files"]),
                    "record_count": sum(
                        item.get("manifest_row_count", 0) or 0 for item in dataset["files"]
                    ),
                    "description": dataset.get("record_semantics", dataset.get("reason")),
                },
                {
                    "source_id": "recorded-telemetry",
                    "source_type": "RECORDED_TELEMETRY",
                    "status": "AVAILABLE" if telemetry["runs"] else "UNAVAILABLE",
                    "artifact_count": len(telemetry["runs"]),
                    "record_count": sum(run["record_count"] for run in telemetry["runs"]),
                    "valid_run_count": telemetry["available_valid_runs"],
                    "description": telemetry["record_semantics"],
                },
                {
                    "source_id": "raw-datasets",
                    "source_type": "RAW_DATASET_FILES",
                    "status": "AVAILABLE"
                    if any(item["file_count"] for item in raw)
                    else "UNAVAILABLE",
                    "datasets": raw,
                    "description": (
                        "Local dataset files are inventoried but not loaded or redistributed "
                        "by the dashboard."
                    ),
                },
                {
                    "source_id": "synthetic-demo",
                    "source_type": "SYNTHETIC",
                    "status": "AVAILABLE",
                    "description": (
                        "Synthetic illustrative scenario fixtures, clearly separated from "
                        "historical artifacts."
                    ),
                },
            ],
        }
