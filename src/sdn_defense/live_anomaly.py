"""Provisional, explainable anomaly scoring for validated OpenFlow windows.

This baseline is not an attack classifier. It is calibrated only from
explicitly identified benign runs and never authorizes mitigation.
"""

from __future__ import annotations

import hashlib
import json
import math
import statistics
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from src.sdn_defense.live_features import LIVE_FEATURE_ORDER, LIVE_FEATURE_SCHEMA_ID
from src.sdn_defense.telemetry_audit import audit_telemetry_jsonl

LIVE_ANOMALY_MODEL_ID = "stage7-live-robust-anomaly"
LIVE_ANOMALY_MODEL_VERSION = "0.1.0"
DEFAULT_ANOMALY_THRESHOLD = 4.0


class LiveEvidenceError(ValueError):
    """A live window or its source provenance is ineligible for scoring."""


@dataclass(frozen=True, slots=True)
class ValidatedLiveWindow:
    window_id: str
    run_id: str
    datapath_id: str
    datapath_epoch_id: str
    rule_identity_id: str
    start_at: str
    end_at: str
    elapsed_seconds: float
    features: dict[str, float]
    source_record_ids: tuple[str, str]
    source_artifact: str
    source_sha256: str

    @classmethod
    def parse(
        cls,
        raw: object,
        *,
        source_artifact: str,
        source_sha256: str,
        max_gap_seconds: float,
    ) -> ValidatedLiveWindow:
        if not isinstance(raw, dict):
            raise LiveEvidenceError("window is not an object")
        if raw.get("schema_version") != 1 or raw.get("validity") != "VALID":
            raise LiveEvidenceError("window is not a valid live feature schema v1 window")
        if raw.get("feature_schema_id") != LIVE_FEATURE_SCHEMA_ID or raw.get(
            "feature_order"
        ) != list(LIVE_FEATURE_ORDER):
            raise LiveEvidenceError("feature names or order do not match the live schema")
        if raw.get("provenance_version") != "sdn-live-observation-v1":
            raise LiveEvidenceError("window provenance version is unsupported")
        if raw.get("observation_source") != "openflow_rule_counter_delta":
            raise LiveEvidenceError("window is not derived from OpenFlow rule counters")
        window_id, run_id, datapath_id = (
            raw.get("window_id"),
            raw.get("run_id"),
            raw.get("datapath_id"),
        )
        identity = raw.get("rule_identity")
        identity_id = identity.get("identity_id") if isinstance(identity, dict) else None
        if not all(
            isinstance(value, str) and value
            for value in (window_id, run_id, datapath_id, identity_id)
        ):
            raise LiveEvidenceError("window, run, datapath, or rule identity is missing")
        records = raw.get("source_record_ids")
        if (
            not isinstance(records, list)
            or len(records) != 2
            or not all(isinstance(value, str) and value for value in records)
        ):
            raise LiveEvidenceError("window must reference exactly two source snapshots")
        start_at, end_at = raw.get("start_at"), raw.get("end_at")
        try:
            start = datetime.fromisoformat(str(start_at).replace("Z", "+00:00"))
            end = datetime.fromisoformat(str(end_at).replace("Z", "+00:00"))
        except ValueError as error:
            raise LiveEvidenceError("window timestamps are invalid") from error
        if start.tzinfo is None or end.tzinfo is None or end <= start:
            raise LiveEvidenceError("window timestamps are not ordered and timezone-aware")
        elapsed = raw.get("measured_elapsed_seconds")
        if (
            isinstance(elapsed, bool)
            or not isinstance(elapsed, (int, float))
            or not math.isfinite(elapsed)
        ):
            raise LiveEvidenceError("window elapsed time is unavailable")
        if elapsed <= 0 or elapsed > max_gap_seconds:
            raise LiveEvidenceError("window exceeds the configured maximum observation gap")
        wall_elapsed = (end - start).total_seconds()
        if abs(wall_elapsed - elapsed) > max(0.001, wall_elapsed * 0.01):
            raise LiveEvidenceError("wall-clock and measured window durations disagree")
        features: dict[str, float] = {}
        for name in LIVE_FEATURE_ORDER:
            value = raw.get(name)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value < 0
            ):
                raise LiveEvidenceError(f"required feature {name} is not finite and nonnegative")
            features[name] = float(value)
        return cls(
            window_id=cast(str, window_id),
            run_id=cast(str, run_id),
            datapath_id=cast(str, datapath_id),
            datapath_epoch_id="",
            rule_identity_id=cast(str, identity_id),
            start_at=start.isoformat(),
            end_at=end.isoformat(),
            elapsed_seconds=float(elapsed),
            features=features,
            source_record_ids=(records[0], records[1]),
            source_artifact=source_artifact,
            source_sha256=source_sha256,
        )


def read_telemetry_windows(
    path: Path, *, max_gap_seconds: float, allow_open_run: bool = False
) -> tuple[list[ValidatedLiveWindow], dict[str, Any]]:
    """Load valid windows only after a whole-file source-lineage audit succeeds."""

    audit = audit_telemetry_jsonl(path)
    issues = audit.get("issues", [])
    permitted_open_boundary = allow_open_run and issues == ["unclosed_run_boundaries:1"]
    if audit.get("status") != "AUDIT_COMPLETE" and not permitted_open_boundary:
        raise LiveEvidenceError("telemetry source-lineage audit is not complete")
    accepted_pairs = {
        str(pair.get("pair_id"))
        for pair in audit.get("pairs", [])
        if isinstance(pair, dict) and pair.get("accepted") is True
    }
    completed_collections = {
        row.get("collection_id")
        for row in audit.get("collections", [])
        if isinstance(row, dict) and row.get("complete") is True
    }
    source_hash = _sha256(path)
    snapshots: dict[str, dict[str, Any]] = {}
    windows: list[ValidatedLiveWindow] = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise LiveEvidenceError(f"invalid telemetry JSONL at line {line_number}") from error
            if not isinstance(record, dict):
                raise LiveEvidenceError(f"telemetry record at line {line_number} is not an object")
            if record.get("record_type") == "flow_snapshot":
                flow = record.get("flow_record")
                if isinstance(flow, dict) and isinstance(flow.get("record_id"), str):
                    snapshots[flow["record_id"]] = record
                continue
            if record.get("record_type") != "observation_window":
                continue
            payload = record.get("observation_window")
            if not isinstance(payload, dict) or payload.get("validity") != "VALID":
                continue
            window = ValidatedLiveWindow.parse(
                payload,
                source_artifact=path.as_posix(),
                source_sha256=source_hash,
                max_gap_seconds=max_gap_seconds,
            )
            left, right = (snapshots.get(value) for value in window.source_record_ids)
            if left is None or right is None:
                raise LiveEvidenceError("window source snapshots are missing or follow the window")
            left_flow, right_flow = left.get("flow_record"), right.get("flow_record")
            if not isinstance(left_flow, dict) or not isinstance(right_flow, dict):
                raise LiveEvidenceError("window source snapshot has no FlowRecord")
            left_collection, right_collection = (
                left.get("collection_id"),
                right.get("collection_id"),
            )
            left_epoch, right_epoch = left.get("datapath_epoch_id"), right.get("datapath_epoch_id")
            pair_id = f"{window.source_record_ids[0]}:{window.source_record_ids[1]}"
            if (
                left_collection == right_collection
                or left_collection not in completed_collections
                or right_collection not in completed_collections
                or left_epoch != right_epoch
                or left_flow.get("datapath_id") != window.datapath_id
                or right_flow.get("datapath_id") != window.datapath_id
                or left.get("run_id") != window.run_id
                or right.get("run_id") != window.run_id
                or pair_id not in accepted_pairs
            ):
                raise LiveEvidenceError("source snapshots lack matching audited run/epoch lineage")
            windows.append(replace(window, datapath_epoch_id=str(left_epoch)))
    return windows, audit


def calibrate_benign_runs(
    runs: list[tuple[Path, dict[str, Any]]],
    *,
    threshold: float = DEFAULT_ANOMALY_THRESHOLD,
    maximum_gap_seconds: float = 30.0,
) -> dict[str, Any]:
    """Create a frozen robust baseline from audited benign-only run artifacts."""

    if not math.isfinite(threshold) or threshold <= 0:
        raise ValueError("threshold must be finite and positive")
    grouped: dict[str, list[ValidatedLiveWindow]] = {}
    training_runs: list[dict[str, str | int]] = []
    root = Path(__file__).resolve().parents[2]
    required_sources = (
        "networking/ryu/config.py",
        "networking/ryu/stage2_controller.py",
        "src/sdn_defense/telemetry.py",
        "src/sdn_defense/live_features.py",
        "src/sdn_defense/live_anomaly.py",
    )
    for path, summary in runs:
        if summary.get("scenario_id") != "controlled-connectivity-observation":
            raise LiveEvidenceError("calibration accepts only explicitly benign connectivity runs")
        if not summary.get("run_id") or summary.get("cleanup_verified") is not True:
            raise LiveEvidenceError("run metadata or verified cleanup is missing")
        environment = summary.get("environment")
        recorded_hashes = (
            environment.get("source_sha256") if isinstance(environment, dict) else None
        )
        if not isinstance(recorded_hashes, dict):
            raise LiveEvidenceError("run summary is missing collector source hashes")
        for relative in required_sources:
            if recorded_hashes.get(relative) != _sha256(root / relative):
                raise LiveEvidenceError(f"run source hash is stale or missing: {relative}")
        windows, audit = read_telemetry_windows(path, max_gap_seconds=maximum_gap_seconds)
        run_id = str(summary["run_id"])
        if not windows or any(window.run_id != run_id for window in windows):
            raise LiveEvidenceError("calibration run IDs do not match eligible windows")
        for window in windows:
            grouped.setdefault(window.rule_identity_id, []).append(window)
        training_runs.append(
            {
                "run_id": run_id,
                "artifact": path.as_posix(),
                "sha256": _sha256(path),
                "valid_windows": len(windows),
                "accepted_pairs": int(audit["counts"]["source_verified_pairs"]),
            }
        )
    profiles: dict[str, Any] = {}
    for identity, windows in grouped.items():
        if len(windows) < 2:
            raise LiveEvidenceError(f"rule {identity} has fewer than two benign windows")
        features: dict[str, Any] = {}
        for name in LIVE_FEATURE_ORDER:
            values = [window.features[name] for window in windows]
            median = statistics.median(values)
            mad = statistics.median(abs(value - median) for value in values)
            scale = max(1.4826 * mad, abs(median) * 0.05, 1.0)
            features[name] = {"median": median, "mad": mad, "scale": scale, "n": len(values)}
        profiles[identity] = {"n_windows": len(windows), "features": features}
    return {
        "artifact_format": "sentinel-live-robust-baseline-v1",
        "model_id": LIVE_ANOMALY_MODEL_ID,
        "version": LIVE_ANOMALY_MODEL_VERSION,
        "task": "benign-baseline anomaly scoring; not attack classification",
        "source_type": "LIVE",
        "feature_schema_id": LIVE_FEATURE_SCHEMA_ID,
        "feature_schema_version": 1,
        "feature_order": list(LIVE_FEATURE_ORDER),
        "scoring_method": "maximum absolute robust z-score by canonical OpenFlow rule identity",
        "explanation_method": (
            "per-feature signed deviation from benign median divided by max(1.4826*MAD, "
            "5% median, 1.0 floor)"
        ),
        "threshold": threshold,
        "threshold_selection": (
            "fixed engineering threshold; not tuned or validated against attack runs"
        ),
        "sustained_change_policy": (
            "at least 2 threshold exceedances in the latest 3 unique windows "
            "for the same rule identity"
        ),
        "profiles": profiles,
        "training_runs": training_runs,
        "software_sha256": {
            "src/sdn_defense/live_anomaly.py": _sha256(Path(__file__).resolve()),
        },
        "calibrated_at": datetime.now(UTC).isoformat(),
        "maximum_gap_seconds": maximum_gap_seconds,
        "status": "PROVISIONAL_BENIGN_CALIBRATION",
        "limitations": [
            "Scores deviation from a benign rule-counter baseline; it does not classify attacks.",
            "The threshold is an engineering default and has not been validated on attack runs.",
            "One calibration run does not estimate run-to-run variation.",
            "Rule identity is a canonical OpenFlow selector identity, not a host/device identity.",
            "Scores are not probabilities and never authorize mitigation.",
        ],
    }


def score_window(model: dict[str, Any], window: ValidatedLiveWindow) -> dict[str, Any]:
    """Return a reproducible score and per-feature explanation."""

    if model.get("feature_schema_id") != LIVE_FEATURE_SCHEMA_ID or model.get(
        "feature_order"
    ) != list(LIVE_FEATURE_ORDER):
        raise LiveEvidenceError("calibration model feature schema is incompatible")
    profile = model.get("profiles", {}).get(window.rule_identity_id)
    if not isinstance(profile, dict):
        raise LiveEvidenceError("no benign profile exists for this rule identity")
    explanations: list[dict[str, Any]] = []
    for name in LIVE_FEATURE_ORDER:
        stats = profile["features"][name]
        value, median, scale = window.features[name], float(stats["median"]), float(stats["scale"])
        signed_z = (value - median) / scale
        explanations.append(
            {
                "feature": name,
                "value": value,
                "benign_median": median,
                "benign_mad": float(stats["mad"]),
                "robust_scale": scale,
                "signed_deviation": signed_z,
                "absolute_deviation": abs(signed_z),
                "direction": (
                    "ABOVE_BASELINE"
                    if signed_z > 0
                    else "BELOW_BASELINE"
                    if signed_z < 0
                    else "AT_BASELINE"
                ),
                "baseline_sample_count": int(stats["n"]),
            }
        )
    score = max(item["absolute_deviation"] for item in explanations)
    threshold = float(model["threshold"])
    unusual = score >= threshold
    return {
        "window_id": window.window_id,
        "run_id": window.run_id,
        "datapath_id": window.datapath_id,
        "datapath_epoch_id": window.datapath_epoch_id,
        "rule_identity_id": window.rule_identity_id,
        "start_at": window.start_at,
        "end_at": window.end_at,
        "elapsed_seconds": window.elapsed_seconds,
        "features": window.features,
        "source_record_ids": list(window.source_record_ids),
        "source_artifact": window.source_artifact,
        "source_sha256": window.source_sha256,
        "source_type": "LIVE",
        "model_id": model["model_id"],
        "model_version": model["version"],
        "feature_schema_id": model["feature_schema_id"],
        "score": score,
        "threshold": threshold,
        "score_semantics": "maximum absolute robust z-score; not a probability",
        "result": "UNUSUAL" if unusual else "WITHIN_BENIGN_BASELINE",
        "explanation": {
            "method": model["explanation_method"],
            "threshold": threshold,
            "features": sorted(
                explanations, key=lambda item: item["absolute_deviation"], reverse=True
            ),
            "reason": (
                "Measured rule-counter features departed from the frozen benign reference."
                if unusual
                else "All measured rule-counter features remained below the provisional threshold."
            ),
            "not_causal": True,
            "mitigation_authorized": False,
        },
    }


def save_calibration(model: dict[str, Any], directory: Path) -> dict[str, Any]:
    """Write a versioned model and hash manifest; never overwrite."""

    directory.mkdir(parents=True, exist_ok=False)
    artifact = directory / "baseline.json"
    payload = json.dumps(model, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    artifact.write_bytes(payload + b"\n")
    manifest = {
        "artifact_format": model["artifact_format"],
        "model_id": model["model_id"],
        "version": model["version"],
        "artifact": artifact.name,
        "artifact_sha256": _sha256(artifact),
        "feature_schema_id": model["feature_schema_id"],
        "feature_order": model["feature_order"],
        "status": model["status"],
        "training_runs": model["training_runs"],
    }
    (directory / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def load_calibration(directory: Path) -> dict[str, Any]:
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("artifact_format") != "sentinel-live-robust-baseline-v1":
        raise LiveEvidenceError("unsupported live calibration artifact format")
    artifact = directory / "baseline.json"
    if _sha256(artifact) != manifest.get("artifact_sha256"):
        raise LiveEvidenceError("live calibration artifact hash mismatch")
    model = json.loads(artifact.read_text(encoding="utf-8"))
    if model.get("feature_schema_id") != LIVE_FEATURE_SCHEMA_ID or model.get(
        "feature_order"
    ) != list(LIVE_FEATURE_ORDER):
        raise LiveEvidenceError("live calibration feature schema mismatch")
    if not isinstance(model, dict):
        raise LiveEvidenceError("live calibration artifact must contain a JSON object")
    return cast(dict[str, Any], model)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
