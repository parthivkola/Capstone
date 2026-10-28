"""Safe, hash-verified model registry and offline inference adapter."""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any, cast

from apps.api.project_data import RESULT_ARTIFACTS, ProjectDataSources
from ml.models.application_linear import (
    FEATURE_SCHEMA_ID,
    LIVE_FEATURE_SCHEMA_ID,
    MODEL_ARTIFACT_FORMAT,
    MODEL_ID,
    OfflineLinearModel,
)
from src.sdn_defense.live_anomaly import LIVE_ANOMALY_MODEL_ID, LiveEvidenceError, load_calibration

MODEL_MANIFEST = Path("var/models/cse-cicflowmeter-binary-logistic-v3/manifest.json")
LEGACY_MODEL_MANIFEST_V2 = Path("var/models/cse-cicflowmeter-binary-logistic-v2/manifest.json")
LEGACY_MODEL_MANIFEST = Path("var/models/cse-cicflowmeter-binary-logistic-v1/manifest.json")
OFFLINE_MANIFEST_CANDIDATES = (MODEL_MANIFEST, LEGACY_MODEL_MANIFEST_V2, LEGACY_MODEL_MANIFEST)
LIVE_MODEL_ID = LIVE_ANOMALY_MODEL_ID
LEGACY_LIVE_MODEL_ID = "stage7-live-rule-counter"
PRELIMINARY_LIVE_MODEL_DIR = Path("var/models/stage7-live-logistic-preliminary-03")


class ModelUnavailableError(RuntimeError):
    """An explicitly requested model is not ready for this operation."""


class ModelRegistry:
    def __init__(self, project_root: Path) -> None:
        self.root = project_root.resolve()
        self.models_root = (self.root / "var/models").resolve()
        self.data_sources = ProjectDataSources(self.root)

    @staticmethod
    def _hash(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()

    def _resolve_offline_manifest(self) -> Path | None:
        for relative in OFFLINE_MANIFEST_CANDIDATES:
            candidate = (self.root / relative).resolve()
            if candidate.is_file() and candidate.is_relative_to(self.models_root):
                return candidate
        return None

    def _offline_status(self) -> dict[str, Any]:
        unavailable = {
            "model_id": MODEL_ID,
            "version": None,
            "family": "OFFLINE_APPLICATION_BASELINE",
            "task": "binary benign-versus-intrusion classification",
            "status": "UNAVAILABLE",
            "inference_enabled": False,
            "live_eligible": False,
            "feature_schema_id": FEATURE_SCHEMA_ID,
            "artifact": MODEL_MANIFEST.as_posix().replace("manifest.json", "model.json"),
            "artifact_sha256": None,
            "reason": (
                "No trained application artifact exists at the active registry path. Run "
                "scripts/compare_application_models.py (preferred) or "
                "scripts/train_application_model.py."
            ),
        }
        manifest_path = self._resolve_offline_manifest()
        if manifest_path is None:
            return unavailable
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if not isinstance(manifest, dict):
                raise ValueError("model manifest must be an object")
            if manifest.get("model_id") != MODEL_ID:
                raise ValueError("model ID does not match the registry allowlist")
            if manifest.get("artifact_format") != MODEL_ARTIFACT_FORMAT:
                raise ValueError("artifact format is unsupported")
            if manifest.get("feature_schema_id") != FEATURE_SCHEMA_ID:
                raise ValueError("offline model schema is incompatible")
            if manifest.get("artifact") != "model.json":
                raise ValueError("only the safe JSON model format is configured")
            artifact_path = (manifest_path.parent / "model.json").resolve()
            if not artifact_path.is_relative_to(self.models_root) or not artifact_path.is_file():
                raise ValueError("model artifact is missing or outside var/models")
            actual_hash = self._hash(artifact_path)
            if actual_hash != manifest.get("artifact_sha256"):
                raise ValueError("model artifact hash does not match its registry manifest")
            document = json.loads(artifact_path.read_text(encoding="utf-8"))
            model = OfflineLinearModel.from_dict(document)
            if list(model.feature_names) != manifest.get("feature_names"):
                raise ValueError("model and manifest feature ordering differs")
            if manifest.get("live_eligible") is not False:
                raise ValueError("offline model cannot be marked live eligible")
            return {
                **manifest,
                "family": "OFFLINE_APPLICATION_BASELINE",
                "status": "LOADABLE",
                "inference_enabled": True,
                "artifact": artifact_path.relative_to(self.root).as_posix(),
                "artifact_sha256": actual_hash,
                "health": "HEALTHY",
                "reason": None,
            }
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
            return {
                **unavailable,
                "status": "INCOMPATIBLE",
                "reason": str(error),
                "inference_enabled": False,
            }

    def _historical_entries(self) -> list[dict[str, Any]]:
        results = self.data_sources.historical_results()
        by_source: dict[str, list[dict[str, Any]]] = {}
        for result in results["records"]:
            by_source.setdefault(result["source_id"], []).append(result)
        entries: list[dict[str, Any]] = []
        for source_id, artifact in RESULT_ARTIFACTS:
            records = by_source.get(source_id, [])
            entries.append(
                {
                    "model_id": f"historical:{source_id}",
                    "version": None,
                    "family": "HISTORICAL_RESEARCH_RESULT",
                    "task": records[0].get("model") if records else "unknown",
                    "status": "HISTORICAL_ONLY" if records else "UNAVAILABLE",
                    "inference_enabled": False,
                    "live_eligible": False,
                    "feature_schema_id": None,
                    "artifact": artifact,
                    "recorded_result_count": len(records),
                    "reason": (
                        "Evaluation JSON is evidence of a past run, not a deployable "
                        "model artifact."
                        if records
                        else "Historical evaluation artifact is missing or unreadable."
                    ),
                }
            )
        return entries

    def list_models(self) -> dict[str, Any]:
        offline = self._offline_status()
        live_path = self.models_root / "stage7-live-robust-v1"
        try:
            live_model = load_calibration(live_path)
            live_manifest = json.loads((live_path / "manifest.json").read_text(encoding="utf-8"))
            live = {
                "model_id": LIVE_ANOMALY_MODEL_ID,
                "version": live_model["version"],
                "family": "LIVE_NATIVE_PROVISIONAL_ANOMALY_BASELINE",
                "task": live_model["task"],
                "status": "PROVISIONAL_BENIGN_CALIBRATION",
                "inference_enabled": True,
                "live_eligible": False,
                "classification_supported": False,
                "feature_schema_id": live_model["feature_schema_id"],
                "feature_order": live_model["feature_order"],
                "artifact": "var/models/stage7-live-robust-v1/baseline.json",
                "artifact_sha256": live_manifest["artifact_sha256"],
                "threshold": live_model["threshold"],
                "threshold_selection": live_model["threshold_selection"],
                "training_runs": live_model["training_runs"],
                "reason": (
                    "Provisional anomaly scoring is available; this is not a validated "
                    "attack detector."
                ),
                "limitations": live_model["limitations"],
            }
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
            live = {
                "model_id": LIVE_ANOMALY_MODEL_ID,
                "version": None,
                "family": "LIVE_NATIVE_PROVISIONAL_ANOMALY_BASELINE",
                "task": "benign-baseline anomaly scoring; not attack classification",
                "status": "UNAVAILABLE",
                "inference_enabled": False,
                "live_eligible": False,
                "classification_supported": False,
                "feature_schema_id": LIVE_FEATURE_SCHEMA_ID,
                "feature_order": [
                    "rule_packet_delta",
                    "rule_byte_delta",
                    "rule_packet_rate_per_second",
                    "rule_byte_rate_per_second",
                ],
                "artifact": None,
                "artifact_sha256": None,
                "reason": str(error) if not isinstance(error, LiveEvidenceError) else str(error),
            }
        candidate_path = (self.root / PRELIMINARY_LIVE_MODEL_DIR).resolve()
        candidate: dict[str, Any] = {
            "model_id": "stage7-live-logistic-preliminary",
            "version": None,
            "family": "LIVE_NATIVE_SUPERVISED_CANDIDATE",
            "task": (
                "controlled benign-connectivity versus bounded port-scan scenario classification"
            ),
            "status": "UNAVAILABLE",
            "inference_enabled": False,
            "live_eligible": False,
            "classification_supported": True,
            "feature_schema_id": LIVE_FEATURE_SCHEMA_ID,
            "feature_order": [
                "rule_packet_delta",
                "rule_byte_delta",
                "rule_packet_rate_per_second",
                "rule_byte_rate_per_second",
            ],
            "artifact": (PRELIMINARY_LIVE_MODEL_DIR / "model.joblib").as_posix(),
            "artifact_sha256": None,
            "reason": "No preliminary live supervised artifact has been trained.",
        }
        try:
            if not candidate_path.is_relative_to(self.models_root):
                raise ValueError("live candidate path escapes var/models")
            candidate_manifest_path = candidate_path / "manifest.json"
            candidate_manifest = json.loads(candidate_manifest_path.read_text(encoding="utf-8"))
            artifact_path = (candidate_path / "model.joblib").resolve()
            if (
                candidate_manifest.get("model_id") != "stage7-live-logistic-preliminary"
                or candidate_manifest.get("status") != "TRAINED_UNAPPROVED_PRELIMINARY"
                or candidate_manifest.get("feature_schema_id") != LIVE_FEATURE_SCHEMA_ID
                or candidate_manifest.get("feature_order")
                != [
                    "rule_packet_delta",
                    "rule_byte_delta",
                    "rule_packet_rate_per_second",
                    "rule_byte_rate_per_second",
                ]
                or candidate_manifest.get("artifact") != "model.joblib"
                or not artifact_path.is_relative_to(self.models_root)
                or not artifact_path.is_file()
            ):
                raise ValueError("live candidate manifest is incomplete or incompatible")
            artifact_hash = self._hash(artifact_path)
            if artifact_hash != candidate_manifest.get("artifact_sha256"):
                raise ValueError("live candidate artifact hash mismatch")
            candidate = {
                **candidate_manifest,
                "family": "LIVE_NATIVE_SUPERVISED_CANDIDATE",
                "artifact": artifact_path.relative_to(self.root).as_posix(),
                "status": "TRAINED_UNAPPROVED_PRELIMINARY",
                "inference_enabled": False,
                "live_eligible": False,
                "artifact_sha256": artifact_hash,
                "reason": (
                    "The candidate has only one held-out run per class and is not approved "
                    "for operational inference."
                ),
            }
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
            candidate["status"] = "INCOMPATIBLE" if candidate_path.exists() else "UNAVAILABLE"
            candidate["reason"] = str(error)
        return {
            "registry_version": 1,
            "models": [offline, live, candidate, *self._historical_entries()],
            "live_model_id": LIVE_MODEL_ID,
            "offline_model_id": MODEL_ID,
        }

    def get_model(self, model_id: str) -> dict[str, Any] | None:
        if model_id == MODEL_ID:
            return self._offline_status()
        for entry in self.list_models()["models"]:
            if entry["model_id"] == model_id:
                return cast(dict[str, Any], entry)
        return None

    def health(self, model_id: str) -> dict[str, Any] | None:
        model = self.get_model(model_id)
        if model is None:
            return None
        return {
            "model_id": model_id,
            "status": model["status"],
            "healthy": model.get("health") == "HEALTHY",
            "inference_enabled": model["inference_enabled"],
            "reason": model.get("reason"),
        }

    def input_schema(self) -> dict[str, Any]:
        live_status = self.get_model(LIVE_MODEL_ID)
        manifest_path = self._resolve_offline_manifest()
        if manifest_path is not None:
            status = self._offline_status()
            if status.get("feature_names"):
                feature_names = status["feature_names"]
            else:
                feature_names = self._read_manifest_feature_names(manifest_path)
        else:
            feature_names = self._read_preparation_feature_names()
        return {
            "models": [
                {
                    "model_id": MODEL_ID,
                    "feature_schema_id": FEATURE_SCHEMA_ID,
                    "feature_schema_version": 1,
                    "feature_count": len(feature_names),
                    "feature_order": feature_names,
                    "input_type": "finite JSON numbers",
                    "required_fields": feature_names,
                    "optional_fields": [],
                    "prediction_scope": "offline CICFlowMeter records only",
                    "confidence_note": "sigmoid score, not calibration-validated",
                },
                {
                    "model_id": LIVE_MODEL_ID,
                    "feature_schema_id": LIVE_FEATURE_SCHEMA_ID,
                    "feature_schema_version": 1,
                    "feature_count": 4,
                    "feature_order": [
                        "rule_packet_delta",
                        "rule_byte_delta",
                        "rule_packet_rate_per_second",
                        "rule_byte_rate_per_second",
                    ],
                    "status": live_status.get("status") if live_status else "UNAVAILABLE",
                    "reason": (
                        "Provisional benign-reference scoring consumes audited collector windows; "
                        "direct live inference requests are not supported and this is not an "
                        "approved attack classifier."
                    ),
                },
            ]
        }

    def _read_manifest_feature_names(self, path: Path) -> list[str]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            names = value.get("feature_names") if isinstance(value, dict) else None
            if isinstance(names, list):
                return cast(list[str], names)
        except (OSError, json.JSONDecodeError):
            pass
        return self._read_preparation_feature_names()

    def _read_preparation_feature_names(self) -> list[str]:
        catalog = self.data_sources.dataset_sources()
        files = catalog.get("files", [])
        if not files or not isinstance(files[0], dict):
            return []
        names = files[0].get("feature_names", [])
        return cast(list[str], names) if isinstance(names, list) else []

    def predict(self, request: dict[str, Any]) -> dict[str, Any]:
        model_id = request.get("model_id")
        if model_id in {LIVE_MODEL_ID, LEGACY_LIVE_MODEL_ID}:
            raise ModelUnavailableError(
                "live inference is disabled: no approved live-native model and evidence gate"
            )
        if model_id != MODEL_ID:
            raise ModelUnavailableError(f"model is not registered for inference: {model_id}")
        status = self._offline_status()
        if not status.get("inference_enabled"):
            raise ModelUnavailableError(str(status.get("reason", "offline model unavailable")))
        manifest_path = self._resolve_offline_manifest()
        if manifest_path is None:
            raise ModelUnavailableError("offline model unavailable")
        artifact_path = manifest_path.parent / "model.json"
        document = json.loads(artifact_path.read_text(encoding="utf-8"))
        model = OfflineLinearModel.from_dict(document)
        feature_values = request.get("features")
        if not isinstance(feature_values, dict):
            raise ValueError("features must be an object of named numeric values")
        if any(
            isinstance(value, float) and not math.isfinite(value)
            for value in feature_values.values()
        ):
            raise ValueError("feature values must be finite JSON numbers")
        feature_schema = request.get("feature_schema")
        feature_order = request.get("feature_order")
        if not isinstance(feature_schema, str):
            raise ValueError("feature_schema must be a string")
        if not isinstance(feature_order, list) or any(
            not isinstance(name, str) for name in feature_order
        ):
            raise ValueError("feature_order must be a list of feature names")
        result = model.predict(
            feature_schema=feature_schema,
            feature_order=feature_order,
            features=feature_values,
        )
        return {
            "model_id": model.model_id,
            "model_version": model.version,
            "feature_schema_id": FEATURE_SCHEMA_ID,
            **result,
        }
