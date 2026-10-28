"""Frozen Stage 5F source/distribution-shift RF adaptation experiment."""

from __future__ import annotations

import copy
import csv
import gzip
import hashlib
import heapq
import json
import math
import time
from collections import Counter
from collections.abc import Iterator
from itertools import islice
from pathlib import Path
from typing import Any, cast

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score

from ml.evaluation.stage5d_cse import EXPECTED_FEATURE_COUNT, _peak_rss_bytes

PROTOCOL_RELATIVE_PATH = Path("experiments/stage5f/drift-adaptation-protocol.json")
MANIFEST_RELATIVE_PATH = Path("experiments/stage5d/cse-preparation.json")
RESULT_RELATIVE_PATH = Path("experiments/stage5f/source-distribution-shift-results.json")
REPORT_RELATIVE_PATH = Path("docs/research/stage5f-source-distribution-shift-results.md")
BENIGN = "Benign"
ATTACK = "Attack"
CLASS_NAMES = (BENIGN, ATTACK)
CHUNK_ROWS = 50_000
PSI_REFERENCE_ROWS = 50_000
PSI_COMPARISON_ROWS = 10_000
MAX_BUFFER_ROWS = 100_000
BUFFER_REPLAY_PER_CLASS = 20_000
BUFFER_RECENT_PER_CLASS = 10_000
BUFFER_RECENT_WINDOWS = 3
PSI_FEATURE_THRESHOLD = 0.20
PSI_FEATURES_TO_TRIGGER = 5
PAIRED_T_975_DF4 = 2.7764451051977987
ROLLBACK_MACRO_F1_DROP = 0.05
ROLLBACK_BENIGN_FPR_INCREASE = 0.02
SEEDS = (2026, 2027, 2028, 2029, 2030)
PARTITION_SEED = 2026
ADAPTATION_LATENCY_DEFINITION = (
    "wall-clock elapsed from eligible label release/update decision to candidate fit completion"
)
FROZEN_WINDOW_ORDER = (
    ("W1", "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv"),
    ("W2", "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv"),
    ("W3", "Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv"),
    ("W4", "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv"),
)


def _load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        return cast(dict[str, Any], json.load(stream))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _prepared_path(root: Path, source: dict[str, Any]) -> Path:
    """Resolve a prepared artifact using its Stage 5D manifest basename."""
    manifest_path = root / MANIFEST_RELATIVE_PATH
    if not manifest_path.is_file():
        return root / cast(str, source["prepared_path"])
    manifest = _load_json(manifest_path)
    record = next(
        (item for item in manifest["source_statistics"] if item["file"] == source["file"]),
        None,
    )
    if record is None:
        return root / cast(str, source["prepared_path"])
    output_name = Path(cast(str, record["output_path"])).name
    return root / "data/processed/stage5d/cse-cic-ids2018" / output_name


def binary_label(label: str) -> int:
    """Map original labels to fixed binary codes: Benign=0, all attack=1."""
    if not label:
        raise ValueError("empty label")
    return 0 if label == BENIGN else 1


def released_window_after_boundary(window_number: int) -> tuple[str | None, bool]:
    """Return newly eligible prior window and whether the boundary is terminal."""
    names = ("W1", "W2", "W3", "W4")
    if not 1 <= window_number <= 4:
        raise ValueError("window number must be in 1..4")
    if window_number == 1:
        return None, False
    return names[window_number - 2], window_number == 4


def should_attempt_update(strategy: str, window_id: str, psi_pending: bool) -> bool:
    """Apply the frozen schedule: periodic W2 only; no terminal W4 updates."""
    if strategy == "static" or window_id == "W4":
        return False
    if strategy == "periodic":
        return window_id == "W2"
    if strategy == "drift_triggered":
        return psi_pending
    raise ValueError(f"unknown adaptation strategy: {strategy}")


def rollback_reasons(
    initial_anchor: dict[str, float], candidate_anchor: dict[str, float]
) -> list[str]:
    reasons: list[str] = []
    if initial_anchor["macro_f1"] - candidate_anchor["macro_f1"] > ROLLBACK_MACRO_F1_DROP:
        reasons.append("anchor_macro_f1_drop_gt_0.05")
    if candidate_anchor["benign_fpr"] - initial_anchor["benign_fpr"] > ROLLBACK_BENIGN_FPR_INCREASE:
        reasons.append("anchor_benign_fpr_increase_gt_0.02")
    return reasons


def psi_triggered(values: np.ndarray) -> bool:
    """The frozen window trigger: at least five features reach PSI 0.20."""
    return (
        int(np.count_nonzero(np.asarray(values) >= PSI_FEATURE_THRESHOLD))
        >= PSI_FEATURES_TO_TRIGGER
    )


def _partition_seed_for_run(protocol: dict[str, Any], model_seed: int) -> int:
    """Return the frozen split seed; model randomness never changes row membership."""
    if model_seed not in protocol["model"]["seeds"]:
        raise ValueError(f"model seed is not in the frozen run set: {model_seed}")
    seed = int(protocol["source_and_window_design"]["initial_source_partition"]["seed"])
    if seed != PARTITION_SEED:
        raise ValueError(f"frozen partition seed changed: expected {PARTITION_SEED}, got {seed}")
    return seed


def psi_report(
    reference_counts: list[np.ndarray], comparison: np.ndarray, bins: list[dict[str, Any]]
) -> dict[str, Any]:
    """Apply the frozen PSI signal and window trigger to an already selected sample."""
    if len(comparison) != PSI_COMPARISON_ROWS:
        raise ValueError(
            f"PSI comparison requires {PSI_COMPARISON_ROWS} rows, got {len(comparison)}"
        )
    values = psi_values(reference_counts, comparison, bins)
    signaled = np.flatnonzero(values >= PSI_FEATURE_THRESHOLD)
    return {
        "comparison_rows": len(comparison),
        "per_feature_psi": values.tolist(),
        "signaled_feature_indices": signaled.astype(int).tolist(),
        "signaled_feature_count": int(len(signaled)),
        "psi_triggered": psi_triggered(values),
        "feature_threshold": PSI_FEATURE_THRESHOLD,
        "required_signaled_features": PSI_FEATURES_TO_TRIGGER,
    }


def adaptation_latency(
    eligible_release_ns: int, update_decision_ns: int, fit_complete_ns: int
) -> dict[str, Any]:
    """Return auditable monotonic wall durations for the frozen latency interval."""
    if not eligible_release_ns <= update_decision_ns <= fit_complete_ns:
        raise ValueError("adaptation latency timestamps must be monotonic")
    return {
        "time_source": "time.perf_counter_ns monotonic clock",
        "eligible_label_release_monotonic_ns": eligible_release_ns,
        "update_decision_monotonic_ns": update_decision_ns,
        "candidate_fit_complete_monotonic_ns": fit_complete_ns,
        "release_to_decision_seconds": (update_decision_ns - eligible_release_ns) / 1e9,
        "decision_to_fit_complete_seconds": (fit_complete_ns - update_decision_ns) / 1e9,
        "release_to_fit_complete_seconds": (fit_complete_ns - eligible_release_ns) / 1e9,
        "definition": ADAPTATION_LATENCY_DEFINITION,
    }


def _hash_rank(seed: int, identity: str, ordinal: int) -> bytes:
    return hashlib.sha256(
        str(seed).encode("ascii") + identity.encode("utf-8") + str(ordinal).encode("ascii")
    ).digest()


def _sample_ordinals(count: int, sample_size: int, seed: int, identity: str) -> np.ndarray:
    """Return deterministic lowest SHA-256-ranked row ordinals, sorted for reading."""
    if count < sample_size:
        raise ValueError(f"cannot sample {sample_size} rows from {count}")
    ranks = heapq.nsmallest(
        sample_size,
        ((_hash_rank(seed, identity, ordinal), ordinal) for ordinal in range(count)),
    )
    return np.sort(np.fromiter((ordinal for _, ordinal in ranks), dtype=np.int64))


def _partition_ordinals(
    source_ordinals: np.ndarray, seed: int, source_name: str, label_name: str
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """SHA-rank source/class row ordinals into disjoint 70/15/15 partitions."""
    count = len(source_ordinals)
    if count < 3:
        raise ValueError(
            f"need at least three rows for fit/validation/anchor: {source_name}/{label_name}"
        )
    identity = source_name
    ranked = sorted(
        (_hash_rank(seed, identity, int(ordinal)), int(ordinal)) for ordinal in source_ordinals
    )
    fit_count = math.floor(count * 0.70)
    validation_count = math.floor(count * 0.15)
    roles = (
        np.sort(np.fromiter((ordinal for _, ordinal in ranked[:fit_count]), dtype=np.int64)),
        np.sort(
            np.fromiter(
                (ordinal for _, ordinal in ranked[fit_count : fit_count + validation_count]),
                dtype=np.int64,
            )
        ),
        np.sort(
            np.fromiter(
                (ordinal for _, ordinal in ranked[fit_count + validation_count :]), dtype=np.int64
            )
        ),
    )
    if sum(len(role) for role in roles) != count:
        raise AssertionError("partition lost rows")
    return roles


def _read_rows(path: Path) -> Iterator[tuple[int, np.ndarray, int]]:
    with gzip.open(path, "rt", encoding="utf-8", newline="") as stream:
        reader = csv.reader(stream)
        header = next(reader, None)
        if header is None or len(header) != EXPECTED_FEATURE_COUNT + 1 or header[-1] != "Label":
            raise ValueError(f"prepared schema changed: {path}")
        for ordinal, row in enumerate(reader):
            if len(row) != len(header):
                raise ValueError(f"invalid row width in {path} at row {ordinal}")
            try:
                features = np.asarray(row[:-1], dtype=np.float32)
            except (ValueError, OverflowError) as error:
                raise ValueError(f"invalid numeric feature in {path} at row {ordinal}") from error
            if features.shape != (EXPECTED_FEATURE_COUNT,) or not np.isfinite(features).all():
                raise ValueError(f"invalid feature vector in {path} at row {ordinal}")
            yield ordinal, features, binary_label(row[-1])


def verify_preflight(root: Path) -> dict[str, Any]:
    """Fail closed against frozen Stage 5F protocol and Stage 5D artifacts."""
    protocol_path = root / PROTOCOL_RELATIVE_PATH
    manifest_path = root / MANIFEST_RELATIVE_PATH
    protocol_digest = _sha256(protocol_path)
    protocol = _load_json(protocol_path)
    manifest_digest = _sha256(manifest_path)
    if manifest_digest != protocol["frozen_inputs"]["preparation_manifest_sha256"]:
        raise ValueError("Stage 5D preparation manifest differs from frozen Stage 5F protocol")
    manifest = _load_json(manifest_path)
    by_name = {item["file"]: item for item in manifest["source_statistics"]}
    protocol_sources = protocol["frozen_inputs"]["sources"]
    if len(protocol_sources) != 7 or set(by_name) != {item["file"] for item in protocol_sources}:
        raise ValueError("source inventory differs from the frozen seven-source protocol")
    failures: list[str] = []
    verified: list[dict[str, Any]] = []
    for source in protocol_sources:
        name = source["file"]
        frozen = by_name[name]
        raw_path = root / source["raw_path"]
        # Frozen Stage 5F strings contain an extra ".csv" before ".model-ready";
        # use the Stage 5D manifest basename and require the frozen digest.
        prepared_path = _prepared_path(root, source)
        if source["raw_sha256"] != frozen["sha256"]:
            failures.append(f"{name}: protocol/raw-manifest hash mismatch")
        if source["prepared_sha256"] != frozen["output_sha256"]:
            failures.append(f"{name}: protocol/prepared-manifest hash mismatch")
        if not raw_path.is_file() or _sha256(raw_path) != source["raw_sha256"]:
            failures.append(f"{name}: raw source hash mismatch or missing")
        if not prepared_path.is_file() or _sha256(prepared_path) != source["prepared_sha256"]:
            failures.append(f"{name}: prepared source hash mismatch or missing")
        if source["prepared_rows"] != frozen["final_usable_row_count"]:
            failures.append(f"{name}: prepared row count mismatch")
        if len(source["prepared_class_counts"]) == 0:
            failures.append(f"{name}: no frozen class counts")
        verified.append(
            {
                "file": name,
                "raw_sha256": source["raw_sha256"],
                "prepared_sha256": source["prepared_sha256"],
                "rows": source["prepared_rows"],
                "class_counts": source["prepared_class_counts"],
            }
        )
    features = protocol["frozen_inputs"]["ordered_model_features"]
    if len(features) != EXPECTED_FEATURE_COUNT or len(features) != 77:
        failures.append("Stage 5F feature list is not the frozen 77-feature schema")
    if protocol["frozen_inputs"]["feature_dtype"] != "float32":
        failures.append("Stage 5F feature dtype is not float32")
    partition_config = protocol["source_and_window_design"]["initial_source_partition"]
    partition_seed = int(partition_config["seed"])
    if partition_seed != PARTITION_SEED:
        failures.append("initial partition seed differs from frozen seed 2026")
    if tuple(protocol["model"]["seeds"]) != SEEDS:
        failures.append("model seed set differs from frozen Stage 5F seed set")
    initial = protocol["source_and_window_design"]["initial_training_sources"]
    windows = [
        item["source_file"]
        for item in protocol["source_and_window_design"]["sequential_evaluation_windows"]
    ]
    expected_initial = [
        "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
        "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",
        "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv",
    ]
    observed_window_pairs = [
        (item["window_id"], item["source_file"])
        for item in protocol["source_and_window_design"]["sequential_evaluation_windows"]
    ]
    expected_windows = [source_name for _, source_name in FROZEN_WINDOW_ORDER]
    if initial != expected_initial or windows != expected_windows:
        failures.append("initial sources or sequential windows differ from frozen order")
    if observed_window_pairs != list(FROZEN_WINDOW_ORDER):
        failures.append("window IDs/source order differ from the frozen Stage 5F protocol")
    if set(initial).intersection(windows) or set(initial + windows) != set(by_name):
        failures.append("initial and sequential source partitions overlap or omit a source")
    if protocol["task_definition"]["label_mapping"] != {
        "Benign": "Benign",
        "every_other_frozen_source_label": "Attack",
    }:
        failures.append("binary label mapping differs from frozen protocol")
    if set(by_name["Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv"]["class_counts"]) != {
        "Benign",
        "DDoS attacks-LOIC-HTTP",
    }:
        failures.append("Tuesday source label inventory differs from frozen source manifest")
    if any("Thuesday-20-02" in name for name in initial):
        failures.append("Tuesday/LOIC-HTTP is included in initial training")
    if protocol["adaptation"]["fit_buffer"]["maximum_total_rows"] != MAX_BUFFER_ROWS:
        failures.append("adaptation buffer cap differs from frozen protocol")
    psi_config = protocol["drift_detector"]
    if (
        int(psi_config["minimum_sample_size"]["reference_rows"]) != PSI_REFERENCE_ROWS
        or int(psi_config["minimum_sample_size"]["comparison_rows"]) != PSI_COMPARISON_ROWS
        or float(psi_config["per_feature_threshold"]) != PSI_FEATURE_THRESHOLD
        or "at least 5 of 77" not in psi_config["window_trigger"]
        or "decile" not in psi_config["binning"]
        or "initial validation" not in psi_config["validation"]
    ):
        failures.append("PSI implementation constants differ from the frozen protocol")
    if not protocol["evaluation"]["adaptation_latency"].startswith("wall-clock"):
        failures.append("adaptation latency definition differs from the frozen protocol")
    if protocol["adaptation"]["labels_forbidden"].find("final-window labels") < 0:
        failures.append("protocol does not forbid final-window labels")
    if "terminal update" not in protocol["adaptation"]["frequency_limit"]:
        failures.append("protocol does not prohibit terminal W4 update")
    result_path = root / RESULT_RELATIVE_PATH
    report_path = root / REPORT_RELATIVE_PATH
    if result_path.exists() or report_path.exists():
        failures.append("Stage 5F result artifacts already exist; preflight expects no results")
    if failures:
        raise ValueError("Stage 5F preflight failed: " + "; ".join(failures))
    # Validate every prepared CSV header against the frozen ordered predictor schema.
    for item in verified:
        path = root / "data/processed/stage5d/cse-cic-ids2018" / Path(
            by_name[item["file"]]["output_path"]
        ).name
        with gzip.open(path, "rt", encoding="utf-8", newline="") as stream:
            header = next(csv.reader(stream), None)
        if header != features + ["Label"]:
            raise ValueError(f"{item['file']}: observed header differs from frozen schema")
    return {
        "passed": True,
        "protocol_sha256": protocol_digest,
        "preparation_manifest_sha256": manifest_digest,
        "sources": verified,
        "source_hashes_match": True,
        "prepared_hashes_match": True,
        "feature_count": len(features),
        "feature_names": features,
        "feature_dtype": "float32",
        "partition_seed": partition_seed,
        "model_seeds": list(SEEDS),
        "initial_partitions_identical_across_model_seeds": True,
        "partition_seed_by_model_seed": {
            str(seed): _partition_seed_for_run(protocol, seed) for seed in SEEDS
        },
        "psi_configuration_matches_protocol": True,
        "initial_validation_psi_required": True,
        "adaptation_latency_definition": ADAPTATION_LATENCY_DEFINITION,
        "adaptation_latency_uses_monotonic_wall_time": True,
        "result_artifacts_absent_at_preflight": True,
        "training_performed_during_preflight": False,
        "initial_sources": initial,
        "sequential_windows": windows,
        "tuesday_excluded_from_initial_fit": True,
        "anchor_partition_isolated_by_protocol": True,
        "psi_bins_fit_scope": "initial fit rows only",
        "w4_labels_adaptation_forbidden": True,
        "buffer_cap_rows": MAX_BUFFER_ROWS,
        "terminal_update_forbidden": True,
    }


def _initial_partitions(
    root: Path, protocol: dict[str, Any], model_seed: int
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, dict[str, Any]]:
    """Create exact frozen fit/validation/anchor partitions for initial sources."""
    partition_seed = _partition_seed_for_run(protocol, model_seed)
    sources = {item["file"]: item for item in protocol["frozen_inputs"]["sources"]}
    source_roles: dict[str, dict[int, np.ndarray]] = {}
    counts: dict[str, Counter[int]] = {}
    partition_manifest: list[dict[str, Any]] = []
    initial_files = protocol["source_and_window_design"]["initial_training_sources"]
    for name in initial_files:
        item = sources[name]
        path = _prepared_path(root, item)
        class_ordinals: dict[int, list[int]] = {0: [], 1: []}
        for ordinal, label in _read_labels(path):
            class_ordinals[label].append(ordinal)
        counts[name] = Counter({label: len(values) for label, values in class_ordinals.items()})
        source_roles[name] = {}
        per_label: dict[str, Any] = {}
        for label_code, ordinals in class_ordinals.items():
            label_name = CLASS_NAMES[label_code]
            actual = np.asarray(ordinals, dtype=np.int64)
            fit, validation, anchor = _partition_ordinals(
                actual, partition_seed, name, label_name
            )
            # Store actual original-file ordinals so no labels cross partitions.
            per_label[label_name] = {
                "source_class_rows": len(ordinals),
                "fit_rows": int(len(fit)),
                "validation_rows": int(len(validation)),
                "anchor_rows": int(len(anchor)),
                "partition_hashes_sha256": {
                    "fit": hashlib.sha256(fit.tobytes()).hexdigest(),
                    "validation": hashlib.sha256(validation.tobytes()).hexdigest(),
                    "anchor": hashlib.sha256(anchor.tobytes()).hexdigest(),
                },
            }
            source_roles[name][label_code] = np.asarray([fit, validation, anchor], dtype=object)
        partition_manifest.append({"source_file": name, "classes": per_label})

    role_sizes = [0, 0, 0]
    for name in initial_files:
        for role_idx in range(3):
            role_sizes[role_idx] += sum(
                len(source_roles[name][label][role_idx]) for label in (0, 1)
            )
    matrices = [np.empty((size, EXPECTED_FEATURE_COUNT), dtype=np.float32) for size in role_sizes]
    targets = [np.empty(size, dtype=np.int8) for size in role_sizes]
    offsets = [0, 0, 0]
    rank_positions: dict[str, dict[int, dict[int, int]]] = {}
    for name in initial_files:
        rank_positions[name] = {}
        for label in (0, 1):
            roles = source_roles[name][label]
            rank_positions[name][label] = {}
            for role_idx, selected in enumerate(roles):
                for ordinal in selected:
                    rank_positions[name][label][int(ordinal)] = role_idx
    for name in initial_files:
        path = _prepared_path(root, sources[name])
        for ordinal, features, label in _read_rows(path):
            assigned_role: int | None = rank_positions[name][label].get(ordinal)
            if assigned_role is None:
                raise ValueError(f"row absent from initial partition manifest: {name}:{ordinal}")
            offset = offsets[assigned_role]
            matrices[assigned_role][offset] = features
            targets[assigned_role][offset] = label
            offsets[assigned_role] += 1
    if offsets != role_sizes:
        raise ValueError("loaded initial partition sizes do not match precomputed sizes")
    for role_matrix, role_target in zip(matrices, targets, strict=True):
        order = np.lexsort((np.arange(len(role_target)), role_target))
        role_matrix[:] = role_matrix[order]
        role_target[:] = role_target[order]
    return (
        matrices[0],
        targets[0],
        matrices[1],
        targets[1],
        {
            "partition_seed": partition_seed,
            "model_seed": model_seed,
            "fit_rows": role_sizes[0],
            "validation_rows": role_sizes[1],
            "anchor_rows": role_sizes[2],
            "partition_by_source_and_binary_class": partition_manifest,
            "anchor_features": matrices[2],
            "anchor_labels": targets[2],
        },
    )


def _read_labels(path: Path) -> Iterator[tuple[int, int]]:
    with gzip.open(path, "rt", encoding="utf-8", newline="") as stream:
        reader = csv.reader(stream)
        header = next(reader, None)
        if header is None or len(header) != EXPECTED_FEATURE_COUNT + 1 or header[-1] != "Label":
            raise ValueError(f"prepared schema changed: {path}")
        for ordinal, row in enumerate(reader):
            if len(row) != len(header):
                raise ValueError(f"invalid row width in {path} at row {ordinal}")
            yield ordinal, binary_label(row[-1])


def _metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, Any]:
    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = (int(value) for value in matrix.ravel())
    per_f1 = f1_score(y_true, y_pred, labels=[0, 1], average=None, zero_division=0)
    return {
        "rows": int(len(y_true)),
        "class_support": {BENIGN: int(tn + fp), ATTACK: int(fn + tp)},
        "class_prevalence": {
            BENIGN: (tn + fp) / len(y_true) if len(y_true) else 0.0,
            ATTACK: (fn + tp) / len(y_true) if len(y_true) else 0.0,
        },
        "macro_f1": float(
            f1_score(y_true, y_pred, labels=[0, 1], average="macro", zero_division=0)
        ),
        "weighted_f1": float(
            f1_score(y_true, y_pred, labels=[0, 1], average="weighted", zero_division=0)
        ),
        "per_class_f1": {BENIGN: float(per_f1[0]), ATTACK: float(per_f1[1])},
        "benign_fpr": fp / (tn + fp) if tn + fp else 0.0,
        "attack_fnr_as_benign": fn / (fn + tp) if fn + tp else 0.0,
        "confusion_matrix_actual_benign_attack_predicted_benign_attack": matrix.tolist(),
    }


def _predict_metrics(
    model: RandomForestClassifier, x: np.ndarray, y: np.ndarray
) -> tuple[dict[str, Any], float]:
    predictions: list[np.ndarray] = []
    elapsed = 0.0
    for start in range(0, len(y), CHUNK_ROWS):
        stop = min(start + CHUNK_ROWS, len(y))
        before = time.perf_counter()
        predictions.append(model.predict(x[start:stop]).astype(np.int8, copy=False))
        elapsed += time.perf_counter() - before
    predicted = np.concatenate(predictions) if predictions else np.empty(0, dtype=np.int8)
    return _metrics(y, predicted), elapsed


def _fit_model(x: np.ndarray, y: np.ndarray, seed: int) -> tuple[RandomForestClassifier, float]:
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=18,
        max_features="sqrt",
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        random_state=seed,
        n_jobs=1,
    )
    started = time.perf_counter()
    model.fit(x, y)
    return model, time.perf_counter() - started


def _initial_rf_config(seed: int) -> dict[str, Any]:
    return {
        "name": "RandomForestClassifier",
        "n_estimators": 100,
        "max_depth": 18,
        "max_features": "sqrt",
        "min_samples_leaf": 2,
        "class_weight": "balanced_subsample",
        "random_state": seed,
        "n_jobs": 1,
    }


def _fit_psi_bins(reference: np.ndarray) -> list[dict[str, Any]]:
    """Fit reference-only decile edges, retaining unique edges and constant rules."""
    specifications: list[dict[str, Any]] = []
    quantiles = np.linspace(0.1, 0.9, 9)
    for feature_index in range(reference.shape[1]):
        values = reference[:, feature_index].astype(np.float64, copy=False)
        unique = np.unique(values)
        if len(unique) == 1:
            edges = np.asarray([], dtype=np.float64)
            constant = float(unique[0])
        else:
            interior = np.quantile(values, quantiles, method="linear")
            edges = np.unique(np.concatenate(([values.min()], interior, [values.max()])))
            constant = None
        specifications.append(
            {
                "edges": edges,
                "constant_reference_value": constant,
                "reference_counts": _bin_counts(values, edges, constant),
            }
        )
    return specifications


def _bin_counts(values: np.ndarray, edges: np.ndarray, constant: float | None) -> np.ndarray:
    if constant is not None:
        bins = np.where(values < constant, 0, np.where(values == constant, 1, 2))
        return np.bincount(bins.astype(np.int64), minlength=3)
    # Explicit underflow, decile bins, and overflow. right=False places edge equality rightward.
    bins = np.searchsorted(edges, values, side="right")
    return np.bincount(bins.astype(np.int64), minlength=len(edges) + 1)


def psi_values(
    reference_counts: list[np.ndarray],
    comparison: np.ndarray,
    bins: list[dict[str, Any]],
) -> np.ndarray:
    """Compute deterministic per-feature PSI with 0.5 count smoothing."""
    if comparison.ndim != 2 or comparison.shape[1] != len(bins):
        raise ValueError("comparison matrix and PSI bin schema differ")
    if len(reference_counts) != len(bins):
        raise ValueError("reference count and PSI bin schema differ")
    values = np.empty(len(bins), dtype=np.float64)
    for index, spec in enumerate(bins):
        observed = _bin_counts(
            comparison[:, index].astype(np.float64, copy=False),
            cast(np.ndarray, spec["edges"]),
            cast(float | None, spec["constant_reference_value"]),
        )
        expected = reference_counts[index]
        if len(observed) != len(expected):
            raise ValueError("PSI observed and reference bins have different sizes")
        p = (expected.astype(np.float64) + 0.5) / (expected.sum() + 0.5 * len(expected))
        q = (observed.astype(np.float64) + 0.5) / (observed.sum() + 0.5 * len(observed))
        values[index] = np.sum((q - p) * np.log(q / p))
    return values


def _choose_sample(matrix: np.ndarray, sample_size: int, seed: int, identity: str) -> np.ndarray:
    ordinals = _sample_ordinals(len(matrix), sample_size, seed, identity)
    return cast(np.ndarray, matrix[ordinals])


def _evaluate_window(
    root: Path,
    source: dict[str, Any],
    models: dict[str, RandomForestClassifier],
    bins: list[dict[str, Any]],
    reference_counts: list[np.ndarray],
    seed: int,
    window_id: str,
) -> tuple[dict[str, dict[str, Any]], np.ndarray]:
    path = _prepared_path(root, source)
    row_count = int(source["prepared_rows"])
    selected = _sample_ordinals(
        row_count,
        PSI_COMPARISON_ROWS,
        seed,
        f"PSI-COMPARISON\0{window_id}",
    )
    selected_set = set(int(value) for value in selected)
    psi_rows = np.empty((PSI_COMPARISON_ROWS, EXPECTED_FEATURE_COUNT), dtype=np.float32)
    confusions = {name: np.zeros((2, 2), dtype=np.int64) for name in models}
    class_support = np.zeros(2, dtype=np.int64)
    prediction_seconds = {name: 0.0 for name in models}
    rows = 0
    sample_offset = 0
    with gzip.open(path, "rt", encoding="utf-8", newline="") as stream:
        reader = csv.reader(stream)
        header = next(reader, None)
        if header is None or header[-1] != "Label" or len(header) != EXPECTED_FEATURE_COUNT + 1:
            raise ValueError(f"prepared window schema changed: {source['file']}")
        while rows_batch := list(islice(reader, CHUNK_ROWS)):
            matrix = np.asarray([row[:-1] for row in rows_batch], dtype=np.float32)
            actual = np.fromiter((binary_label(row[-1]) for row in rows_batch), dtype=np.int8)
            for name, model in models.items():
                before = time.perf_counter()
                predicted = model.predict(matrix).astype(np.int8, copy=False)
                prediction_seconds[name] += time.perf_counter() - before
                confusions[name] += confusion_matrix(actual, predicted, labels=[0, 1])
            class_support += np.bincount(actual, minlength=2)
            for local_index in range(len(rows_batch)):
                ordinal = rows + local_index
                if ordinal in selected_set:
                    psi_rows[sample_offset] = matrix[local_index]
                    sample_offset += 1
            rows += len(rows_batch)
    if rows != row_count or sample_offset != PSI_COMPARISON_ROWS:
        raise ValueError(f"window row/sample count mismatch for {source['file']}")
    psi = psi_values(reference_counts, psi_rows, bins)
    signaled = np.flatnonzero(psi >= PSI_FEATURE_THRESHOLD)
    result: dict[str, dict[str, Any]] = {}
    for name, confusion in confusions.items():
        tn, fp, fn, tp = (int(value) for value in confusion.ravel())
        per_f1 = f1_score_from_confusion(confusion)
        result[name] = {
            "rows": int(class_support.sum()),
            "class_support": {BENIGN: int(class_support[0]), ATTACK: int(class_support[1])},
            "class_prevalence": {
                BENIGN: float(class_support[0] / class_support.sum()),
                ATTACK: float(class_support[1] / class_support.sum()),
            },
            "macro_f1": float(np.mean(per_f1)),
            "weighted_f1": float(
                (per_f1[0] * class_support[0] + per_f1[1] * class_support[1])
                / max(int(class_support.sum()), 1)
            ),
            "per_class_f1": {BENIGN: per_f1[0], ATTACK: per_f1[1]},
            "benign_fpr": fp / (tn + fp) if tn + fp else 0.0,
            "attack_fnr_as_benign": fn / (fn + tp) if fn + tp else 0.0,
            "confusion_matrix_actual_benign_attack_predicted_benign_attack": confusion.tolist(),
            "psi": psi.tolist(),
            "signaled_feature_indices": signaled.astype(int).tolist(),
            "signaled_feature_count": int(len(signaled)),
            "psi_triggered": psi_triggered(psi),
            "psi_sample_rows": PSI_COMPARISON_ROWS,
            "prediction_seconds": prediction_seconds[name],
        }
    return result, psi_rows


def f1_score_from_confusion(confusion: np.ndarray) -> list[float]:
    result: list[float] = []
    for label in (0, 1):
        tp = int(confusion[label, label])
        fp = int(confusion[:, label].sum() - tp)
        fn = int(confusion[label, :].sum() - tp)
        denominator = 2 * tp + fp + fn
        result.append(2 * tp / denominator if denominator else 0.0)
    return result


def _select_window_buffer(
    root: Path,
    source: dict[str, Any],
    seed: int,
    window_id: str,
) -> tuple[np.ndarray, np.ndarray, dict[str, Any]]:
    """Select up to 10k per binary class by SHA-256 rank, then read those rows."""
    path = _prepared_path(root, source)
    candidates: dict[int, list[tuple[int, int]]] = {0: [], 1: []}
    limits = {
        0: min(BUFFER_RECENT_PER_CLASS, int(source["prepared_class_counts"].get(BENIGN, 0))),
        1: 0,
    }
    limits[1] = min(
        BUFFER_RECENT_PER_CLASS,
        sum(
            int(count)
            for label_name, count in source["prepared_class_counts"].items()
            if label_name != BENIGN
        ),
    )
    # Keep only each class's smallest deterministic SHA ranks in bounded heaps.
    for ordinal, label in _read_labels(path):
        limit = limits[label]
        if limit == 0:
            continue
        rank = int.from_bytes(_hash_rank(seed, f"BUFFER\0{window_id}\0{label}", ordinal), "big")
        item = (-rank, -ordinal)
        heap = candidates[label]
        if len(heap) < limit:
            heapq.heappush(heap, item)
        elif item > heap[0]:
            heapq.heapreplace(heap, item)
    selected_by_class: dict[int, set[int]] = {}
    selected_counts: dict[str, int] = {}
    for label in (0, 1):
        chosen = candidates[label]
        selected_by_class[label] = {-ordinal for _, ordinal in chosen}
        selected_counts[CLASS_NAMES[label]] = len(chosen)
    selected_x = np.empty((sum(selected_counts.values()), EXPECTED_FEATURE_COUNT), dtype=np.float32)
    selected_y = np.empty(len(selected_x), dtype=np.int8)
    offset = 0
    for ordinal, features, label in _read_rows(path):
        if ordinal in selected_by_class[label]:
            selected_x[offset] = features
            selected_y[offset] = label
            offset += 1
    if offset != len(selected_y):
        raise ValueError(f"selected adaptation buffer rows changed for {source['file']}")
    selected_ordinals_hash = hashlib.sha256(
        b"".join(
            label.to_bytes(1, "big") + ordinal.to_bytes(8, "big")
            for label in (0, 1)
            for ordinal in sorted(selected_by_class[label])
        )
    ).hexdigest()
    return (
        selected_x,
        selected_y,
        {
            "rows_by_class": selected_counts,
            "selected_ordinals_sha256": selected_ordinals_hash,
        },
    )


def _initial_replay(x: np.ndarray, y: np.ndarray, seed: int) -> tuple[np.ndarray, np.ndarray]:
    selected: list[np.ndarray] = []
    for label in (0, 1):
        positions = np.flatnonzero(y == label)
        count = min(BUFFER_REPLAY_PER_CLASS, len(positions))
        ranked_local = _sample_ordinals(
            len(positions), count, seed, f"INITIAL-REPLAY\0{CLASS_NAMES[label]}"
        )
        selected.append(positions[ranked_local])
    indices = np.concatenate(selected)
    order = np.lexsort((indices, y[indices]))
    indices = indices[order]
    return x[indices].copy(), y[indices].copy()


def _build_adaptation_buffer(
    replay_x: np.ndarray,
    replay_y: np.ndarray,
    released_windows: list[tuple[str, dict[str, Any]]],
    root: Path,
    seed: int,
) -> tuple[np.ndarray, np.ndarray, dict[str, Any]]:
    recent_x: list[np.ndarray] = []
    recent_y: list[np.ndarray] = []
    membership: list[dict[str, Any]] = []
    for window_id, source in released_windows[-BUFFER_RECENT_WINDOWS:]:
        x, y, counts = _select_window_buffer(root, source, seed, window_id)
        recent_x.append(x)
        recent_y.append(y)
        membership.append({"window_id": window_id, "source_file": source["file"], **counts})
    x_parts = [replay_x, *recent_x]
    y_parts = [replay_y, *recent_y]
    buffer_x = np.concatenate(x_parts, axis=0)
    buffer_y = np.concatenate(y_parts, axis=0)
    if len(buffer_y) > MAX_BUFFER_ROWS:
        raise ValueError("frozen adaptation buffer cap exceeded")
    return (
        buffer_x,
        buffer_y,
        {
            "rows": len(buffer_y),
            "class_counts": {
                CLASS_NAMES[label]: int(np.count_nonzero(buffer_y == label)) for label in (0, 1)
            },
            "initial_replay_rows": len(replay_y),
            "recent_windows": membership,
            "membership_sha256": hashlib.sha256(
                replay_x.tobytes()
                + replay_y.tobytes()
                + b"".join(
                    x.tobytes() + y.tobytes() for x, y in zip(recent_x, recent_y, strict=True)
                )
            ).hexdigest(),
        },
    )


def _psi_reference_from_buffer(
    matrix: np.ndarray, bins: list[dict[str, Any]], seed: int, identity: str
) -> list[np.ndarray]:
    size = min(PSI_REFERENCE_ROWS, len(matrix))
    sample = _choose_sample(matrix, size, seed, f"PSI-REFERENCE-RESET\0{identity}")
    return [
        _bin_counts(
            sample[:, index].astype(np.float64),
            cast(np.ndarray, spec["edges"]),
            cast(float | None, spec["constant_reference_value"]),
        )
        for index, spec in enumerate(bins)
    ]


def _aggregate_metrics(rows: list[dict[str, Any]], key: str) -> dict[str, Any]:
    values = np.asarray([float(row[key]) for row in rows], dtype=np.float64)
    return {
        "mean": float(values.mean()),
        "std": float(values.std(ddof=1)) if len(values) > 1 else 0.0,
    }


def _paired_comparisons(seed_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    pairs = (("static", "periodic"), ("static", "drift_triggered"), ("periodic", "drift_triggered"))
    comparisons: list[dict[str, Any]] = []
    for window in ("W1", "W2", "W3", "W4"):
        for metric in ("macro_f1", "benign_fpr", "attack_fnr_as_benign"):
            for left, right in pairs:
                by_seed = {
                    record["seed"]: record["window_metrics"][left][window][metric]
                    - record["window_metrics"][right][window][metric]
                    for record in seed_records
                }
                differences = np.asarray([by_seed[seed] for seed in SEEDS], dtype=np.float64)
                mean = float(differences.mean())
                std = float(differences.std(ddof=1))
                if std == 0.0:
                    ci_low = mean
                    ci_high = mean
                    dz: float | None = None
                else:
                    if len(differences) != 5:
                        raise ValueError("paired 95% t interval requires the frozen five seeds")
                    critical = PAIRED_T_975_DF4
                    margin = critical * std / math.sqrt(len(differences))
                    ci_low, ci_high = mean - margin, mean + margin
                    dz = mean / std
                comparisons.append(
                    {
                        "window": window,
                        "metric": metric,
                        "difference": f"{left} minus {right}",
                        "paired_mean_difference": mean,
                        "paired_difference_std": std,
                        "95_percent_paired_t_interval": [ci_low, ci_high],
                        "cohens_dz": dz,
                        "paired_values_by_seed": by_seed,
                    }
                )
    return comparisons


def _summarize(seed_records: list[dict[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "strategies": {},
        "paired_comparisons": _paired_comparisons(seed_records),
    }
    for strategy in ("static", "periodic", "drift_triggered"):
        summary["strategies"][strategy] = {}
        for window in ("initial_validation", "W1", "W2", "W3", "W4"):
            records = [record["window_metrics"][strategy][window] for record in seed_records]
            summary["strategies"][strategy][window] = {
                metric: _aggregate_metrics(records, metric)
                for metric in (
                    "macro_f1",
                    "weighted_f1",
                    "benign_fpr",
                    "attack_fnr_as_benign",
                    "per_class_f1_benign",
                    "per_class_f1_attack",
                )
            }
    return summary


def _anchor_metrics(
    model: RandomForestClassifier, x: np.ndarray, y: np.ndarray
) -> tuple[dict[str, Any], float]:
    return _predict_metrics(model, x, y)


def run_seed(
    root: Path,
    protocol: dict[str, Any],
    preflight: dict[str, Any],
    seed: int,
) -> dict[str, Any]:
    initial_x, initial_y, validation_x, validation_y, partitions = _initial_partitions(
        root, protocol, seed
    )
    anchor_x = cast(np.ndarray, partitions.pop("anchor_features"))
    anchor_y = cast(np.ndarray, partitions.pop("anchor_labels"))
    initial_model, initial_fit_seconds = _fit_model(initial_x, initial_y, seed)
    initial_validation, initial_validation_inference = _predict_metrics(
        initial_model, validation_x, validation_y
    )
    initial_anchor, initial_anchor_inference = _anchor_metrics(initial_model, anchor_x, anchor_y)
    replay_x, replay_y = _initial_replay(initial_x, initial_y, seed)
    ref_positions = _sample_ordinals(
        len(initial_x), PSI_REFERENCE_ROWS, seed, "PSI-INITIAL-REFERENCE"
    )
    reference_sample = initial_x[ref_positions]
    bins = _fit_psi_bins(reference_sample)
    reference_counts = [cast(np.ndarray, spec["reference_counts"]) for spec in bins]
    validation_positions = _sample_ordinals(
        len(validation_x), PSI_COMPARISON_ROWS, seed, "PSI-INITIAL-VALIDATION"
    )
    initial_validation_psi = psi_report(
        reference_counts, validation_x[validation_positions], bins
    )
    initial_validation_psi["sample_identity"] = "disjoint initial validation partition"
    initial_validation_psi["signaled_feature_names"] = [
        protocol["frozen_inputs"]["ordered_model_features"][index]
        for index in initial_validation_psi["signaled_feature_indices"]
    ]
    source_by_name = {item["file"]: item for item in protocol["frozen_inputs"]["sources"]}
    window_defs = protocol["source_and_window_design"]["sequential_evaluation_windows"]
    result: dict[str, Any] = {
        "seed": seed,
        "model_configuration": _initial_rf_config(seed),
        "initial_partition": partitions,
        "initial_fit_seconds": initial_fit_seconds,
        "initial_validation_metrics": initial_validation,
        "initial_validation_inference_seconds": initial_validation_inference,
        "initial_anchor_metrics": initial_anchor,
        "initial_anchor_inference_seconds": initial_anchor_inference,
        "initial_validation_psi": initial_validation_psi,
        "initial_anchor_forgetting_reference": {
            "macro_f1": initial_anchor["macro_f1"],
            "benign_fpr": initial_anchor["benign_fpr"],
        },
        "psi_reference_rows": PSI_REFERENCE_ROWS,
        "psi_bin_edges": [cast(np.ndarray, spec["edges"]).tolist() for spec in bins],
        "psi_constant_reference_features": [
            index for index, spec in enumerate(bins) if spec["constant_reference_value"] is not None
        ],
        "window_metrics": {
            "static": {"initial_validation": _window_metric_record(initial_validation)},
            "periodic": {"initial_validation": _window_metric_record(initial_validation)},
            "drift_triggered": {"initial_validation": _window_metric_record(initial_validation)},
        },
        "strategy_events": {"static": [], "periodic": [], "drift_triggered": []},
        "window_events": [],
    }
    del initial_x, initial_y, reference_sample
    active_models = {
        "static": initial_model,
        "periodic": copy.deepcopy(initial_model),
        "drift_triggered": copy.deepcopy(initial_model),
    }
    anchor_baseline = initial_anchor
    released_windows: list[tuple[str, dict[str, Any]]] = []
    pending_drift_trigger = False
    pending_trigger_windows: list[str] = []
    for window_index, window in enumerate(window_defs, start=1):
        window_id = window["window_id"]
        source = source_by_name[window["source_file"]]
        # One sequential source read feeds all paired model scores and the PSI sample.
        metric_by_strategy, comparison = _evaluate_window(
            root,
            source,
            active_models,
            bins,
            reference_counts,
            seed,
            window_id,
        )
        psi_summary = psi_report(reference_counts, comparison, bins)
        signaled = np.asarray(psi_summary["signaled_feature_indices"], dtype=np.int64)
        triggered = bool(psi_summary["psi_triggered"])
        if triggered:
            pending_drift_trigger = True
            pending_trigger_windows.append(window_id)
        window_psi = {
            "window_id": window_id,
            "source_file": source["file"],
            **psi_summary,
            "signaled_feature_names": [
                protocol["frozen_inputs"]["ordered_model_features"][int(i)] for i in signaled
            ],
        }
        for strategy in ("static", "periodic", "drift_triggered"):
            metric = metric_by_strategy[strategy]
            metric["psi_triggered"] = bool(triggered)
            metric["signaled_feature_count"] = int(len(signaled))
            metric["periodic_update_due"] = bool(window_id in {"W2", "W4"})
            metric["adaptation_attempted"] = False
            metric["adaptation_accepted"] = None
            metric["adaptation_latency"] = None
            metric["forgetting_anchor_macro_f1"] = None
            metric["forgetting_anchor_benign_fpr"] = None
            metric["inference_seconds"] = metric["prediction_seconds"]
            result["window_metrics"][strategy][window_id] = _window_metric_record(metric)
        del comparison, metric_by_strategy
        result["window_events"].append(window_psi)

        # Wk labels are released only when W(k+1) closes. W4 labels never release.
        if window_index < len(window_defs):
            # This is availability after the next window closes; add the previous window now.
            # At W1 boundary there is no eligible label. At W2 boundary, release W1.
            released_name, terminal = released_window_after_boundary(window_index)
            if released_name is not None and not terminal:
                prior = next(item for item in window_defs if item["window_id"] == released_name)
                released_windows.append((prior["window_id"], source_by_name[prior["source_file"]]))
            released_summary = {
                "evaluated_window": window_id,
                "released_window": released_name,
                "eligible_labeled_windows": [name for name, _ in released_windows],
            }
        else:
            # W3 labels become available after W4 closes, but W4 is terminal and
            # no adaptation can consume them. W4 labels are never released.
            released_name, terminal = released_window_after_boundary(window_index)
            prior = next(item for item in window_defs if item["window_id"] == released_name)
            released_windows.append((prior["window_id"], source_by_name[prior["source_file"]]))
            released_summary = {
                "evaluated_window": window_id,
                "released_window": prior["window_id"],
                "eligible_labeled_windows": [name for name, _ in released_windows],
                "used_for_adaptation": False,
                "terminal_window_labels_forbidden": True,
            }
        release_monotonic_ns = time.perf_counter_ns()
        released_summary["eligible_label_release_monotonic_ns"] = release_monotonic_ns
        result.setdefault("label_release_events", []).append(released_summary)

        if window_id == "W4":
            for strategy in ("periodic", "drift_triggered"):
                result["strategy_events"][strategy].append(
                    {
                        "window_boundary": "W4",
                        "attempted": False,
                        "reason": "terminal window; no update allowed",
                    }
                )
            continue

        # Apply scheduled/triggered adaptation only after the current window closes.
        for strategy in ("periodic", "drift_triggered"):
            due = should_attempt_update(strategy, window_id, pending_drift_trigger)
            if not due:
                continue
            if not released_windows:
                result["strategy_events"][strategy].append(
                    {
                        "window_boundary": window_id,
                        "attempted": False,
                        "reason": "no eligible delayed labels",
                    }
                )
                continue
            update_decision_monotonic_ns = time.perf_counter_ns()
            buffer_x, buffer_y, buffer_info = _build_adaptation_buffer(
                replay_x, replay_y, released_windows, root, seed
            )
            candidate, fit_seconds = _fit_model(buffer_x, buffer_y, seed)
            fit_complete_monotonic_ns = time.perf_counter_ns()
            latency = adaptation_latency(
                release_monotonic_ns,
                update_decision_monotonic_ns,
                fit_complete_monotonic_ns,
            )
            anchor_metrics, anchor_inference_seconds = _anchor_metrics(
                candidate, anchor_x, anchor_y
            )
            event_trigger_windows = list(pending_trigger_windows)
            macro_drop = anchor_baseline["macro_f1"] - anchor_metrics["macro_f1"]
            fpr_increase = anchor_metrics["benign_fpr"] - anchor_baseline["benign_fpr"]
            rejection_reasons = rollback_reasons(anchor_baseline, anchor_metrics)
            accepted = not rejection_reasons
            if accepted:
                active_models[strategy] = candidate
                reference_counts = (
                    _psi_reference_from_buffer(buffer_x, bins, seed, f"{strategy}-{window_id}")
                    if strategy == "drift_triggered"
                    else reference_counts
                )
                if strategy == "drift_triggered":
                    pending_drift_trigger = False
                    pending_trigger_windows = []
            else:
                del candidate
            event = {
                "window_boundary": window_id,
                "strategy": strategy,
                "attempted": True,
                "accepted": accepted,
                "rejection_reasons": rejection_reasons,
                "trigger_windows": event_trigger_windows if strategy == "drift_triggered" else [],
                "label_release_window": released_windows[0][0],
                "adaptation_latency": latency,
                "adaptation_latency_to_acceptance_seconds": (
                    latency["release_to_fit_complete_seconds"] if accepted else None
                ),
                "buffer": buffer_info,
                "training_seconds": fit_seconds,
                "anchor_inference_seconds": anchor_inference_seconds,
                "anchor_metrics": anchor_metrics,
                "anchor_macro_f1_drop_from_initial": macro_drop,
                "anchor_benign_fpr_increase_from_initial": fpr_increase,
                "candidate_kept_as_production": accepted,
                "model_rebuilt_from_scratch": True,
            }
            result["strategy_events"][strategy].append(event)
            # Attach post-fit anchor and cost to this evaluation boundary row.
            boundary_record = result["window_metrics"][strategy][window_id]
            boundary_record["adaptation_attempted"] = True
            boundary_record["adaptation_accepted"] = accepted
            boundary_record["adaptation_training_seconds"] = fit_seconds
            boundary_record["adaptation_latency"] = latency
            boundary_record["forgetting_anchor_macro_f1"] = anchor_metrics["macro_f1"]
            boundary_record["forgetting_anchor_benign_fpr"] = anchor_metrics["benign_fpr"]
            if strategy == "drift_triggered" and accepted:
                boundary_record["psi_reference_reset_from_buffer"] = True
            if strategy == "periodic" and due:
                boundary_record["periodic_update_due"] = True
            del buffer_x, buffer_y

    result["resource_usage"] = {
        "peak_process_rss_bytes": _peak_rss_bytes(),
        "peak_measurement": (
            "process peak RSS via getrusage; includes all seed work completed so far"
        ),
    }
    return result


def _window_metric_record(metrics: dict[str, Any]) -> dict[str, Any]:
    return {
        "rows": metrics["rows"],
        "class_support": metrics["class_support"],
        "class_prevalence": metrics["class_prevalence"],
        "macro_f1": metrics["macro_f1"],
        "weighted_f1": metrics["weighted_f1"],
        "per_class_f1_benign": metrics["per_class_f1"][BENIGN],
        "per_class_f1_attack": metrics["per_class_f1"][ATTACK],
        "benign_fpr": metrics["benign_fpr"],
        "attack_fnr_as_benign": metrics["attack_fnr_as_benign"],
        "confusion_matrix_actual_benign_attack_predicted_benign_attack": metrics[
            "confusion_matrix_actual_benign_attack_predicted_benign_attack"
        ],
        "inference_seconds": metrics.get(
            "inference_seconds", metrics.get("prediction_seconds", 0.0)
        ),
        "psi": metrics.get("psi", []),
        "signaled_feature_count": metrics.get("signaled_feature_count", 0),
        "psi_triggered": metrics.get("psi_triggered", False),
        "periodic_update_due": metrics.get("periodic_update_due", False),
        "adaptation_attempted": metrics.get("adaptation_attempted", False),
        "adaptation_accepted": metrics.get("adaptation_accepted"),
        "adaptation_latency": metrics.get("adaptation_latency"),
        "forgetting_anchor_macro_f1": metrics.get("forgetting_anchor_macro_f1"),
        "forgetting_anchor_benign_fpr": metrics.get("forgetting_anchor_benign_fpr"),
    }


def run_experiment(root: Path, preflight: dict[str, Any]) -> dict[str, Any]:
    protocol = _load_json(root / PROTOCOL_RELATIVE_PATH)
    source_records: list[dict[str, Any]] = []
    for seed in SEEDS:
        source_records.append(run_seed(root, protocol, preflight, seed))
    summary = _summarize(source_records)
    adaptation_summary: dict[str, Any] = {}
    for strategy in ("periodic", "drift_triggered"):
        events = [
            event for record in source_records for event in record["strategy_events"][strategy]
        ]
        attempts = [event for event in events if event.get("attempted")]
        adaptation_summary[strategy] = {
            "attempted": len(attempts),
            "accepted": sum(bool(event["accepted"]) for event in attempts),
            "rejected": sum(not bool(event["accepted"]) for event in attempts),
            "events_by_seed": {
                str(record["seed"]): record["strategy_events"][strategy]
                for record in source_records
            },
        }
    return {
        "stage": "5F",
        "experiment_id": "CSE-STAGE5F-SOURCE-DISTRIBUTION-SHIFT-RF-ADAPTATION",
        "status": "completed",
        "condition": "SOURCE/DISTRIBUTION SHIFT; not temporal drift or concept drift",
        "research_question": protocol["research_question"],
        "protocol_sha256": preflight["protocol_sha256"],
        "preparation_manifest_sha256": preflight["preparation_manifest_sha256"],
        "preflight": preflight,
        "protocol_configuration": {
            "source_order": protocol["source_and_window_design"],
            "task_definition": protocol["task_definition"],
            "model": protocol["model"],
            "strategies": protocol["strategies"],
            "psi": protocol["drift_detector"],
            "adaptation": protocol["adaptation"],
        },
        "seed_runs": source_records,
        "summary_mean_std_across_seeds": summary,
        "adaptation_summary": adaptation_summary,
        "limitations": protocol["known_limitations"],
        "interpretation": (
            "Observed differences are source/distribution differences under this imposed sequence. "
            "PSI monitors P(X) only and does not establish concept drift or a change in P(Y|X)."
        ),
    }
