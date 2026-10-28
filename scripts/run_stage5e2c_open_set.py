"""Run the Stage 5E.2C CSE Random Forest confidence-rejection experiment."""

from __future__ import annotations

import argparse
import json
import platform
from pathlib import Path
from typing import Any

import numpy
import sklearn

from ml.evaluation.stage5e2c_open_set import (
    load_manifests,
    load_stage5e2a_context,
    load_stage5e2b_context,
    run_experiment,
    verify_stage_preflight,
)


def _markdown(result: dict[str, Any]) -> str:
    primary = result["primary_metrics"]
    matrix = primary[
        "confusion_matrix_actual_rows_benign_then_loic_http_predicted_columns_known_then_unknown"
    ]
    lines = [
        "# Stage 5E.2C — CSE RF confidence-based open-set rejection",
        "",
        "**Scope:** one confidence-based open-set mechanism under the frozen CSE-CIC-IDS2018 "
        "Tuesday source-held-out LOIC-HTTP condition. This is an empirical test, not an "
        "assumption that rejection will help or a general zero-day claim.",
        "",
        "## Preflight and partitions",
        "",
        "- Stage 5D prepared-data integrity preflight: passed before training.",
        "- Training sources: six non-Tuesday sources; Tuesday is test-only.",
        f"- RF training rows: {result['training_rows']:,}.",
        f"- Validation rows: {result['validation_protocol']['validation_rows']:,}; "
        f"benign validation rows: {result['validation_protocol']['benign_validation_rows']:,}.",
        f"- Tuesday test rows: {result['test_rows']:,}.",
        f"- Attack rows in six training sources excluded from threshold calibration: "
        f"{result['attack_rows_in_six_training_sources_excluded_from_threshold_fitting']:,}. "
        "These attack rows remain eligible for supervised RF fitting when assigned to the "
        "training partition.",
        f"- Attack rows held out in validation and excluded from RF fitting: "
        f"{result['validation_attack_rows_excluded_from_training_and_threshold_fitting']:,}. "
        "Only benign validation probabilities select thresholds.",
        f"- LOIC-HTTP absent from training vocabulary: "
        f"{result['loic_http_absent_from_training_vocabulary']}.",
        f"- Predictors: {result['feature_schema']['count']} frozen ordered float32 features.",
        "- Preprocessing: fixed Stage 5D CSV-to-float32 cast; no fitted preprocessing.",
        "",
        "The deterministic validation split selects an exact 20% of row ordinals without "
        "replacement within each source and training class. The remaining rows fit the RF. "
        "Only benign validation `p_max` values select rejection thresholds; validation "
        "attack rows do not determine thresholds. Tuesday labels are not inputs to fitting, "
        "validation, threshold selection, or model selection.",
        "",
        "## Frozen Random Forest configuration",
        "",
        "```json",
        json.dumps(result["model"], indent=2),
        "```",
        "",
        "## Confidence and threshold protocol",
        "",
        "For each flow, `p_max` is the largest RF class probability. If `p_max < threshold`, "
        "the output is UNKNOWN; otherwise the RF argmax class is retained. Low confidence "
        "is tested as a rejection signal and is not assumed to imply novelty.",
        "",
        "Thresholds use benign validation probabilities only. For each target, the selected "
        "confidence group boundary gives the closest attainable benign rejection count; "
        "confidence ties are indivisible and ties in distance choose fewer rejections. "
        "The primary operating point was preregistered at 1%.",
        "",
        f"Primary threshold: **{result['threshold_selection']['primary']['threshold']:.12g}**; "
        f"realized validation benign rejection: "
        f"**{result['threshold_selection']['primary']['validation_benign_rejection_rate']:.6%}**.",
        "",
        "## Primary 1% results",
        "",
        f"Benign test rows: {primary['benign_test_rows']:,}; "
        f"LOIC-HTTP test rows: {primary['loic_http_test_rows']:,}.",
        "",
        "| Metric | Result |",
        "|---|---:|",
        f"| Benign rejection / FPR | {primary['benign_rejection_rate_fpr']:.6%} |",
        f"| LOIC-HTTP unknown recall | {primary['loic_http_unknown_recall']:.6%} |",
        f"| LOIC-HTTP known rate | {primary['loic_http_known_rate']:.6%} |",
        f"| Unknown precision | {primary['unknown_precision']:.6%} |",
        f"| Unknown F1 | {primary['unknown_f1']:.6f} |",
        f"| Balanced accuracy | {primary['balanced_accuracy']:.6f} |",
        "",
        "### Counts and confusion matrix",
        "",
        f"- Benign known: {primary['benign_known_count']:,}; "
        f"benign UNKNOWN: {primary['benign_unknown_count']:,}.",
        f"- LOIC-HTTP known: {primary['loic_http_known_count']:,}; "
        f"LOIC-HTTP UNKNOWN: {primary['loic_http_unknown_count']:,}.",
        "",
        "| Actual \\ Predicted | Known | Unknown |",
        "|---|---:|---:|",
        f"| Benign | {matrix[0][0]:,} | {matrix[0][1]:,} |",
        f"| LOIC-HTTP | {matrix[1][0]:,} | {matrix[1][1]:,} |",
        "",
        "### LOIC-HTTP flows retained as known",
        "",
        "| RF predicted known class | Count |",
        "|---|---:|",
    ]
    for label, count in primary["loic_http_predicted_known_class_distribution"].items():
        lines.append(f"| {label} | {count:,} |")
    lines.extend(
        [
            "",
            "## Sensitivity by benign rejection operating point",
            "",
            "Tuesday was evaluated once after thresholds were frozen. All operating points "
            "use the same test probability stream.",
            "",
            "| Target benign rejection | Threshold | Validation benign rejection | "
            "Test benign rejection | "
            "LOIC-HTTP unknown recall | Unknown precision | Unknown F1 | Balanced accuracy |",
            "|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for point in result["sensitivity"]:
        lines.append(
            f"| {point['target_benign_rejection']} | {point['threshold']:.12g} | "
            f"{point['validation_benign_rejection']:.6%} | "
            f"{point['test_benign_rejection']:.6%} | "
            f"{point['loic_http_unknown_recall']:.6%} | "
            f"{point['unknown_precision']:.6%} | {point['unknown_f1']:.6f} | "
            f"{point['balanced_accuracy']:.6f} |"
        )
    e2a = result["comparisons"]["stage5e2a_context"]
    e2b = result["comparisons"]["stage5e2b_context"]
    lines.extend(
        [
            "",
            "## Context against frozen baselines",
            "",
            "Stage 5E.2A is a closed-set RF with no UNKNOWN/reject class; consequently every "
            "LOIC-HTTP flow received a known-class prediction. It assigned "
            f"{e2a['loic_http_assigned_to_benign_count']:,} of "
            f"{e2a['loic_http_test_flows']:,} flows "
            f"({e2a['loic_http_assigned_to_benign_rate']:.4%}) to Benign.",
            "",
            "Stage 5E.2B is the benign-only Isolation Forest. At its primary 1% validation "
            f"operating point, LOIC-HTTP unknown recall was "
            f"{e2b['primary_loic_http_unknown_recall']:.6%}.",
            "",
            "These are contextual comparisons of the targeted unknown-rejection behavior, "
            "not directly comparable accuracy models. No superiority is assumed or claimed.",
            "",
            "## Timing and reproducibility",
            "",
            f"- Training: {result['training_seconds']:.3f} seconds.",
            f"- Validation inference (`predict_proba` only): "
            f"{result['validation_inference_seconds_predict_proba_only']:.3f} seconds.",
            f"- Tuesday inference (`predict_proba` only): "
            f"{result['test_inference_seconds_predict_proba_only']:.3f} seconds; "
            f"{result['test_inference_seconds_per_row']:.9f} seconds per test row.",
            f"- Peak process RSS: {result['peak_process_rss_bytes']:,} bytes.",
            f"- Seed: {result['reproducibility']['seed']}; environment versions and source "
            "hashes are recorded in the companion JSON.",
            "",
            "## Limitations",
            "",
            "This evaluates one confidence-based rejection mechanism on one CSE-CIC-IDS2018 "
            "unseen source/class condition. Confidence can be high for unseen behavior; "
            "these results do not establish general unseen-attack detection. The within-source "
            "validation partition calibrates a benign rejection rate and is not a separate "
            "source-generalization test.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    integrity, manifest = load_manifests(root)
    preflight_report = verify_stage_preflight(root, integrity, manifest)
    print("Stage 5E.2C preflight passed:")
    print(json.dumps(preflight_report, indent=2))
    if args.preflight_only:
        return 0
    result = run_experiment(root, integrity, manifest)
    result["comparisons"]["stage5e2a_context"] = load_stage5e2a_context(root)
    result["comparisons"]["stage5e2b_context"] = load_stage5e2b_context(root)
    result["reproducibility"]["software"] = {
        "python": platform.python_version(),
        "numpy": numpy.__version__,
        "scikit_learn": sklearn.__version__,
        "platform": platform.platform(),
    }
    json_path = root / "experiments/stage5e/cse-unseen-loic-http-rf-open-set.json"
    markdown_path = root / "docs/research/dataset-audit/stage5e2c-rf-open-set.md"
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    markdown_path.write_text(_markdown(result), encoding="utf-8")
    print(f"Wrote {json_path.relative_to(root)} and {markdown_path.relative_to(root)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
