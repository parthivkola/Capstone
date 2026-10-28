"""Run the validation-calibrated Stage 5E.2B CSE Isolation Forest experiment."""

from __future__ import annotations

import argparse
import json
import platform
from pathlib import Path
from typing import Any, cast

import numpy
import sklearn

from ml.evaluation.stage5d_cse import preflight
from ml.evaluation.stage5e2b_novelty import run_experiment, stage5e2a_context, verify_preflight


def _markdown(result: dict[str, Any], context: dict[str, Any]) -> str:
    primary = result["primary_metrics"]
    lines = [
        "# Stage 5E.2B — explicit novelty detection for CSE LOIC-HTTP",
        "",
        "**Status:** validation-calibrated Isolation Forest; Tuesday-20-02 is the test source.",
        "",
        "## Preflight and data partitions",
        "",
        "- Frozen prepared-data integrity preflight: passed before model fitting.",
        "- Training/validation sources: six non-Tuesday prepared CSE files, each with "
        "deterministic per-source benign row partitioning.",
        f"- Model-fit rows: {result['train_rows']:,} benign flows.",
        f"- Threshold-validation rows: {result['validation_rows']:,} benign flows.",
        f"- Tuesday test rows: {result['test_rows']:,} flows.",
        "- Tuesday excluded from fit and threshold selection: "
        f"{result['preflight']['test_source_excluded_from_model_fit_and_threshold_selection']}.",
        f"- LOIC-HTTP used in fit: {result['loic_http_used_in_fit']}.",
        f"- Frozen predictors: {result['feature_schema']['count']} ordered float32 features.",
        "",
        "The validation partition is a seeded exact 20% sample of benign row ordinals "
        "without replacement within each source file. The remaining benign rows from those "
        "same six sources fit the detector. Attack rows are ignored; their labels are not "
        "supplied to `IsolationForest.fit`. Tuesday remains untouched until final scoring.",
        "",
        "## Isolation Forest configuration",
        "",
        "```json",
        json.dumps(result["model"], indent=2),
        "```",
        "",
        "The configuration follows the project's existing Isolation Forest baseline (100 trees, "
        "contamination `auto`, seed 2026, one job); `max_samples=256` states the existing "
        "sklearn `auto` sample count explicitly for this dataset size. `contamination=auto` "
        "does not set the final decision threshold. The runner uses `score_samples` and its "
        "own validation-selected cutpoints.",
        "",
        "### Score orientation and threshold selection",
        "",
        "`IsolationForest.score_samples` is lower for more anomalous records. The novelty "
        "score is its negation, so higher scores mean more novel behavior. The decision is "
        "`novelty_score >= threshold → UNKNOWN`; otherwise the flow is KNOWN.",
        "",
        "Thresholds are selected only from benign validation novelty scores. For each "
        "predeclared target, the runner chooses the attainable score-group boundary nearest "
        "the requested rejection count; ties choose the lower realized validation FPR. Equal "
        "scores are indivisible, so the realized validation FPR can differ slightly from target.",
        "",
        "Primary pre-registered operating point: **1% benign FPR**; selected threshold: "
        f"**{result['threshold_selection']['primary']['threshold']:.12g}**. "
        "Validation benign rows: "
        f"{result['threshold_selection']['primary']['validation_benign_rows']:,}; "
        "validation unknown count: "
        f"{result['threshold_selection']['primary']['validation_benign_unknown_count']:,}; "
        "realized validation FPR: "
        f"{result['threshold_selection']['primary']['validation_benign_fpr']:.6%}.",
        "",
        "## Primary 1% operating-point results",
        "",
        f"Test benign rows: {primary['benign_test_rows']:,}; "
        f"test LOIC-HTTP rows: {primary['loic_http_test_rows']:,}.",
        "",
        "| Metric | Result |",
        "|---|---:|",
        f"| Benign FPR / rejection rate | {primary['benign_fpr']:.6%} |",
        f"| LOIC-HTTP unknown recall | {primary['loic_http_unknown_recall']:.6%} |",
        f"| Unknown precision | {primary['unknown_precision']:.6%} |",
        f"| Unknown F1 | {primary['unknown_f1']:.6f} |",
        f"| Balanced accuracy | {primary['balanced_accuracy']:.6f} |",
        "",
        "### Counts and 2×2 confusion matrix",
        "",
        f"- Benign known: {primary['benign_known_count']:,}; "
        f"benign UNKNOWN: {primary['benign_unknown_count']:,}.",
        f"- LOIC-HTTP known: {primary['loic_http_known_count']:,}; "
        f"LOIC-HTTP UNKNOWN: {primary['loic_http_unknown_count']:,}.",
        "",
        "| Actual \\ Predicted | Known | Unknown |",
        "|---|---:|---:|",
        f"| Benign | {primary['confusion_matrix'][0][0]:,} | "
        f"{primary['confusion_matrix'][0][1]:,} |",
        f"| LOIC-HTTP | {primary['confusion_matrix'][1][0]:,} | "
        f"{primary['confusion_matrix'][1][1]:,} |",
        "",
        "## Operating-point sensitivity",
        "",
        "Each threshold below was independently selected on the same benign validation "
        "partition. Tuesday was scored once, and all operating points used the same scores.",
        "",
        "| Target validation benign FPR | Threshold | Validation FPR | Test benign FPR | "
        "LOIC unknown recall | Unknown precision | Unknown F1 | Balanced accuracy |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for point in result["sensitivity"]:
        lines.append(
            f"| {point['operating_point']} | {point['threshold']:.12g} | "
            f"{point['validation_benign_fpr']:.6%} | {point['test_benign_fpr']:.6%} | "
            f"{point['loic_http_unknown_recall']:.6%} | {point['unknown_precision']:.6%} | "
            f"{point['unknown_f1']:.6f} | {point['balanced_accuracy']:.6f} |"
        )
    lines.extend(
        [
            "",
            "## Context against Stage 5E.2A",
            "",
            "Stage 5E.2A is a closed-set classifier with no unknown/reject class. Therefore "
            "every LOIC-HTTP flow necessarily received a known-class prediction. Stage 5E.2B "
            "adds an explicit UNKNOWN decision. These are not directly comparable accuracy "
            "models; this report uses 5E.2A only as context and makes no superiority claim.",
            "",
            f"Stage 5E.2A assigned all {context['stage5e2a_loic_test_flows']:,} "
            "LOIC-HTTP test flows to known classes; its known prediction distribution is "
            "recorded in the companion result JSON.",
            "",
            "## Reproducibility, timing, and memory",
            "",
            f"- Seed: {result['reproducibility']['random_seed']}.",
            f"- Training time: {result['training_seconds']:.3f} seconds; "
            f"validation scoring: {result['validation_scoring_seconds']:.3f} seconds.",
            "- Test inference (`score_samples` calls only): "
            f"{result['inference_seconds_total_score_samples_only']:.3f} seconds total; "
            f"{result['inference_seconds_per_test_row']:.9f} seconds per row.",
            f"- Peak process RSS: {result['peak_process_rss_bytes']:,} bytes; "
            f"{result['peak_memory_measurement']}.",
            f"- Environment: Python {result['reproducibility']['software']['python']}; "
            f"NumPy {result['reproducibility']['software']['numpy']}; "
            f"scikit-learn {result['reproducibility']['software']['scikit_learn']}.",
            "- Raw and prepared artifact hashes are in the JSON. Raw data and earlier "
            "stage artifacts were not modified.",
            "",
            "## Limitations",
            "",
            "This is one dataset/source condition with a validation-calibrated benign "
            "operating point. The per-source row partition shares each source across fitting "
            "and validation; it calibrates an FPR operating point and is not source-generalization "
            "validation. Only Tuesday is held out at source level for final evaluation. The "
            "result does not establish broad novelty-detection effectiveness or performance "
            "on other unseen attacks.",
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
    with (root / "experiments/stage5d/cse-preparation.json").open(encoding="utf-8") as stream:
        manifest = cast(dict[str, Any], json.load(stream))
    integrity = preflight(root)
    verified = verify_preflight(integrity, manifest)
    print("Stage 5E.2B preflight passed:")
    print(json.dumps(verified, indent=2))
    if args.preflight_only:
        return 0

    result = run_experiment(root, integrity, manifest)
    result["reproducibility"]["software"] = {
        "python": platform.python_version(),
        "numpy": numpy.__version__,
        "scikit_learn": sklearn.__version__,
        "platform": platform.platform(),
    }
    context = stage5e2a_context(
        root / "experiments/stage5e/cse-unseen-loic-http-closed-set-rf.json"
    )
    result["stage5e2a_context"] = context
    output_json = root / "experiments/stage5e/cse-unseen-loic-http-isolation-forest.json"
    output_markdown = root / "docs/research/dataset-audit/stage5e2b-novelty-detection.md"
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_markdown.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    output_markdown.write_text(_markdown(result, context), encoding="utf-8")
    print(f"Wrote {output_json.relative_to(root)} and {output_markdown.relative_to(root)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
