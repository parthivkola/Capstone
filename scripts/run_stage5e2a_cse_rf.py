"""Run the Stage 5E.2A Tuesday-held-out closed-set CSE RF experiment."""

from __future__ import annotations

import argparse
import json
import platform
from pathlib import Path
from typing import Any, cast

import numpy
import sklearn

from ml.evaluation.stage5d_cse import preflight
from ml.evaluation.stage5e2a_cse import run_experiment, verify_preflight_for_experiment


def _markdown(result: dict[str, Any], stage5d: dict[str, Any]) -> str:
    metrics = result["metrics"]
    unseen = result["unseen_label"]
    lines = [
        "# Stage 5E.2A — CSE Tuesday-20-02 closed-set RF baseline",
        "",
        "**Condition:** closed-set unseen-class/source baseline. This is not novelty detection.",
        "",
        "## Preflight and split",
        "",
        "- Stage 5D artifact preflight: "
        f"**{'passed' if result['preflight']['passed'] else 'failed'}**.",
        f"- Training sources: {', '.join(result['preflight']['training_sources'])}.",
        f"- Test source: `{result['preflight']['test_source']}`.",
        f"- Source-disjoint: **{result['preflight']['sources_disjoint']}**.",
        f"- Rows: {result['training_rows']:,} train; {result['test_rows']:,} test.",
        f"- Predictors: {result['feature_count']} frozen Stage 5D features.",
        f"- Training label vocabulary ({len(result['training_class_vocabulary'])}): "
        + ", ".join(f"`{label}`" for label in result["training_class_vocabulary"])
        + ".",
        f"- `{unseen['label']}` absent from training: "
        f"**{unseen['absent_from_training_vocabulary']}**; "
        f"test support: **{unseen['test_flows']:,}**.",
        "",
        "## Frozen RF configuration",
        "",
        "```json",
        json.dumps(result["model"], indent=2),
        "```",
        "",
        "Feature handling uses the frozen Stage 5D numeric CSV-to-float32 cast, "
        "with no fitted preprocessing. Label codes come from training-source labels only. "
        "Tuesday rows are read in chunks for inference; test labels are used only for evaluation. "
        "No threshold or hyperparameter was selected on Tuesday.",
        "",
        "## Metrics",
        "",
        f"Macro F1 is averaged over the **{metrics['macro_f1_denominator_class_count']} "
        "distinct labels present in the test source**, including LOIC-HTTP. The unseen class "
        "receives F1 0 because no output class can represent it.",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Accuracy | {metrics['accuracy']:.6f} |",
        f"| Macro F1 (test-supported classes) | {metrics['macro_f1']:.6f} |",
        f"| Weighted F1 | {metrics['weighted_f1']:.6f} |",
        f"| Benign FPR | {metrics['benign_fpr']:.6f} |",
        f"| Attack FNR as Benign | {metrics['attack_fnr_as_benign']:.6f} |",
        "",
        "### Per-test-class metrics",
        "",
        "| Test class | Support | Predicted support | Precision | Recall | F1 |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for label, item in metrics["per_class"].items():
        lines.append(
            f"| {label} | {item['test_support']:,} | {item['predicted_support']:,} | "
            f"{item['precision']:.6f} | {item['recall']:.6f} | {item['f1']:.6f} |"
        )
    lines.extend(
        [
            "",
            "### LOIC-HTTP assignment to known classes",
            "",
            "The classifier has no unknown/reject output. Every test LOIC-HTTP flow is "
            "therefore assigned to a known training class.",
            "",
            "| Predicted known class | Count | Rate among LOIC-HTTP test flows |",
            "|---|---:|---:|",
        ]
    )
    for label, count in unseen["predicted_class_distribution"].items():
        lines.append(
            f"| {label} | {count:,} | {unseen['predicted_distribution_rates'][label]:.6f} |"
        )
    lines.extend(
        [
            "",
            "## Confusion matrix",
            "",
            "Rows are actual labels; columns are predicted labels. The test-only LOIC-HTTP "
            "column is zero because it is not in the model vocabulary.",
            "",
            "| Actual \\ Predicted | " + " | ".join(metrics["confusion_matrix_labels"]) + " |",
            "|---|" + "---:|" * len(metrics["confusion_matrix_labels"]),
        ]
    )
    for label, row in zip(
        metrics["confusion_matrix_labels"],
        metrics["confusion_matrix_actual_rows_predicted_columns"],
        strict=True,
    ):
        lines.append(f"| {label} | " + " | ".join(f"{value:,}" for value in row) + " |")
    lines.extend(
        [
            "",
            "## Timing and memory",
            "",
            f"- Training: {result['training_seconds']:.3f} seconds.",
            f"- Inference (`predict` calls only): "
            f"{result['inference_seconds_total_predict_calls_only']:.3f} seconds total; "
            f"{result['inference_seconds_per_test_flow']:.9f} seconds per test flow.",
            f"- Peak process RSS: {result['peak_process_rss_bytes']:,} bytes. "
            + result["peak_memory_measurement"]
            + ".",
            "",
            "## Context against frozen Stage 5D",
            "",
            "The Stage 5D A/B metrics are separate context only. They test known classes "
            "on different held-out sources, while this run holds out a source containing a "
            "class absent from training. They are not a direct performance comparison; "
            "no causal interpretation is made.",
            "",
            "| Frozen Stage 5D run | Accuracy | Test-supported macro F1 | Weighted F1 |",
            "|---|---:|---:|---:|",
        ]
    )
    for holdout in stage5d["holdouts"]:
        m = holdout["metrics"]
        lines.append(
            f"| {holdout['holdout_id']} (separate known-class protocol) | {m['accuracy']:.6f} | "
            f"{m['macro_f1_test_supported_classes']:.6f} | {m['weighted_f1']:.6f} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation limits",
            "",
            "This result measures how the frozen closed-set Random Forest assigns a "
            "source-held-out, training-unsupported class among known outputs. It does not "
            "measure novelty detection, unknown rejection, security effectiveness, or "
            "causal effects of training support.",
            "",
            "## Reproducibility",
            "",
            f"Python {result['software']['python']}; NumPy {result['software']['numpy']}; "
            f"scikit-learn {result['software']['scikit_learn']}. Prepared artifact SHA-256 "
            "values and the full configuration are recorded in the companion JSON.",
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
    prepared = root / "experiments/stage5d/cse-preparation.json"
    with prepared.open(encoding="utf-8") as stream:
        manifest = cast(dict[str, Any], json.load(stream))
    preflight_result = preflight(root)
    checked = verify_preflight_for_experiment(
        preflight_result, [item["file"] for item in manifest["source_statistics"]]
    )
    print("Stage 5E.2A preflight passed:")
    print(json.dumps(checked, indent=2))
    if args.preflight_only:
        return 0
    result = run_experiment(root, preflight_result)
    result["software"] = {
        "python": platform.python_version(),
        "numpy": numpy.__version__,
        "scikit_learn": sklearn.__version__,
        "platform": platform.platform(),
    }
    result["prepared_artifacts"] = [
        {
            "source_file": item["file"],
            "path": item["output_path"],
            "sha256": item["output_sha256"],
        }
        for item in manifest["source_statistics"]
    ]
    output_json = root / "experiments/stage5e/cse-unseen-loic-http-closed-set-rf.json"
    output_md = root / "docs/research/dataset-audit/stage5e2a-closed-set-unseen-class.md"
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    with (root / "experiments/stage5d/cse-source-holdout-rf.json").open(encoding="utf-8") as stream:
        stage5d = cast(dict[str, Any], json.load(stream))
    output_md.write_text(_markdown(result, stage5d), encoding="utf-8")
    print(f"Wrote {output_json.relative_to(root)} and {output_md.relative_to(root)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
