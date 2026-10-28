#!/usr/bin/env python3
"""Analyze frozen Stage 5D class support and RF confusion matrices (no training)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast

from ml.evaluation.stage5e_error_analysis import analyze_holdout, compare_existing_metrics


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _format(value: float | int | None) -> str:
    if value is None:
        return "N/A"
    if isinstance(value, int):
        return f"{value:,}"
    return f"{value:.6f}"


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    source_path = root / "experiments/stage5d/cse-source-holdout-rf.json"
    source: dict[str, Any] = json.loads(source_path.read_text(encoding="utf-8"))
    if source.get("status") != "completed" or source.get("models_other_than_random_forest_trained"):
        raise ValueError("Frozen Stage 5D RF result artifact is incomplete or incompatible")
    analyses = [analyze_holdout(item) for item in source["holdouts"]]
    comparison = compare_existing_metrics(analyses)
    report = {
        "stage": "5E.1",
        "status": "derived_from_frozen_stage5d_results_no_training",
        "source_artifact": str(source_path.relative_to(root)),
        "source_sha256": _sha256(source_path),
        "models_trained": False,
        "source_results_modified": False,
        "method": {
            "source": "Stage 5D class distributions and confusion matrices",
            "class_metrics": "derived from actual-row/predicted-column confusion matrix counts",
            "training_support": "training class distribution in Stage 5D holdout artifact",
            "test_to_training_support_ratio": (
                "test support divided by training support; null if training support is zero"
            ),
            "attack_to_benign_rate": (
                "attack-class rows predicted Benign divided by that class test support"
            ),
            "benign_to_attack_rate": (
                "Benign rows predicted to each attack class divided by all Benign test rows"
            ),
            "causal_inference": False,
        },
        "holdouts": analyses,
        "existing_metric_comparison": comparison,
    }
    output_path = root / "experiments/stage5e/cse-rf-error-analysis.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    lines = [
        "# Stage 5E.1 — CSE RF error and class-support analysis",
        "",
        (
            "**Scope:** post-hoc analysis only. Both holdouts use the frozen Stage 5D "
            "Random Forest results. No model was trained, and no prior result, raw "
            "dataset, prepared dataset, protocol, or RF configuration was changed."
        ),
        "",
        (
            "Source artifact: [`cse-source-holdout-rf.json`]"
            "(../../../experiments/stage5d/cse-source-holdout-rf.json). "
            f"SHA-256: `{report['source_sha256']}`."
        ),
        "",
        "## Method and definitions",
        "",
        (
            "The confusion matrices provide aggregate class-prediction counts, so the "
            "requested class-level counts and rates are derivable. They do not preserve "
            "row-level feature values or an ordered per-flow prediction list; those are "
            "not needed for this aggregate analysis. Confusion matrix rows are actual "
            "labels and columns are predicted labels."
        ),
        "",
        (
            "`attack → benign` rate is the actual attack class's count predicted as "
            "Benign divided by that attack class's test support. For an attack class, "
            "`benign → this attack` is benign rows predicted as that class divided by "
            "all benign test rows. For the Benign row, `benign → attack` is the "
            "aggregate benign-to-any-attack count/rate. A ratio is `test support / "
            "training support`; it is N/A if training support is zero. These values are "
            "descriptive and do not imply causality."
        ),
        "",
        "## Existing holdout metrics comparison",
        "",
        (
            "The values below are copied from Stage 5D without redefining or "
            "overwriting them. Difference is Holdout B minus Holdout A."
        ),
        "",
        "| Metric | Holdout A | Holdout B | B − A |",
        "|---|---:|---:|---:|",
    ]
    pretty = {
        "accuracy": "Accuracy",
        "weighted_f1": "Weighted F1",
        "primary_test_supported_macro_f1": "Primary test-supported macro F1",
        "benign_fpr": "Benign FPR",
        "attack_fnr_as_benign": "Attack FNR as benign",
    }
    comp = cast(dict[str, Any], report["existing_metric_comparison"])
    for key, title in pretty.items():
        lines.append(
            f"| {title} | {_format(comp['holdout_A'][key])} | "
            f"{_format(comp['holdout_B'][key])} | {_format(comp['B_minus_A'][key])} |"
        )

    for holdout in analyses:
        lines += [
            "",
            f"## {holdout['holdout_id']}",
            "",
            f"Training rows: {holdout['training_rows']:,}; test rows: {holdout['test_rows']:,}.",
            "",
            (
                "| Class | Train support | Test support | Predicted support | Test/train "
                "ratio | Precision | Recall | F1 | Attack → benign (count / class "
                "rate) | Benign → attack (count / benign rate) |"
            ),
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
        for label, values in holdout["class_analysis"].items():
            if label == "Benign":
                benign_error = (
                    f"{_format(values['benign_to_attack_error_count'])} / "
                    f"{_format(values['benign_to_attack_error_rate_among_benign'])}"
                )
                attack_error = "N/A"
            else:
                attack_error = (
                    f"{_format(values['attack_to_benign_error_count'])} / "
                    f"{_format(values['attack_to_benign_error_rate_within_class'])}"
                )
                benign_error = (
                    f"{_format(values['benign_to_attack_error_count'])} / "
                    f"{_format(values['benign_to_attack_error_rate_among_benign'])}"
                )
            lines.append(
                f"| {label} | {_format(values['training_support'])} | "
                f"{_format(values['test_support'])} | {_format(values['predicted_support'])} | "
                f"{_format(values['test_to_training_support_ratio'])} | "
                f"{_format(values['precision'])} | {_format(values['recall'])} | "
                f"{_format(values['f1'])} | {attack_error} | {benign_error} |"
            )
        lines += [
            "",
            "### Confusion matrix",
            "",
            "| Actual \\ Predicted | " + " | ".join(holdout["confusion_matrix"]["labels"]) + " |",
            "|---|" + "---:|" * len(holdout["confusion_matrix"]["labels"]),
        ]
        for label, row in zip(
            holdout["confusion_matrix"]["labels"],
            holdout["confusion_matrix"]["counts_actual_rows_predicted_columns"],
            strict=True,
        ):
            lines.append("| " + label + " | " + " | ".join(f"{count:,}" for count in row) + " |")

    lines += [
        "",
        "## Observed support/performance association",
        "",
        (
            "The held-out classes with weak F1 are the web brute-force and SQL-injection "
            "classes in both holdouts, with XSS also weak in B. Their training supports "
            "are small relative to Benign and larger training attack classes: Web has "
            "249 (A) or 362 (B), XSS has 79 (A) or 151 (B), and SQL Injection has 34 "
            "(A) or 53 (B). Their test supports are also small: 362/249, 151/79, and "
            "53/34, respectively. The per-class table reports corresponding ratios."
        ),
        "",
        (
            "This is an observed association between weak minority-class scores and "
            "small absolute training and test supports in these two reciprocal files. "
            "It does not establish that support caused the errors. Test support affects "
            "score uncertainty and resolution; training support is not experimentally "
            "varied independently here."
        ),
        "",
        (
            "Benign scores remain high, while a portion of attack traffic is predicted "
            "as Benign (the Stage 5D attack FNR-as-benign is 0.409894 in A and 0.138122 "
            "in B). Benign-to-attack errors differ by predicted attack class and are "
            "detailed above. Aggregate accuracy and weighted F1 remain high because "
            "Benign dominates test support; test-supported macro F1 is much lower."
        ),
        "",
        "## Limits and next step",
        "",
        (
            "Only confusion matrices and class-level supports were available in Stage "
            "5D. This supports class-level error analysis, but not per-flow error "
            "inspection, confidence analysis, feature attribution, threshold sweeps, "
            "or identifying individual misclassified records."
        ),
        "",
        (
            "Recommended Stage 5E.2: if finer-grained diagnosis is needed, preserve "
            "prediction-level records from a separately authorized evaluation run "
            "(source ID, true label, predicted label, and model score), while keeping "
            "the existing Stage 5D results frozen. Do not retrain or alter Stage 5D "
            "to retrofit this analysis."
        ),
        "",
        (
            "Machine-readable analysis: [`cse-rf-error-analysis.json`]"
            "(../../../experiments/stage5e/cse-rf-error-analysis.json)."
        ),
        "",
    ]
    doc_path = root / "docs/research/dataset-audit/stage5e-rf-error-analysis.md"
    doc_path.parent.mkdir(parents=True, exist_ok=True)
    doc_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {output_path.relative_to(root)} and {doc_path.relative_to(root)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
