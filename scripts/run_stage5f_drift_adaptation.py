"""Preflight and run the frozen Stage 5F source/distribution-shift experiment."""

from __future__ import annotations

import argparse
import json
import platform
from pathlib import Path
from typing import Any

import numpy
import sklearn

from ml.evaluation.stage5f_drift_adaptation import (
    REPORT_RELATIVE_PATH,
    RESULT_RELATIVE_PATH,
    run_experiment,
    verify_preflight,
)


def _markdown(result: dict[str, Any]) -> str:
    lines = [
        "# Stage 5F — Source/Distribution-Shift Adaptation Results",
        "",
        "**Study condition: SOURCE/DISTRIBUTION SHIFT.** The imposed source order is "
        "not temporal. No concept-drift or temporal-drift claim is made; PSI is an "
        "input-distribution signal only.",
        "",
        f"Research question: {result['research_question']}",
        "",
        "## Integrity and configuration",
        "",
        f"- Protocol SHA-256: `{result['protocol_sha256']}`.",
        f"- Stage 5D preparation manifest SHA-256: `{result['preparation_manifest_sha256']}`.",
        "- All seven raw and prepared source hashes passed preflight; headers matched "
        "77-feature schema.",
        "- No raw or prepared source files were modified.",
        "- No Tuesday/LOIC-HTTP rows entered initial fitting; all labels map to Benign or Attack.",
        "- PSI reference/bin edges use only initial-fit data. W4 labels remain evaluation-only.",
        "",
        "## Source windows and row counts",
        "",
        "| Window | Source | Prepared rows | Benign | Attack |",
        "|---|---|---:|---:|---:|",
    ]
    source_by_name = {item["file"]: item for item in result["preflight"]["sources"]}
    for item in result["protocol_configuration"]["source_order"]["sequential_evaluation_windows"]:
        source = source_by_name[item["source_file"]]
        labels = source["class_counts"]
        benign = int(labels.get("Benign", 0))
        attack = sum(int(value) for label, value in labels.items() if label != "Benign")
        lines.append(
            f"| {item['window_id']} | `{item['source_file']}` | {source['rows']:,} | "
            f"{benign:,} | {attack:,} |"
        )
    lines.extend(["", "## Strategy results by window", ""])
    for strategy, windows in result["summary_mean_std_across_seeds"]["strategies"].items():
        lines.extend(
            [
                f"### {strategy.replace('_', ' ').title()}",
                "",
                "| Window | Macro F1 mean ± SD | Weighted F1 mean ± SD | Benign FPR mean ± SD | "
                "Attack FNR mean ± SD | Benign F1 mean ± SD | Attack F1 mean ± SD |",  # noqa: E501
                "|---|---:|---:|---:|---:|---:|---:|",
            ]
        )
        for window, metrics in windows.items():

            def fmt(name: str, row_metrics: dict[str, Any] = metrics) -> str:
                value = row_metrics[name]
                return f"{value['mean']:.6f} ± {value['std']:.6f}"

            lines.append(
                f"| {window} | {fmt('macro_f1')} | {fmt('weighted_f1')} | "
                f"{fmt('benign_fpr')} | {fmt('attack_fnr_as_benign')} | "
                f"{fmt('per_class_f1_benign')} | {fmt('per_class_f1_attack')} |"
            )
        lines.append("")
    lines.extend(
        [
            "## PSI by source window",
            "",
            "PSI ≥ 0.20 is a frozen operational feature signal; a window is flagged when at least "
            "five features signal. It is not a significance test.",
            "",
            "### Initial validation false-alarm check",
            "",
            "| Seed | Comparison rows | Signaled features | Trigger |",
            "|---:|---:|---:|---|",
        ]
    )
    for seed_run in result["seed_runs"]:
        validation_psi = seed_run["initial_validation_psi"]
        lines.append(
            f"| {seed_run['seed']} | {validation_psi['comparison_rows']} | "
            f"{validation_psi['signaled_feature_count']} | "
            f"{'yes' if validation_psi['psi_triggered'] else 'no'} |"
        )
    lines.extend(
        [
            "",
            "| Seed | Window | Signaled features | Trigger |",
            "|---:|---|---:|---|",
        ]
    )
    for seed_run in result["seed_runs"]:
        for event in seed_run["window_events"]:
            lines.append(
                f"| {seed_run['seed']} | {event['window_id']} | "
                f"{event['signaled_feature_count']} | "
                f"{'yes' if event['psi_triggered'] else 'no'} |"
            )
    lines.extend(["", "## Update, delay, and rollback events", ""])
    for strategy, summary in result["adaptation_summary"].items():
        lines.extend(
            [
                f"### {strategy.replace('_', ' ').title()}",
                "",
                f"Attempted: {summary['attempted']}; accepted: {summary['accepted']}; "
                f"rejected: {summary['rejected']}.",
                "",
                "| Seed | Boundary | Attempted | Accepted | Reason | Buffer rows | "
                "Latency seconds | Anchor macro F1 | Anchor benign FPR |",
                "|---:|---|---|---|---|---:|---:|---:|---:|",
            ]
        )
        for seed, events in summary["events_by_seed"].items():
            for event in events:
                if event.get("attempted"):
                    reason = ", ".join(event["rejection_reasons"]) or "accepted"
                    lines.append(
                        f"| {seed} | {event['window_boundary']} | yes | "
                        f"{event['accepted']} | {reason} | "
                        f"{event['buffer']['rows']:,} | "
                        f"{event['adaptation_latency']['release_to_fit_complete_seconds']:.6f} | "
                        f"{event['anchor_metrics']['macro_f1']:.6f} | "
                        f"{event['anchor_metrics']['benign_fpr']:.6f} |"
                    )
                elif event.get("window_boundary") == "W4":
                    lines.append(
                        f"| {seed} | W4 | no | — | terminal update prohibited | — | — | — | — |"
                    )
        lines.append("")
    lines.extend(
        [
            "## Paired strategy comparisons",
            "",
            "Differences are left strategy minus right strategy on identical seeds "
            "and windows. Seeds are algorithmic repeats on the same finite source "
            "files, not independent captures.",
            "",
            "| Window | Metric | Pair | Mean difference | Paired 95% t interval | Cohen dz |",
            "|---|---|---|---:|---:|---:|",
        ]
    )
    for comparison in result["summary_mean_std_across_seeds"]["paired_comparisons"]:
        ci = comparison["95_percent_paired_t_interval"]
        dz = "N/A" if comparison["cohens_dz"] is None else f"{comparison['cohens_dz']:.6f}"
        lines.append(
            f"| {comparison['window']} | {comparison['metric']} | {comparison['difference']} | "
            f"{comparison['paired_mean_difference']:.6f} | [{ci[0]:.6f}, {ci[1]:.6f}] | {dz} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation and limitations",
            "",
            "Report negative outcomes directly, including no PSI triggers, no "
            "post-update improvement, or rollbacks. Performance differences are "
            "source-specific under this imposed schedule. The source order is not "
            "chronological, source/extractor comparability is not verified, "
            "and PSI alone does not establish a change in P(Y|X).",
            "",
            "## Reproducibility",
            "",
            f"- Seeds: {', '.join(str(seed) for seed in result['protocol_configuration']['model']['seeds'])}.",  # noqa: E501
            f"- Python: {result['software']['python']}; NumPy: {result['software']['numpy']}; "
            f"scikit-learn: {result['software']['scikit_learn']}.",
            f"- Peak process RSS: {result['peak_process_rss_bytes']:,} bytes.",
            "- Input hashes, split memberships, model parameters, PSI values, buffer memberships, "
            "event records, and per-seed output are in the companion JSON.",
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
    print("Stage 5F preflight: hashing and checking frozen protocol inputs...", flush=True)
    checked = verify_preflight(root)
    print(json.dumps(checked, indent=2), flush=True)
    if args.preflight_only:
        return 0

    results = run_experiment(root, checked)
    results["software"] = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "numpy": numpy.__version__,
        "scikit_learn": sklearn.__version__,
    }
    results["peak_process_rss_bytes"] = max(
        run["resource_usage"]["peak_process_rss_bytes"] for run in results["seed_runs"]
    )
    results["runtime"] = {
        "model_configuration_by_seed": [run["model_configuration"] for run in results["seed_runs"]],
        "protocol_source_order_is_not_chronology": True,
        "raw_datasets_modified": False,
        "prepared_datasets_modified": False,
        "previous_stage_artifacts_modified": False,
    }
    output_path = root / RESULT_RELATIVE_PATH
    report_path = root / REPORT_RELATIVE_PATH
    output_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(results, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    report_path.write_text(_markdown(results), encoding="utf-8")
    print(f"Wrote {output_path.relative_to(root)} and {report_path.relative_to(root)}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
