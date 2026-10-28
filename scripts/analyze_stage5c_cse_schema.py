# ruff: noqa: E501  # Long report prose is emitted as Markdown paragraphs/table cells.
"""Generate a read-only Stage 5C CSE-CIC-IDS2018 schema comparison."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from textwrap import fill
from typing import Any

from ml.datasets.schema_compatibility import common_schema_assessment, compare_schema

ROOT = Path(__file__).resolve().parents[1]
DATASET_NAME = "CSE-CIC-IDS2018"
FEB20 = "Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv"
SUSPICIOUS_HEADER_ROWS = {
    "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv": 1,
    "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv": 25,
    "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv": 33,
}
LEAKAGE_EXCLUSIONS = {
    "Flow ID",
    "Src IP",
    "Src Port",
    "Dst IP",
    "Dst Port",
    "Timestamp",
    "Label",
}


def _normalized_header(path: Path) -> list[str]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        return next(csv.reader(stream), [])


def _build_report(root: Path, audit_path: Path) -> dict[str, Any]:
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    dataset = next(item for item in audit["datasets"] if item["name"] == DATASET_NAME)
    inventory = {entry["path"]: entry for entry in dataset["inventory"]}
    files: list[dict[str, Any]] = []
    for source in dataset["files"]:
        path = source["path"]
        local_path = root / path
        audit_header = [column["name"] for column in source["columns"]]
        raw_header = _normalized_header(local_path)
        raw_header = [name.strip().lstrip("\ufeff") for name in raw_header]
        labels = {
            column["name"]: column.get("label_counts", {})
            for column in source["columns"]
            if column.get("label_counts") is not None
        }
        timestamp_columns = [
            {
                "name": column["name"],
                "inferred_type": column["inferred_type"],
                "min": column["time_min"],
                "max": column["time_max"],
            }
            for column in source["columns"]
            if "time" in column["name"].casefold() or "date" in column["name"].casefold()
        ]
        file_name = Path(path).name
        files.append(
            {
                "path": path,
                "size_bytes": inventory[path]["size_bytes"],
                "sha256": inventory[path]["sha256"],
                "rows": source["rows"],
                "column_count": source["column_count"],
                "ordered_columns": audit_header,
                "columns": source["columns"],
                "normalized_column_names": [_normalize(name) for name in audit_header],
                "normalized_column_name_set": sorted({_normalize(name) for name in audit_header}),
                "raw_header_matches_stage5a": raw_header == audit_header,
                "inferred_types": {
                    column["name"]: column["inferred_type"] for column in source["columns"]
                },
                "label_columns": source["label_columns"],
                "label_counts": labels,
                "missing_cell_count": sum(column["missing"] for column in source["columns"]),
                "nonfinite_cell_count": sum(column["nonfinite"] for column in source["columns"]),
                "missing_by_column": {
                    column["name"]: column["missing"]
                    for column in source["columns"]
                    if column["missing"]
                },
                "nonfinite_by_column": {
                    column["name"]: column["nonfinite"]
                    for column in source["columns"]
                    if column["nonfinite"]
                },
                "duplicate_rows_within_file": source.get("duplicate_rows_beyond_first"),
                "timestamp_columns": timestamp_columns,
                "identifier_like_columns": source["identifier_like_columns"],
                "repeated_header_rows": source.get("repeated_header_rows", 0),
                "label_suspicious_header_value_count": labels.get("Label", {}).get("Label", 0),
                "schema_profile": (
                    "feb20-84"
                    if file_name == FEB20
                    else "standard-80-with-repeated-header-data"
                    if file_name in SUSPICIOUS_HEADER_ROWS
                    else "standard-80"
                ),
            }
        )

    feb_file = next(file for file in files if Path(file["path"]).name == FEB20)
    comparisons = [
        compare_schema(other, feb_file) for other in files if other["path"] != feb_file["path"]
    ]
    intersection = common_schema_assessment(files, excluded_from_features=LEAKAGE_EXCLUSIONS)
    standard_names = next(
        file["ordered_columns"] for file in files if file["schema_profile"] == "standard-80"
    )
    feb_names = feb_file["ordered_columns"]
    standard_only = [name for name in standard_names if name not in set(feb_names)]
    feb_only = [name for name in feb_names if name not in set(standard_names)]
    row_by_name = {Path(file["path"]).name: file for file in files}
    label_sets = {
        name: set(row["Label"])
        for name, row in ((Path(item["path"]).name, item["label_counts"]) for item in files)
    }
    label_counts_by_file = {
        name: row["Label"]
        for name, row in ((Path(item["path"]).name, item["label_counts"]) for item in files)
    }
    candidates: list[dict[str, Any]] = []
    for held_out in (
        "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv",
        "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv",
    ):
        training_files = [
            name for name in row_by_name if name != held_out and name not in SUSPICIOUS_HEADER_ROWS
        ]
        train_labels = set().union(*(label_sets[name] for name in training_files))
        test_labels = label_sets[held_out]
        training_counts: dict[str, int] = {}
        for training_file in training_files:
            for label, count in label_counts_by_file[training_file].items():
                training_counts[label] = training_counts.get(label, 0) + count
        candidates.append(
            {
                "id": f"known-class-holdout-{held_out.split('_')[0].lower()}",
                "training_files": training_files,
                "held_out_file": held_out,
                "excluded_from_candidate_training_due_to_header_rows": sorted(
                    SUSPICIOUS_HEADER_ROWS
                ),
                "class_labels_in_held_out": sorted(test_labels),
                "held_out_label_counts": label_counts_by_file[held_out],
                "held_out_labels_missing_from_training": sorted(test_labels - train_labels),
                "training_label_counts": dict(sorted(training_counts.items())),
                "known_class_support_check_passes": not (test_labels - train_labels),
                "twenty_feb_in_training": FEB20 in training_files,
                "common_schema_projection_required": True,
                "feature_exclusions": sorted(LEAKAGE_EXCLUSIONS),
                "status": "candidate; requires explicit decision on header-row contamination and nonfinite values",
            }
        )

    unseen_candidates = []
    for held_out in row_by_name:
        train_labels = set().union(
            *(labels for name, labels in label_sets.items() if name != held_out)
        )
        unseen = sorted(label_sets[held_out] - train_labels)
        if unseen:
            unseen_candidates.append(
                {
                    "held_out_file": held_out,
                    "held_out_labels_missing_from_other_files": unseen,
                    "held_out_label_counts": label_counts_by_file[held_out],
                    "experiment_type": "separate unseen-class/source condition; not known-class evaluation",
                }
            )

    return {
        "stage": "5C",
        "dataset": DATASET_NAME,
        "source_audit": "docs/research/dataset-audit/stage5a-dataset-audit.json (read-only)",
        "raw_policy": "read-only; only each file's first CSV record was reopened to verify its header",
        "normalization_rule": "Unicode NFKC, case-fold, trim, replace each run of non-ASCII-alphanumeric characters with underscore; comparison only, never a rewrite",
        "file_count": len(files),
        "files": files,
        "february_20_file": feb_file["path"],
        "february_20_ordered_columns": feb_names,
        "standard_80_ordered_columns": standard_names,
        "columns_only_in_february_20": feb_only,
        "columns_missing_from_february_20": standard_only,
        "february_20_vs_every_other_file": comparisons,
        "all_file_common_schema_assessment": intersection,
        "header_data_quality_observation": {
            "files_with_exact_repeated_header_rows": SUSPICIOUS_HEADER_ROWS,
            "sum_repeated_header_rows": sum(SUSPICIOUS_HEADER_ROWS.values()),
            "interpretation": "These raw data rows reproduce the header, causing mixed inferred types across 78 shared non-label/non-timestamp columns and the pseudo-label value Label. They are a data-row formatting/artifact issue, not evidence that those features have different semantic types.",
            "policy": "No rows or columns were removed or changed in this analysis. Any future exclusion requires a declared, countable data-quality rule.",
        },
        "cross_file_duplicate_context": dataset["duplicates"]["cross_file"],
        "candidate_known_class_source_holdouts": candidates,
        "separate_unseen_class_source_candidates": unseen_candidates,
        "semantic_assessment": {
            "structural_finding": "The February 20 file contains the same ordered 80 columns as the other files plus four prepended identifier fields; no standard column is absent.",
            "meaning_finding": "The shared CICFlowMeter feature names/order strongly support a structural mapping, but Stage 5A acquisition records contain no extractor/version metadata proving identical units or generation settings. Treat semantic equivalence as provisional pending provenance confirmation.",
            "label_finding": "All files use Label with traffic-category strings; label vocabularies are capture-specific. Similar spellings/capitalization are preserved and must not be normalized without a written label map.",
            "formal_decision": "Do not force a formal all-ten-file model schema yet. A provisional 80-column common projection is structurally defined; type/data quality review and CICFlowMeter provenance confirmation remain gates.",
        },
    }


def _normalize(name: str) -> str:
    from ml.datasets.schema_compatibility import normalize_column_name

    return normalize_column_name(name)


def _render_markdown(report: dict[str, Any]) -> str:
    files = report["files"]
    standard = report["standard_80_ordered_columns"]
    feb = report["february_20_ordered_columns"]
    lines = [
        "# Stage 5C CSE-CIC-IDS2018 Schema Analysis",
        "",
        "This is a read-only schema/protocol analysis. It uses the immutable Stage 5A audit for streaming per-cell facts and re-opened only each raw CSV's first record to verify its header. It does not fit preprocessing, impute values, merge files, or train models.",
        "",
        "## Summary decision",
        "",
        "- The 20-February file has 84 columns: the same ordered 80-column standard schema plus four identifier fields prepended. No standard column is missing from it.",
        "- Its shared-column inferred types match the standard-schema files without repeated header rows. Three other files have 78 shared fields inferred as `mixed` because exact repeated header rows occur within the data; this is a data-row artifact, not a 20-February semantic type difference.",
        "- A structural 80-column intersection exists. A scientifically validated all-ten-file feature schema remains **provisional**, pending repeated-header and non-finite value policies and confirmation that the files use compatible CICFlowMeter versions/settings.",
        "- 20-February is safe to include only conditionally: project explicitly onto the shared 80 columns, exclude identifier/time fields, and define handling for its 118,906 non-finite cells. It cannot serve as a known-class held-out file because `DDoS attacks-LOIC-HTTP` occurs only there.",
        "",
        "## Per-file audit",
        "",
        "Exact ordered headers and normalized name sets are stored per file in the JSON. `standard-80` and `feb20-84` schema definitions below provide readable cross-references; `standard-80-with-repeated-header-data` has the exact standard header but inferred types affected by repeated header rows.",
        "",
        "| Source file | Rows | Columns/schema | Labels | Missing / non-finite | Duplicate rows | Repeated header rows | Timestamp range | Identifier-like columns | Raw header matches audit |",
        "| --- | ---: | --- | --- | ---: | ---: | ---: | --- | --- | --- |",
    ]
    for file in files:
        labels = "; ".join(
            f"{name}: {', '.join(values)}"
            for name, counts in file["label_counts"].items()
            for values in [list(counts)]
        )
        timestamp = (
            "; ".join(
                f"{item['name']} {item['min']} … {item['max']}"
                for item in file["timestamp_columns"]
            )
            or "none"
        )
        identifiers = ", ".join(file["identifier_like_columns"]) or "none"
        lines.append(
            f"| `{Path(file['path']).name}` | {file['rows']:,} | {file['column_count']} / `{file['schema_profile']}` | {labels} | {file['missing_cell_count']:,} / {file['nonfinite_cell_count']:,} | {file['duplicate_rows_within_file']:,} | {file['repeated_header_rows']} | {timestamp} | {identifiers} | {file['raw_header_matches_stage5a']} |"
        )
    lines += [
        "",
        "### Standard 80-column ordered schema",
        "",
        "```text",
        ", ".join(standard),
        "```",
        "",
        "### 20-February 84-column ordered schema",
        "",
        "```text",
        ", ".join(feb),
        "```",
        "",
        "### Normalized schema set",
        "",
        "Normalization: Unicode NFKC, case-fold, trim, then replace punctuation/whitespace runs with `_`. This is used for equality diagnostics only; raw headers are unchanged.",
        "",
        "```text",
        ", ".join(files[0]["normalized_column_name_set"]),
        "```",
        "",
        "The 20-February normalized set is this common set plus `flow_id`, `src_ip`, `src_port`, and `dst_ip`.",
        "",
        "## Explicit 20-February comparisons",
        "",
        "| Compared file | Only in 20-Feb | Missing from 20-Feb | Same-name inferred type mismatches | Label columns/vocabulary |",
        "| --- | --- | --- | ---: | --- |",
    ]
    for comparison in report["february_20_vs_every_other_file"]:
        other = Path(comparison["reference_path"]).name
        only = ", ".join(comparison["columns_only_in_candidate"]) or "none"
        missing = ", ".join(comparison["columns_missing_from_candidate"]) or "none"
        labels = (
            "same Label column; vocabulary differs by source"
            if comparison["label_vocabulary_difference"]
            else "same"
        )
        lines.append(
            f"| `{other}` | {only} | {missing} | {len(comparison['same_name_type_mismatches'])} | {labels} |"
        )
    lines += [
        "",
        "The JSON contains the exact per-column mismatch maps for all nine comparisons. For the standard-schema files without repeated headers there are no shared-name type mismatches. For Friday 16-February, Thursday 1-March, and Wednesday 28-February, the mismatch count is 78 each: these shared columns are inferred `mixed` against 20-February's numeric types. Timestamp and Label remain string/category. The repeated-header observation explains this apparent difference.",
        "",
        "### February 20 difference interpretation",
        "",
        "- **Only in 20-February:** `Flow ID`, `Src IP`, `Src Port`, `Dst IP`.",
        "- **Missing from 20-February:** none of the standard 80 columns.",
        "- **Ordering:** the four extra fields are prepended; all shared names retain the standard relative order.",
        "- **Semantics:** the four extra fields are flow/endpoint identifiers. Their addition is semantic schema enrichment, not a spelling-only formatting variation. Their exclusion from a common model projection would be explicit.",
        "- **Common-column types:** no type mismatch against six standard files without repeated headers; 78 apparent mixed-type mismatches against each of the three repeated-header files. No conversion is proposed here.",
        "- **Label:** all use `Label`, but per-file class sets differ. The 20-February-only label `DDoS attacks-LOIC-HTTP` makes that source unsuitable as known-class test against all other files.",
        "- **Other suspicious content:** Friday 16-February has one exact repeated header row, Thursday 1-March has 25, Wednesday 28-February has 33. Stage 5A also observed non-finite values in `Flow Byts/s` and `Flow Pkts/s` (including 59,453 each on 20-February). Timestamp ranges on Wednesday 14-February and Thursday 22-February include values in 1970 and require review before temporal use. No data were changed.",
        "",
        "## Candidate common schemas",
        "",
        "### Structural 80-column intersection",
        "",
        fill(
            "All ten files contain the same exact 80 standard header names in the same relative order. The 20-February file adds four prepended identifier columns. This establishes a structural intersection, not by itself semantic equivalence of units/extractor settings. A future common projection can retain the 80 shared columns, with an explicit feature policy that excludes Label and leakage-prone identifiers/time fields. The JSON records the full candidate feature list and inferred type per source.",
            width=96,
        ),
        "",
        "### Candidate model feature projection (not applied)",
        "",
        "A conservative later experiment could use the shared CICFlowMeter columns after explicitly excluding `Label`, `Timestamp`, `Dst Port`, and, for 20-February, `Flow ID`, `Src IP`, `Src Port`, and `Dst IP`. `Dst Port` is flagged identifier-like by Stage 5A and is excluded conservatively here; a later protocol may retain it only with a documented justification. `Protocol` and aggregate flow statistics remain candidates. This proposal does not assert final semantic compatibility.",
        "",
        "## Source-file holdout protocol candidates",
        "",
        "All source files remain indivisible groups. Candidate training groups avoid the three files with detected repeated-header rows. These are **protocol candidates**, not executed experiments; other non-finite values remain and require a declared handling policy:",
        "",
        "| Candidate | Training files | Held-out file | Held-out labels with training support | Status |",
        "| --- | --- | --- | --- | --- |",
    ]
    for candidate in report["candidate_known_class_source_holdouts"]:
        training = ", ".join(Path(name).name for name in candidate["training_files"])
        support = (
            "all"
            if candidate["known_class_support_check_passes"]
            else str(candidate["held_out_labels_missing_from_training"])
        )
        lines.append(
            f"| `{candidate['id']}` | {training} | {Path(candidate['held_out_file']).name} | {support} | Candidate; explicit data-quality decisions required |"
        )
    lines += [
        "",
        "In these candidates, the 20-February file is a training source and requires an explicit 80-column projection. The `Brute Force -Web`, `Brute Force -XSS`, and `SQL Injection` labels are present in both Friday 23-February and Thursday 22-February, so the support check passes for either held-out file. The candidates omit all three files involved in Stage 5A's sole shared exact-row signature. Non-finite flow-rate values still require a predeclared policy; do not train until approved.",
        "",
        "### Separate unseen-class/source conditions",
        "",
    ]
    for item in report["separate_unseen_class_source_candidates"]:
        lines.append(
            f"- Hold out `{Path(item['held_out_file']).name}`: labels absent from all other source files: {', '.join(item['held_out_labels_missing_from_other_files']) or 'none'}; treat as a separate unseen-class/source condition, not known-class classification."
        )
    lines += [
        "",
        "## Decision and blockers",
        "",
        "The 20-February file may be included in a future known-class source-holdout training set under an explicit common-schema projection, but it is not a valid known-class held-out source for its unique LOIC-HTTP label. It is not yet approved as model input because the four extra identifier fields need exclusion, shared feature semantics lack extractor provenance confirmation, and non-finite values require a declared policy.",
        "",
        "Before training, resolve: (1) repeated-header row treatment for the three affected source files; (2) non-finite `Flow Byts/s`/`Flow Pkts/s` handling without changing raw files; (3) CICFlowMeter provenance/unit compatibility; (4) final identifier/time feature exclusions; and (5) whether the experiment is known-class holdout or unseen-class/source evaluation. No resolution was silently applied in Stage 5C.",
        "",
        "Stage 5C performs no model training and makes no detection-effectiveness claim.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument(
        "--audit-json",
        type=Path,
        default=Path("docs/research/dataset-audit/stage5a-dataset-audit.json"),
    )
    args = parser.parse_args()
    root = args.root.resolve()
    audit_path = args.audit_json if args.audit_json.is_absolute() else root / args.audit_json
    report = _build_report(root, audit_path)
    output_json = root / "experiments/stage5c/cse-schema-analysis.json"
    output_markdown = root / "docs/research/dataset-audit/stage5c-cse-schema-analysis.md"
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_markdown.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    output_markdown.write_text(_render_markdown(report), encoding="utf-8")
    print(f"JSON: {output_json}")
    print(f"Markdown: {output_markdown}")
    print(
        f"Files checked: {len(report['files'])}; 20-Feb comparisons: {len(report['february_20_vs_every_other_file'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
