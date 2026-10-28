"""Run the Stage 5A read-only audit on the locally acquired datasets."""

from __future__ import annotations

import argparse
import csv
import io
import json
import sqlite3
import sys
import tempfile
import zipfile
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from textwrap import fill
from typing import Any

from src.sdn_defense.dataset_audit import (
    CsvSource,
    audit_csv_stream,
    audit_path,
    duplicate_summary,
    make_hash_database,
    sha256_file,
)

DATASET_PATHS = {
    "CIC-IDS2017": "data/raw/cicids2017",
    "CSE-CIC-IDS2018": "data/raw/cse-cic-ids2018",
    "UNSW-NB15": "data/raw/unsw-nb15",
    "TON_IoT": "data/raw/ton-iot/train_test_network.csv",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="repository root")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("docs/research/dataset-audit"),
        help="directory for generated JSON and Markdown reports",
    )
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    output_dir = arguments.output_dir
    if not output_dir.is_absolute():
        output_dir = root / output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(
        prefix="stage5a-audit-", dir="/var/tmp"
    ) as temporary_directory:
        datasets = _audit_all(root, Path(temporary_directory))

    report: dict[str, Any] = {
        "audit": {
            "stage": "5A",
            "generated_at_utc": datetime.now(UTC).isoformat(timespec="seconds"),
            "tool": "scripts/run_stage5a_dataset_audit.py",
            "python_version": sys.version,
            "raw_data_policy": "read-only; no extraction, rewrite, merge, or download",
            "row_duplicate_method": (
                "SHA-256 of JSON-encoded parsed CSV cells with header/schema prefix; "
                "raw row order and cell strings are preserved after CSV parsing"
            ),
        },
        "datasets": datasets,
    }
    json_path = output_dir / "stage5a-dataset-audit.json"
    markdown_path = output_dir / "stage5a-dataset-audit.md"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n")
    markdown_path.write_text(_render_markdown(report), encoding="utf-8")
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {markdown_path}")
    for item in datasets:
        totals = item["summary"]
        print(
            f"{item['name']}: {totals['rows']} rows across "
            f"{totals['analysis_file_count']} analysis files"
        )
    return 0


def _audit_all(root: Path, temporary_directory: Path) -> list[dict[str, Any]]:
    tasks = [
        ("cic", _audit_cic),
        (
            "cse",
            lambda base, db: _audit_directory_csvs(
                base,
                db,
                "CSE-CIC-IDS2018",
                Path(DATASET_PATHS["CSE-CIC-IDS2018"]),
                "Date-named TrafficForML CSVs remain separate. The original download source "
                "is not recorded in repository metadata.",
            ),
        ),
        ("unsw", _audit_unsw),
        ("ton", _audit_ton),
    ]
    datasets: list[dict[str, Any]] = []
    for key, audit_function in tasks:
        database = make_hash_database(temporary_directory / f"{key}-row-hashes.sqlite3")
        try:
            dataset = audit_function(root, database)
            duplicate_data = duplicate_summary(database)
            dataset["duplicates"] = duplicate_data
            _set_dataset_duplicate_total(dataset, duplicate_data)
            if dataset["name"] == "UNSW-NB15":
                dataset["split_structure"]["exact_overlap"] = _unsw_split_overlap(database)
            datasets.append(dataset)
        finally:
            database.close()
    return datasets


def _inventory(root: Path, dataset_root: Path) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    if not dataset_root.exists():
        return entries
    paths = (
        [dataset_root]
        if dataset_root.is_file()
        else sorted(p for p in dataset_root.rglob("*") if p.is_file())
    )
    for path in paths:
        entries.append(
            {
                "path": path.relative_to(root).as_posix(),
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    return entries


def _audit_cic(root: Path, database: sqlite3.Connection) -> dict[str, Any]:
    relative = Path(DATASET_PATHS["CIC-IDS2017"])
    folder = root / relative
    inventory = _inventory(root, folder)
    archives = list(folder.glob("*.zip"))
    files: list[dict[str, object]] = []
    if not archives:
        return _dataset_result(
            "CIC-IDS2017",
            inventory,
            files,
            [],
            "No ZIP archive found in the acquisition directory; no extraction was attempted.",
        )
    for archive_path in archives:
        with zipfile.ZipFile(archive_path) as archive:
            for info in archive.infolist():
                if info.is_dir() or not info.filename.lower().endswith(".csv"):
                    continue
                with archive.open(info.filename) as binary_stream:
                    text_stream = io.TextIOWrapper(
                        binary_stream, encoding="utf-8-sig", errors="replace", newline=""
                    )
                    try:
                        result = audit_csv_stream(
                            text_stream,
                            display_path=f"{archive_path.relative_to(root).as_posix()}::{info.filename}",
                            row_hash_sink=database,
                        )
                    except (csv.Error, UnicodeError) as error:
                        result = {"path": f"{archive_path}::{info.filename}", "error": str(error)}
                    result["uncompressed_size_bytes"] = info.file_size
                    result["compressed_size_bytes"] = info.compress_size
                    result["crc32"] = f"{info.CRC:08x}"
                    files.append(result)
    analysis_paths = [item["path"] for item in files if "error" not in item]
    return _dataset_result(
        "CIC-IDS2017",
        inventory,
        files,
        analysis_paths,
        "MachineLearningCSV.zip was audited by streaming its CSV members; the raw archive "
        "was not extracted. Repository provenance/version is undocumented. The companion "
        "MachineLearningCSV.md5 names MachineLearningCVE.zip, so its applicability to "
        "the acquired archive requires confirmation.",
    )


def _audit_directory_csvs(
    root: Path,
    database: sqlite3.Connection,
    name: str,
    relative: Path,
    provenance: str,
) -> dict[str, Any]:
    folder = root / relative
    inventory = _inventory(root, folder)
    files = [
        audit_path_source(path, root, database, inventory) for path in sorted(folder.glob("*.csv"))
    ]
    return _dataset_result(
        name, inventory, files, [f["path"] for f in files if "error" not in f], provenance
    )


def audit_path_source(
    path: Path,
    root: Path,
    database: sqlite3.Connection,
    inventory: list[dict[str, object]],
) -> dict[str, object]:
    relative = path.relative_to(root).as_posix()
    result = audit_path(CsvSource(relative, path), database)
    manifest = next((entry for entry in inventory if entry["path"] == relative), None)
    if manifest is not None:
        result["sha256"] = manifest["sha256"]
        result["size_bytes"] = manifest["size_bytes"]
    return result


def _audit_unsw(root: Path, database: sqlite3.Connection) -> dict[str, Any]:
    relative = Path(DATASET_PATHS["UNSW-NB15"])
    folder = root / relative
    inventory = _inventory(root, folder)
    csv_root = folder / "CSV Files"
    feature_names = _unsw_raw_feature_names(csv_root / "NUSW-NB15_features.csv")
    raw_names = feature_names
    if len(raw_names) == 47:
        raw_names.extend(["attack_cat", "Label"])
    files: list[dict[str, object]] = []
    for path in sorted(csv_root.rglob("*.csv")):
        if re_match_unsw_partition(path.name):
            source = CsvSource(
                path.relative_to(root).as_posix(), path, "supplied", tuple(raw_names)
            )
            file_report = audit_path(source, database)
            manifest = next(
                (entry for entry in inventory if entry["path"] == source.display_path), None
            )
            if manifest is not None:
                file_report["sha256"] = manifest["sha256"]
                file_report["size_bytes"] = manifest["size_bytes"]
            files.append(file_report)
        else:
            files.append(audit_path_source(path, root, database, inventory))
    analysis_paths = [
        item["path"]
        for item in files
        if "error" not in item
        and Path(str(item["path"])).name
        not in {"NUSW-NB15_GT.csv", "NUSW-NB15_features.csv", "UNSW-NB15_LIST_EVENTS.csv"}
    ]
    result = _dataset_result(
        "UNSW-NB15",
        inventory,
        files,
        analysis_paths,
        "Repository contains official headered train/test files, four headerless raw "
        "partitions with positions named from the local feature dictionary, auxiliary "
        "ground-truth/feature/event CSVs, and two PDFs. Acquisition source/version is "
        "not recorded in repository text.",
    )
    result["split_structure"] = {
        "official_train_test": [
            "CSV Files/Training and Testing Sets/UNSW_NB15_training-set.csv",
            "CSV Files/Training and Testing Sets/UNSW_NB15_testing-set.csv",
        ],
        "raw_partitions": [f"CSV Files/UNSW-NB15_{n}.csv" for n in range(1, 5)],
        "raw_partition_headers": (
            "absent; positional names taken from the local feature dictionary. Verify "
            "the mapping against dataset documentation before modeling."
        ),
    }
    return result


def _unsw_raw_feature_names(path: Path) -> list[str]:
    with path.open(encoding="cp1252", newline="") as stream:
        reader = csv.DictReader(stream)
        rows = list(reader)
    return [row["Name"].strip() for row in rows if row.get("Name")]


def re_match_unsw_partition(name: str) -> bool:
    return name in {f"UNSW-NB15_{index}.csv" for index in range(1, 5)}


def _audit_ton(root: Path, database: sqlite3.Connection) -> dict[str, Any]:
    path = root / DATASET_PATHS["TON_IoT"]
    inventory = _inventory(root, path)
    files = [audit_path_source(path, root, database, inventory)] if path.exists() else []
    return _dataset_result(
        "TON_IoT",
        inventory,
        files,
        [item["path"] for item in files if "error" not in item],
        "The acquired artifact is train_test_network.csv from a public mirror, per the "
        "project acquisition note. This does not establish that it is the complete "
        "23-file processed network dataset. Mirror URL, retrieval date, and upstream "
        "checksum are absent from repository metadata.",
    )


def _dataset_result(
    name: str,
    inventory: list[dict[str, Any]],
    files: list[dict[str, Any]],
    analysis_paths: list[object],
    provenance: str,
) -> dict[str, Any]:
    selected = [f for f in files if f.get("path") in analysis_paths and "error" not in f]
    row_total = sum(int(f.get("rows", 0)) for f in selected)
    schemas = sorted({int(f.get("column_count", 0)) for f in selected})
    labels_by_key: dict[str, str] = {}
    for file_info in selected:
        for label in file_info.get("label_columns", []):
            labels_by_key.setdefault(str(label).casefold(), str(label))
    label_names = sorted(labels_by_key.values(), key=str.casefold)
    class_values: dict[str, set[str]] = {label: set() for label in label_names}
    label_totals: dict[str, Counter[str]] = {label: Counter() for label in label_names}
    label_denominators: Counter[str] = Counter()
    for file_info in selected:
        for column in file_info.get("columns", []):
            if not isinstance(column, dict) or not column.get("label_like_by_name"):
                continue
            source_name = str(column.get("name", ""))
            label_name = labels_by_key.get(source_name.casefold())
            if label_name is None:
                continue
            counts = column.get("label_counts")
            if isinstance(counts, dict):
                for value, count in counts.items():
                    class_values[label_name].add(str(value))
                    label_totals[label_name][str(value)] += int(count)
                    label_denominators[label_name] += int(count)
    feature_widths = sorted(
        {
            int(file_info.get("column_count", 0)) - len(file_info.get("label_columns", []))
            for file_info in selected
        }
    )
    return {
        "name": name,
        "inventory": inventory,
        "files": files,
        "analysis_file_paths": analysis_paths,
        "provenance_and_acquisition_notes": provenance,
        "summary": {
            "file_count": len(inventory),
            "analysis_file_count": len(selected),
            "rows": row_total,
            "schema_widths_including_labels": schemas,
            "feature_count_excluding_name-detected_labels": feature_widths,
            "label_columns": label_names,
            "classes_by_label": {label: sorted(values) for label, values in class_values.items()},
            "label_counts_by_label": {
                label: dict(sorted(counts.items())) for label, counts in label_totals.items()
            },
            "label_percentages_by_label": {
                label: {
                    value: round(count * 100 / label_denominators[label], 6)
                    if label_denominators[label]
                    else 0.0
                    for value, count in sorted(counts.items())
                }
                for label, counts in label_totals.items()
            },
            "missing_cell_count": sum(
                int(column.get("missing", 0))
                for f in selected
                for column in f.get("columns", [])
                if isinstance(column, dict)
            ),
            "nonfinite_cell_count": sum(
                int(column.get("nonfinite", 0))
                for f in selected
                for column in f.get("columns", [])
                if isinstance(column, dict)
            ),
            "duplicate_rows_within_files": 0,
        },
    }


def _unsw_split_overlap(database: sqlite3.Connection) -> dict[str, object]:
    training = "data/raw/unsw-nb15/CSV Files/Training and Testing Sets/UNSW_NB15_training-set.csv"
    testing = "data/raw/unsw-nb15/CSV Files/Training and Testing Sets/UNSW_NB15_testing-set.csv"
    counts = database.execute(
        "SELECT COUNT(*) FROM (SELECT row_hash FROM row_hashes WHERE file_key IN (?, ?) "
        "GROUP BY row_hash HAVING COUNT(DISTINCT file_key) = 2)",
        (training, testing),
    ).fetchone()
    return {
        "official_train_test_shared_exact_row_signatures": int(counts[0]) if counts else 0,
        "comparison": "exact parsed rows with identical header/schema prefix",
    }


def _set_dataset_duplicate_total(dataset: dict[str, Any], duplicate_data: dict[str, Any]) -> None:
    paths = set(dataset.get("analysis_file_paths", []))
    per_file = duplicate_data.get("per_file", {})
    for file_info in dataset.get("files", []):
        file_info["duplicate_rows_beyond_first"] = per_file.get(file_info.get("path"), {}).get(
            "duplicate_rows_beyond_first", 0
        )
    dataset["summary"]["duplicate_rows_within_files"] = sum(
        int(stats.get("duplicate_rows_beyond_first", 0))
        for path, stats in per_file.items()
        if path in paths
    )
    repeated_headers = [
        f"{file_info.get('repeated_header_rows')} exact repeated header rows in "
        f"{file_info.get('path')}"
        for file_info in dataset.get("files", [])
        if file_info.get("repeated_header_rows", 0)
    ]
    if repeated_headers:
        dataset["verified_observations"] = repeated_headers


def _render_markdown(report: dict[str, Any]) -> str:
    datasets = report["datasets"]
    lines = [
        "# Stage 5A Dataset Audit",
        "",
        fill(
            f"Generated from the files present at `{report['audit']['generated_at_utc']}`. "
            "Raw files were opened read-only; no downloads, extraction, rewriting, or "
            "cross-dataset merging were performed.",
            width=88,
        ),
        "",
        "## Summary",
        "",
        fill(
            "Rows sum independently audited analysis files; files with different schemas "
            "or partitions remain separate in the detailed section. Feature widths "
            "exclude columns identified by label-like names; this is not a modeling "
            "recommendation.",
            width=88,
        ),
        "",
        "| Dataset | Files present | Rows | Feature widths | Labels | Classes (count / %) | "
        "Missing / non-finite | Duplicates | Split structure | Provenance / limitations |",
        "| --- | ---: | ---: | --- | --- | --- | ---: | ---: | --- | --- |",
    ]
    for dataset in datasets:
        summary = dataset["summary"]
        label_text = "; ".join(summary["label_columns"]) or "not identified by column name"
        classes = _class_summary(summary)
        miss = f"{summary['missing_cell_count']} / {summary['nonfinite_cell_count']}"
        split = _split_summary(dataset)
        lines.append(
            f"| {dataset['name']} | {summary['file_count']} | {summary['rows']} | "
            f"{summary['feature_count_excluding_name-detected_labels']} | {label_text} | "
            f"{classes} | {miss} | {summary['duplicate_rows_within_files']} | {split} | "
            f"{_short_provenance(dataset)} |"
        )
    lines.extend(["", "## Observed facts by dataset", ""])
    for dataset in datasets:
        lines.extend(
            [
                f"### {dataset['name']}",
                "",
                fill(str(dataset["provenance_and_acquisition_notes"]), width=88),
                "",
            ]
        )
        lines.extend(
            [
                "| File | Size | Hash | Rows | Cols | Bad | Repeat hdrs | Dups | Labels |",
                "| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | --- |",
            ]
        )
        inventoried_paths: set[str] = set()
        for entry in dataset["inventory"]:
            inventoried_paths.add(str(entry["path"]))
            corresponding = next(
                (item for item in dataset["files"] if item.get("path") == entry["path"]), None
            )
            if corresponding is None:
                lines.append(
                    f"| {entry['path']} | {entry['size_bytes']} | `{entry['sha256']}` "
                    "| — | — | — | — | — | — |"
                )
                continue
            labels = []
            for column in corresponding.get("columns", []):
                if isinstance(column, dict) and column.get("label_like_by_name"):
                    counts = column.get("label_counts", {})
                    labels.append(f"{column['name']}: {counts}")
            size = entry["size_bytes"]
            row_count = corresponding.get("rows", "—")
            column_count = corresponding.get("column_count", "—")
            malformed_count = corresponding.get("malformed_rows", "—")
            repeated_header_count = corresponding.get("repeated_header_rows", "—")
            duplicate_count = corresponding.get("duplicate_rows_beyond_first", "—")
            lines.append(
                f"| {entry['path']} | {size} | `{entry['sha256']}` | {row_count} | "
                f"{column_count} | {malformed_count} | {repeated_header_count} | "
                f"{duplicate_count} | "
                f"{'; '.join(labels) or 'not identified'} |"
            )
        for file_info in dataset["files"]:
            if file_info.get("path") in inventoried_paths:
                continue
            member_labels = _file_label_summary(file_info)
            lines.append(
                f"| {file_info['path']} | {file_info.get('uncompressed_size_bytes', '—')} | "
                f"ZIP CRC32 `{file_info.get('crc32', 'not recorded')}` | "
                f"{file_info.get('rows', '—')} | {file_info.get('column_count', '—')} | "
                f"{file_info.get('malformed_rows', '—')} | "
                f"{file_info.get('repeated_header_rows', '—')} | "
                f"{file_info.get('duplicate_rows_beyond_first', '—')} | {member_labels} |"
            )
        lines.extend(
            [
                "",
                "#### Schema and value checks",
                "",
                fill(
                    "See the JSON report for each column's inferred type, missing/non-finite "
                    "counts, numeric range, negative count, distinct count or lower bound, "
                    "top values, constant flags, and identifier/time/label name flags.",
                    width=88,
                ),
                "",
            ]
        )
        for file_info in dataset["files"]:
            if "error" in file_info:
                lines.append(f"- `{file_info['path']}` audit error: {file_info['error']}")
                continue
            concerns = [
                column
                for column in file_info.get("columns", [])
                if isinstance(column, dict)
                and (
                    column.get("nonfinite", 0)
                    or column.get("constant")
                    or column.get("near_constant_ge_99_9_percent")
                    or column.get("negative_numeric_count", 0)
                )
            ]
            lines.append(
                fill(
                    f"- `{file_info['path']}`: {len(concerns)} columns flagged for "
                    "non-finite, constant/near-constant, or negative numeric values. "
                    "Detailed counts and ranges are in JSON.",
                    width=88,
                )
            )
        for observation in dataset.get("verified_observations", []):
            lines.append(f"- Verified observation: {observation}")
        lines.append("")
        duplicate_data = dataset.get("duplicates", {})
        if dataset["name"] == "UNSW-NB15":
            overlap = dataset.get("split_structure", {}).get("exact_overlap", {})
            lines.append(
                "Official train/test exact shared row signatures: "
                f"{overlap.get('official_train_test_shared_exact_row_signatures', 'not computed')}."
            )
        lines.append(
            "Cross-file duplicate summary: `"
            f"{json.dumps(duplicate_data.get('cross_file', {}), sort_keys=True)}`."
        )
        lines.append("")
    lines.extend(
        [
            "## Audit method and interpretation",
            "",
            fill(
                "CSV rows are streamed independently. Headerless UNSW raw partition columns "
                "are assigned positionally from the local feature dictionary and observed "
                "49-field layout; verify this mapping against acquired documentation before "
                "modeling. Duplicate fingerprints hash parsed cells plus the exact header. "
                "Equal hashes are treated as exact duplicates, subject to negligible SHA-256 "
                "collision risk. Distinct counts are exact up to 50,000 values per column; "
                "higher cardinality is reported as a lower bound. Near-constant means the "
                "leading value is at least 99.9% of rows, checked only below that cap.",
                width=88,
            ),
            "",
            fill(
                "Non-finite detection recognizes common NaN/Inf tokens and numeric parsing. "
                "Numeric ranges are observed extrema, not validity judgments. Name-based "
                "label, identifier, and timestamp flags are heuristic signals, not confirmed "
                "leakage. File identity and timestamps may expose source or time information; "
                "the audit does not decide whether they are valid model inputs.",
                width=88,
            ),
            "",
            *_experimental_implications(),
        ]
    )
    return "\n".join(lines) + "\n"


def _split_summary(dataset: dict[str, Any]) -> str:
    if dataset["name"] == "UNSW-NB15":
        return "official train/test + four raw partitions"
    if dataset["name"] == "CIC-IDS2017":
        return "eight date/session member CSVs in ZIP"
    if dataset["name"] == "CSE-CIC-IDS2018":
        return "ten date-named CSVs; one file has differing schema"
    if dataset["name"] == "TON_IoT":
        return "single train_test_network.csv artifact"
    return "not established"


def _experimental_implications() -> list[str]:
    return [
        "## Implications for Experimental Design",
        "",
        fill(
            "- **Random splitting:** avoid as the primary protocol where records may share "
            "sessions, duplicate rows, days, or source identifiers. It can be a secondary "
            "baseline after group leakage is assessed.",
            width=88,
        ),
        fill(
            "- **Source/file-aware splitting:** preserve CIC-IDS2017 member and CSE date-file "
            "boundaries where schemas permit. Keep CSE files separate; file-level splits can "
            "evaluate day/source change. The 20 February CSE file has a different schema and "
            "needs explicit feature mapping.",
            width=88,
        ),
        fill(
            "- **Temporal splitting:** use timestamps for CIC/CSE and TON where parsing is "
            "reliable. UNSW raw partitions expose positional Stime/Ltime; official splits do "
            "not expose direct timestamps. Review JSON ranges before defining windows and do "
            "not select windows from test outcomes.",
            width=88,
        ),
        fill(
            "- **Cross-dataset evaluation:** keep datasets and label/feature semantics "
            "separate. Transfer is supplementary and requires explicit common-feature and "
            "label mappings; do not concatenate schemas.",
            width=88,
        ),
        fill(
            "- **Leakage risks:** assess exact duplicates across same-schema files, file/date "
            "identifiers, IP/flow identifiers, timestamp-derived fields, label-like values, "
            "and official split overlap. Drop or group identifiers only under a documented "
            "protocol. Test data must not fit preprocessing or thresholds.",
            width=88,
        ),
        fill(
            "- **Development vs generalization:** CIC-IDS2017 and CSE-CIC-IDS2018 have "
            "multiple source/date files that can support development and held-out-file/day "
            "evaluation after duplicate, label, and schema checks. UNSW-NB15 has an official "
            "train/test pair; use its training split for development and retain testing for "
            "final evaluation, while validating the raw-partition feature mapping. TON_IoT's "
            "single public-mirror file has no verified internal split provenance, so it is a "
            "development candidate only after split provenance is resolved, not a standalone "
            "generalization set. Cross-dataset evaluation needs frozen feature and label maps. "
            "This audit does not rank datasets.",
            width=88,
        ),
        "",
    ]


def _class_summary(summary: dict[str, Any]) -> str:
    counts = summary["label_counts_by_label"]
    percentages = summary["label_percentages_by_label"]
    pieces = []
    for label, values in counts.items():
        portions = percentages.get(label, {})
        pieces.append(
            f"{label}: "
            + ", ".join(
                f"{value}={count} ({portions.get(value, 0)}%)" for value, count in values.items()
            )
        )
    return "; ".join(pieces) or "not identified"


def _file_label_summary(file_info: dict[str, Any]) -> str:
    portions = []
    for column in file_info.get("columns", []):
        if isinstance(column, dict) and column.get("label_like_by_name"):
            counts = column.get("label_counts", {})
            percentages = column.get("label_percentages", {})
            if isinstance(counts, dict) and isinstance(percentages, dict):
                portions.append(
                    f"{column['name']}: "
                    + ", ".join(
                        f"{value}={count} ({percentages.get(value, 0)}%)"
                        for value, count in counts.items()
                    )
                )
    return "; ".join(portions) or "not identified"


def _short_provenance(dataset: dict[str, Any]) -> str:
    if dataset["name"] == "TON_IoT":
        return "Public mirror; single file; mirror URL/date absent"
    if dataset["name"] == "CIC-IDS2017":
        return "CSV remains zipped; original source undocumented"
    if dataset["name"] == "CSE-CIC-IDS2018":
        return "Acquisition source undocumented"
    return "Local metadata/docs present; acquisition source undocumented"


if __name__ == "__main__":
    raise SystemExit(main())
