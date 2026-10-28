"""Read-only source-lineage and cadence audit for Stage 7 telemetry JSONL."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from src.sdn_defense.telemetry_audit import audit_telemetry_jsonl, render_audit_report


def _paths_alias_or_unverifiable(left: Path, right: Path) -> bool:
    """Fail closed for equal, symlinked, hard-linked, or uninspectable paths."""

    try:
        if left.resolve() == right.resolve():
            return True
        return left.exists() and right.exists() and os.path.samefile(left, right)
    except OSError:
        return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("telemetry_jsonl", type=Path)
    parser.add_argument("--summary-json", type=Path)
    parser.add_argument("--report-md", type=Path)
    arguments = parser.parse_args()
    output_paths = [
        path
        for path in (arguments.summary_json, arguments.report_md)
        if path is not None
    ]
    if any(
        _paths_alias_or_unverifiable(arguments.telemetry_jsonl, output)
        for output in output_paths
    ):
        parser.error("audit outputs must not overwrite or alias the input telemetry JSONL")
    if len(output_paths) == 2 and _paths_alias_or_unverifiable(
        output_paths[0], output_paths[1]
    ):
        parser.error("summary and Markdown outputs must use distinct paths")
    try:
        summary = audit_telemetry_jsonl(arguments.telemetry_jsonl)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.exit(2, f"AUDIT_INCOMPLETE: {error}\n")
    rendered = render_audit_report(summary)
    try:
        if arguments.summary_json is not None:
            arguments.summary_json.write_text(
                json.dumps(summary, sort_keys=True, indent=2, allow_nan=False) + "\n",
                encoding="utf-8",
            )
        if arguments.report_md is not None:
            arguments.report_md.write_text(rendered, encoding="utf-8")
    except OSError as error:
        print(f"AUDIT_OUTPUT_ERROR: {error}\n", file=sys.stderr, end="")
        return 2
    print(rendered, end="")
    return 0 if summary["status"] == "AUDIT_COMPLETE" else 2


if __name__ == "__main__":
    raise SystemExit(main())
