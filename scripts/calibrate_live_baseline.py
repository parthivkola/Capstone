#!/usr/bin/env python3
"""Calibrate a provisional live anomaly baseline from audited benign run data."""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.sdn_defense.live_anomaly import calibrate_benign_runs, save_calibration  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run-dir",
        action="append",
        required=True,
        help="verified run directory under experiments/stage7-telemetry (repeatable)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="new, non-existing directory under var/models",
    )
    parser.add_argument(
        "--threshold", type=float, default=4.0, help="fixed robust-z threshold; default 4.0"
    )
    parser.add_argument("--max-gap-seconds", type=float, default=30.0)
    args = parser.parse_args()
    if not math.isfinite(args.max_gap_seconds) or args.max_gap_seconds <= 0:
        parser.error("--max-gap-seconds must be finite and positive")
    runs: list[tuple[Path, dict[str, object]]] = []
    for value in args.run_dir:
        directory = (ROOT / value).resolve()
        allowed = (ROOT / "experiments/stage7-telemetry").resolve()
        if not directory.is_relative_to(allowed) or not directory.is_dir():
            parser.error(f"run directory must exist under experiments/stage7-telemetry: {value}")
        telemetry = directory / "telemetry.jsonl"
        summary_path = directory / "collection-summary.json"
        if not telemetry.is_file() or not summary_path.is_file():
            parser.error(f"run is missing telemetry.jsonl or collection-summary.json: {value}")
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            parser.error(f"cannot read run summary {summary_path}: {error}")
        if not isinstance(summary, dict):
            parser.error(f"run summary must be a JSON object: {summary_path}")
        runs.append((telemetry, summary))
    output = (
        (ROOT / args.output_dir).resolve()
        if not args.output_dir.is_absolute()
        else args.output_dir.resolve()
    )
    if not output.is_relative_to((ROOT / "var/models").resolve()):
        parser.error("output directory must remain under var/models")
    try:
        model = calibrate_benign_runs(
            runs, threshold=args.threshold, maximum_gap_seconds=args.max_gap_seconds
        )
        manifest = save_calibration(model, output)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.exit(2, f"calibration refused: {error}\n")
    print(json.dumps(manifest, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
