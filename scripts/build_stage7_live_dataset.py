#!/usr/bin/env python3
"""Assemble and evaluate run-separated Stage 7 benign/port-scan telemetry."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.sdn_defense.live_dataset import LiveDatasetError, build_live_dataset  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", action="append", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--max-gap-seconds", type=float, default=30.0)
    args = parser.parse_args()
    runs = [
        (ROOT / value).resolve() if not value.is_absolute() else value.resolve()
        for value in args.run_dir
    ]
    try:
        manifest = build_live_dataset(
            runs,
            output_directory=(ROOT / args.output_dir).resolve()
            if not args.output_dir.is_absolute()
            else args.output_dir.resolve(),
            max_gap_seconds=args.max_gap_seconds,
        )
    except (LiveDatasetError, OSError, ValueError) as error:
        parser.exit(2, f"dataset build refused: {error}\n")
    print(json.dumps(manifest, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
