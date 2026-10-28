#!/usr/bin/env python3
"""Create reproducible, model-ready CSE data without fitting or training models."""

from __future__ import annotations

import argparse
from pathlib import Path

from ml.datasets.stage5d_preparation import run_preparation


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir", type=Path, default=Path("data/raw/cse-cic-ids2018"))
    parser.add_argument(
        "--output-dir", type=Path, default=Path("data/processed/stage5d/cse-cic-ids2018")
    )
    parser.add_argument(
        "--report", type=Path, default=Path("experiments/stage5d/cse-preparation.json")
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    report = run_preparation(root, args.raw_dir, args.output_dir, args.report)
    print(f"Prepared {len(report['source_statistics'])} source files; no models trained.")
    print(f"Preparation report: {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
