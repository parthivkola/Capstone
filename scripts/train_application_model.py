#!/usr/bin/env python3
"""Explicit opt-in trainer for the new offline application baseline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ml.models.train_application_model import (
    MAX_RECORDS_PER_CLASS_PER_SOURCE,
    SEED,
    train_application_model,
)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("var/models/cse-cicflowmeter-binary-logistic-v1"),
    )
    parser.add_argument(
        "--max-records-per-class-per-source",
        type=int,
        default=MAX_RECORDS_PER_CLASS_PER_SOURCE,
    )
    parser.add_argument("--seed", type=int, default=SEED)
    arguments = parser.parse_args()
    manifest = train_application_model(
        root,
        arguments.output_dir,
        max_records_per_class_per_source=arguments.max_records_per_class_per_source,
        seed=arguments.seed,
    )
    print(
        json.dumps(
            {
                "model_id": manifest["model_id"],
                "status": manifest["status"],
                "artifact": str(arguments.output_dir / "manifest.json"),
                "test_metrics": manifest["metrics"]["test"],
                "live_eligible": manifest["live_eligible"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
