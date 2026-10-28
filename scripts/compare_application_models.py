#!/usr/bin/env python3
"""Compare offline linear candidates on validation and write the selected winner."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ml.models.train_application_model import SEED, compare_application_models


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("var/models/cse-cicflowmeter-binary-logistic-v2"),
    )
    parser.add_argument(
        "--comparison-path",
        type=Path,
        default=Path("experiments/stage5d/application-linear-model-comparison-v1.json"),
    )
    parser.add_argument("--max-records-per-class-per-source", type=int, default=300)
    parser.add_argument("--max-benign-fpr", type=float, default=0.25)
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--version", default="2.0.0")
    arguments = parser.parse_args()
    result = compare_application_models(
        root,
        arguments.output_dir,
        arguments.comparison_path,
        max_records_per_class_per_source=arguments.max_records_per_class_per_source,
        max_benign_fpr=arguments.max_benign_fpr,
        seed=arguments.seed,
        version=arguments.version,
    )
    print(
        json.dumps(
            {
                "winner": result["comparison"]["winner"],
                "candidates": [
                    {
                        "candidate_id": row["candidate_id"],
                        "validation_macro_f1": row["validation"]["macro_f1"],
                        "validation_benign_fpr": row["validation"]["benign_fpr"],
                        "selected": row["selected"],
                    }
                    for row in result["comparison"]["candidates"]
                ],
                "comparison_report": str(arguments.comparison_path),
                "model_manifest": str(arguments.output_dir / "manifest.json"),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
