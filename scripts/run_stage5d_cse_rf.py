#!/usr/bin/env python3
"""Preflight and run the frozen CSE source-file Random Forest holdouts."""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
from pathlib import Path
from typing import Any

from ml.evaluation.stage5d_cse import preflight, train_holdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    preflight_result = preflight(root)
    preflight_path = root / "experiments/stage5d/cse-preflight.json"
    preflight_path.write_text(
        json.dumps(preflight_result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    if not preflight_result["passed"]:
        print(json.dumps(preflight_result["failures"], indent=2), file=sys.stderr)
        return 2
    print("Stage 5D preflight passed for all prepared sources.")
    if args.preflight_only:
        return 0

    import numpy as np
    import sklearn

    from ml.evaluation.stage5d_cse import _load_json

    protocol = _load_json(root / "experiments/stage5c1/cse-protocol.json")
    results: list[dict[str, Any]] = []
    for holdout in protocol["source_file_holdouts"]:
        print(f"Training {holdout['id']} Random Forest ...", flush=True)
        results.append(train_holdout(root, holdout, preflight_result))
        print(f"Completed {holdout['id']}.", flush=True)

    stage5b_path = root / "experiments/stage5b/unsw-nb15-official-baselines.json"
    stage5b = _load_json(stage5b_path)
    unsw_rf = stage5b.get("results", {}).get("random_forest")
    output = {
        "stage": "5D source-file holdout Random Forest",
        "status": "completed",
        "dataset": "CSE-CIC-IDS2018 prepared sources only",
        "seed": 2026,
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "numpy": np.__version__,
            "scikit_learn": sklearn.__version__,
            "cpu_count": os.cpu_count(),
            "gpu": (
                "NVIDIA GeForce GTX 1650, 4 GiB VRAM; unused "
                "(no compatible GPU RF package installed)"
            ),
        },
        "preflight": preflight_result,
        "model_configuration": results[0]["model"] if results else {},
        "preprocessing": {
            "features": preflight_result["feature_schema"],
            "feature_dtype": "float32",
            "learned_preprocessing": "none",
            "test_sources_used_for_fit_or_selection": False,
        },
        "holdouts": results,
        "separate_dataset_reference": {
            "dataset": "UNSW-NB15 official train/test pair",
            "stage5b_result": unsw_rf,
            "direct_comparability": False,
            "note": (
                "Separate-dataset reference only; dataset, split, schema, and label "
                "semantics differ."
            ),
        },
        "source_file_generalization_gap": {
            "computed": False,
            "reason": (
                "No frozen within-source reference exists for the same data and "
                "protocol; do not compare against Stage 5B or invent a random split."
            ),
        },
        "models_other_than_random_forest_trained": False,
    }
    out = root / "experiments/stage5d/cse-source-holdout-rf.json"
    out.write_text(json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Results: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
