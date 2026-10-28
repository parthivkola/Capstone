#!/usr/bin/env python3
"""Train an explicitly unapproved, run-separated four-feature logistic baseline."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.sdn_defense.live_dataset import (  # noqa: E402
    LiveDatasetError,
    train_preliminary_live_model,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--max-validation-fpr", type=float, default=0.10)
    args = parser.parse_args()
    dataset_manifest = (
        (ROOT / args.dataset_manifest).resolve()
        if not args.dataset_manifest.is_absolute()
        else args.dataset_manifest.resolve()
    )
    output = (
        (ROOT / args.output_dir).resolve()
        if not args.output_dir.is_absolute()
        else args.output_dir.resolve()
    )
    if not output.is_relative_to((ROOT / "var/models").resolve()):
        parser.error("model output must remain under var/models")
    try:
        result = train_preliminary_live_model(
            dataset_manifest_path=dataset_manifest,
            output_directory=output,
            maximum_validation_fpr=args.max_validation_fpr,
        )
    except (LiveDatasetError, OSError, ValueError) as error:
        parser.exit(2, f"live baseline training refused: {error}\n")
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
