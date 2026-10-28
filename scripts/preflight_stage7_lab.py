#!/usr/bin/env python3
"""Read-only preflight for the isolated Stage 7 Mininet lab."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.sdn_defense.lab_preflight import format_preflight, inspect_lab  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller-port", type=int, default=6653)
    parser.add_argument(
        "--ack-isolated-lab",
        action="store_true",
        help="acknowledge the topology is confined to Mininet namespaces; does not override checks",
    )
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    args = parser.parse_args()
    ryu_path = ROOT / ".venv-ryu" / "bin" / "ryu-manager"
    ryu_manager = (
        str(ryu_path)
        if ryu_path.is_file() and os.access(ryu_path, os.X_OK)
        else "ryu-manager"
    )
    result = inspect_lab(
        acknowledge_isolation=args.ack_isolated_lab,
        controller_port=args.controller_port,
        ryu_manager=ryu_manager,
    )
    print(json.dumps(result, indent=2) if args.json else format_preflight(result))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
