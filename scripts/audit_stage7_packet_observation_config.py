"""Audit existing OVS/collector state without starting or changing infrastructure."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from networking.mininet.packet_observation_auditor import run_read_only_audit

EXIT_CODES = {"AUDIT_COMPLETE": 0, "AUDIT_INCOMPLETE": 2, "CONFIGURATION_MISMATCH": 3}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bridge", default="s1")
    parser.add_argument("--collector-namespace", default="s7collector")
    parser.add_argument("--collector-interface", default="s7rcv0")
    parser.add_argument(
        "--requested-config",
        type=Path,
        help="optional JSON object containing requested bridge/mirror/collector settings",
    )
    parser.add_argument(
        "--manifest-output",
        type=Path,
        help="write a realized manifest only when the audit is complete",
    )
    args = parser.parse_args(argv)
    requested = None
    if args.requested_config is not None:
        try:
            requested_data = json.loads(args.requested_config.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(
                json.dumps(
                    {
                        "status": "AUDIT_INCOMPLETE",
                        "error": f"requested configuration unavailable: {type(exc).__name__}",
                        "manifest": None,
                    },
                    sort_keys=True,
                )
            )
            return EXIT_CODES["AUDIT_INCOMPLETE"]
        requested = requested_data.get("requested", requested_data)
        if not isinstance(requested, dict):
            print(
                json.dumps(
                    {
                        "status": "AUDIT_INCOMPLETE",
                        "error": "requested configuration must be a JSON object",
                        "manifest": None,
                    },
                    sort_keys=True,
                )
            )
            return EXIT_CODES["AUDIT_INCOMPLETE"]
    audit = run_read_only_audit(
        requested=requested,
        bridge_name=args.bridge,
        collector_namespace=args.collector_namespace,
        collector_interface=args.collector_interface,
    )
    if args.manifest_output is not None:
        manifest = audit.get("manifest")
        if manifest is None:
            audit["manifest_write"] = {
                "written": False,
                "reason": "audit did not complete; no realized manifest was created",
            }
        else:
            try:
                args.manifest_output.parent.mkdir(parents=True, exist_ok=True)
                args.manifest_output.write_text(
                    json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8"
                )
                audit["manifest_write"] = {"written": True, "path": str(args.manifest_output)}
            except OSError as exc:
                audit["manifest_write"] = {
                    "written": False,
                    "error": f"{type(exc).__name__}: manifest output unavailable",
                }
                audit["status"] = "AUDIT_INCOMPLETE"
    print(json.dumps(audit, sort_keys=True, indent=2))
    return EXIT_CODES[audit["status"]]


if __name__ == "__main__":
    sys.exit(main())
