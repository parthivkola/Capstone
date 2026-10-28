"""Read-only converter from a Stage 2 Ryu log to Stage 4 JSONL records."""

from __future__ import annotations

import argparse

from src.sdn_defense.flow_records import deduplicate_records, extract_ryu_log, write_jsonl


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="Ryu structured log containing stage2_event JSON")
    parser.add_argument("output", help="destination JSONL path")
    parser.add_argument(
        "--deduplicate", action="store_true", help="remove byte-identical normalized snapshots"
    )
    arguments = parser.parse_args()
    records = extract_ryu_log(arguments.input)
    if arguments.deduplicate:
        records = deduplicate_records(records)
    write_jsonl(records, arguments.output)
    print(f"Wrote {len(records)} flow records to {arguments.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
