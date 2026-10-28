"""Streaming, read-only CSV dataset auditing helpers for Stage 5A."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import re
import sqlite3
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO

MISSING_TOKENS = {"", "?", "na", "n/a", "null", "none"}
NONFINITE_TOKENS = {
    "nan",
    "+nan",
    "-nan",
    "inf",
    "+inf",
    "-inf",
    "infinity",
    "+infinity",
    "-infinity",
}
LABEL_PATTERN = re.compile(r"(^|[^a-z])(label|class|attack|category)([^a-z]|$)", re.IGNORECASE)
IDENTIFIER_PATTERN = re.compile(
    r"(^|[^a-z])(id|flow.?id|src.?ip|dst.?ip|source.?ip|destination.?ip|src.?port|dst.?port|timestamp|time|date|filename|file)([^a-z]|$)",
    re.IGNORECASE,
)
TIME_PATTERN = re.compile(r"time|timestamp|date", re.IGNORECASE)
MAX_DISTINCT_TRACKED = 50_000
MAX_LABEL_CLASSES = 10_000


@dataclass(frozen=True, slots=True)
class CsvSource:
    """One independently audited CSV input."""

    display_path: str
    path: Path
    header_mode: str = "first_row"
    supplied_columns: tuple[str, ...] = ()


class _ColumnState:
    def __init__(self, name: str) -> None:
        self.name = name
        self.label_like_by_name = bool(LABEL_PATTERN.search(name))
        self.nonmissing = 0
        self.missing = 0
        self.nonfinite = 0
        self.integer_values = 0
        self.numeric_values = 0
        self.string_values = 0
        self.numeric_min: float | None = None
        self.numeric_max: float | None = None
        self.negative_numeric = 0
        self.distinct: set[str] | None = set()
        self.distinct_lower_bound = 0
        self.top_values: Counter[str] | None = Counter()
        self.label_counts: Counter[str] | None = Counter() if self.label_like_by_name else None
        self.time_min: str | None = None
        self.time_max: str | None = None

    def add(self, value: str) -> None:
        token = value.strip()
        folded = token.casefold()
        if folded in MISSING_TOKENS:
            self.missing += 1
            return
        self.nonmissing += 1
        if self.distinct is not None:
            self.distinct.add(token)
            if len(self.distinct) > MAX_DISTINCT_TRACKED:
                self.distinct_lower_bound = len(self.distinct)
                self.distinct = None
                self.top_values = None

        if self.top_values is not None:
            self.top_values[token] += 1
        if self.label_counts is not None:
            if len(self.label_counts) <= MAX_LABEL_CLASSES or token in self.label_counts:
                self.label_counts[token] += 1
            else:
                self.label_counts = None

        if TIME_PATTERN.search(self.name):
            timestamp = _parse_datetime(token)
            if timestamp is not None:
                if self.time_min is None or timestamp < self.time_min:
                    self.time_min = timestamp
                if self.time_max is None or timestamp > self.time_max:
                    self.time_max = timestamp

        if folded in NONFINITE_TOKENS:
            self.nonfinite += 1
            return
        try:
            number = float(token)
        except ValueError:
            self.string_values += 1
            return
        if not math.isfinite(number):
            self.nonfinite += 1
            return
        self.numeric_values += 1
        if number.is_integer():
            self.integer_values += 1
        if number < 0:
            self.negative_numeric += 1
        self.numeric_min = number if self.numeric_min is None else min(self.numeric_min, number)
        self.numeric_max = number if self.numeric_max is None else max(self.numeric_max, number)

    def result(self, row_count: int) -> dict[str, Any]:
        if self.nonmissing == 0:
            inferred = "empty"
        elif self.numeric_values == self.nonmissing - self.nonfinite:
            inferred = "integer" if self.integer_values == self.numeric_values else "number"
        elif self.numeric_values == 0:
            inferred = "string/category"
        else:
            inferred = "mixed"
        distinct = len(self.distinct) if self.distinct is not None else None
        candidates = (
            sorted(self.top_values.items(), key=lambda item: (-item[1], item[0]))[:3]
            if self.top_values is not None
            else []
        )
        near_constant = bool(candidates and row_count and candidates[0][1] / row_count >= 0.999)
        output: dict[str, Any] = {
            "name": self.name,
            "inferred_type": inferred,
            "nonmissing": self.nonmissing,
            "missing": self.missing,
            "missing_percent": _percent(self.missing, row_count),
            "nonfinite": self.nonfinite,
            "distinct_count": distinct,
            "distinct_count_lower_bound": self.distinct_lower_bound if distinct is None else None,
            "constant": distinct == 1,
            "near_constant_ge_99_9_percent": near_constant,
            "top_values": [{"value": key, "count": value} for key, value in candidates],
            "numeric_min": self.numeric_min,
            "numeric_max": self.numeric_max,
            "negative_numeric_count": self.negative_numeric,
            "identifier_like_by_name": bool(IDENTIFIER_PATTERN.search(self.name)),
            "label_like_by_name": bool(LABEL_PATTERN.search(self.name)),
            "time_min": self.time_min,
            "time_max": self.time_max,
        }
        if self.label_counts is not None:
            output["label_counts"] = dict(sorted(self.label_counts.items()))
            output["label_percentages"] = {
                key: _percent(value, self.nonmissing)
                for key, value in sorted(self.label_counts.items())
            }
        return output


def sha256_file(path: str | Path) -> str:
    """Return a streaming SHA-256 digest without modifying the input."""

    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def audit_csv_stream(
    stream: TextIO,
    *,
    display_path: str,
    row_hash_sink: sqlite3.Connection,
    supplied_columns: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Audit one CSV text stream. The caller owns/opened stream and hash sink."""

    reader = csv.reader(stream)
    header = list(supplied_columns) if supplied_columns is not None else next(reader, [])
    header = [name.strip().lstrip("\ufeff") for name in header]
    if not header:
        return {
            "path": display_path,
            "columns": [],
            "column_count": 0,
            "rows": 0,
            "malformed_rows": 0,
            "error": "empty CSV or missing header",
        }

    states = [_ColumnState(name) for name in header]
    row_count = 0
    malformed = 0
    repeated_header_rows = 0
    hashes: list[tuple[str, bytes]] = []
    file_key = display_path
    schema_bytes = json.dumps(header, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    for row in reader:
        if not row:
            continue
        row_count += 1
        if row == header:
            repeated_header_rows += 1
        canonical = json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        row_digest = hashlib.sha256(schema_bytes + b"\0" + canonical).digest()
        hashes.append((file_key, row_digest))
        if len(hashes) >= 4096:
            _insert_row_hashes(row_hash_sink, hashes)
            hashes.clear()
        if len(row) != len(states):
            malformed += 1
        for index, state in enumerate(states):
            state.add(row[index] if index < len(row) else "")
    if hashes:
        _insert_row_hashes(row_hash_sink, hashes)
    row_hash_sink.commit()
    label_values = {
        value for state in states if state.label_counts is not None for value in state.label_counts
    }
    columns: list[dict[str, Any]] = []
    for state in states:
        column_result = state.result(row_count)
        if not state.label_like_by_name:
            column_result["feature_values_matching_label_classes"] = (
                sorted(label_values.intersection(state.distinct))
                if state.distinct is not None
                else None
            )
        columns.append(column_result)
    return {
        "path": display_path,
        "columns": columns,
        "column_count": len(header),
        "rows": row_count,
        "malformed_rows": malformed,
        "repeated_header_rows": repeated_header_rows,
        "schema_sha256": hashlib.sha256(schema_bytes).hexdigest(),
        "label_columns": [c["name"] for c in columns if c["label_like_by_name"]],
        "identifier_like_columns": [c["name"] for c in columns if c["identifier_like_by_name"]],
    }


def _insert_row_hashes(connection: sqlite3.Connection, batch: list[tuple[str, bytes]]) -> None:
    connection.executemany(
        "INSERT INTO row_hashes(file_key, row_hash, occurrences) VALUES (?, ?, 1) "
        "ON CONFLICT(file_key, row_hash) DO UPDATE SET occurrences=occurrences+1",
        batch,
    )


def duplicate_summary(connection: sqlite3.Connection) -> dict[str, Any]:
    """Summarize exact parsed-row duplicates from per-file SHA-256 fingerprints."""

    per_file: dict[str, dict[str, int]] = {}
    for file_key, signatures, extra_rows in connection.execute(
        "SELECT file_key, COUNT(*), COALESCE(SUM(occurrences - 1), 0) "
        "FROM row_hashes GROUP BY file_key"
    ):
        per_file[file_key] = {
            "distinct_row_hashes": int(signatures),
            "duplicate_rows_beyond_first": int(extra_rows),
        }
    cross_files = connection.execute(
        "SELECT COUNT(*), COALESCE(SUM(file_count - 1), 0), "
        "COALESCE(SUM(total_occurrences - 1), 0) "
        "FROM (SELECT row_hash, COUNT(*) AS file_count, SUM(occurrences) AS total_occurrences "
        "FROM row_hashes GROUP BY row_hash HAVING COUNT(*) > 1)"
    ).fetchone()
    assert cross_files is not None
    pair_counts: Counter[tuple[str, str]] = Counter()
    shared_groups = connection.execute(
        "SELECT GROUP_CONCAT(file_key, char(31)) FROM row_hashes "
        "GROUP BY row_hash HAVING COUNT(*) > 1"
    )
    for (group,) in shared_groups:
        file_keys = sorted(str(group).split("\x1f"))
        for index, first in enumerate(file_keys):
            for second in file_keys[index + 1 :]:
                pair_counts[(first, second)] += 1
    return {
        "per_file": per_file,
        "cross_file": {
            "shared_distinct_row_signatures": int(cross_files[0]),
            "extra_file_memberships": int(cross_files[1]),
            "total_occurrences_beyond_first_file_row": int(cross_files[2]),
            "file_pairs": [
                {"first_file": pair[0], "second_file": pair[1], "shared_signatures": count}
                for pair, count in sorted(pair_counts.items())
            ],
        },
        "method": (
            "SHA-256 of JSON-encoded parsed cell arrays; cryptographic collision risk is "
            "negligible but nonzero"
        ),
    }


def make_hash_database(path: str | Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=OFF")
    connection.execute("PRAGMA synchronous=OFF")
    connection.execute("PRAGMA cache_size=-65536")
    connection.execute(
        "CREATE TABLE row_hashes (file_key TEXT NOT NULL, row_hash BLOB NOT NULL, "
        "occurrences INTEGER NOT NULL, PRIMARY KEY(file_key, row_hash)) WITHOUT ROWID"
    )
    return connection


def audit_path(source: CsvSource, connection: sqlite3.Connection) -> dict[str, Any]:
    """Audit one filesystem CSV source; the caller adds its content hash."""

    path = source.path
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as stream:
            result = audit_csv_stream(
                stream,
                display_path=source.display_path,
                row_hash_sink=connection,
                supplied_columns=source.supplied_columns or None,
            )
        result["size_bytes"] = path.stat().st_size
        return result
    except (OSError, csv.Error) as exc:
        return {"path": source.display_path, "error": str(exc)}


def _percent(value: int, denominator: int) -> float:
    return round(value * 100 / denominator, 6) if denominator else 0.0


def _parse_datetime(value: str) -> str | None:
    candidates = [value.replace("Z", "+00:00")]
    formats = ["%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S"]
    for candidate in candidates:
        try:
            return datetime.fromisoformat(candidate).isoformat()
        except ValueError:
            pass
        for date_format in formats:
            try:
                return datetime.strptime(candidate, date_format).isoformat()
            except ValueError:
                continue
    if value.isdigit() and len(value) == 10:
        try:
            return datetime.fromtimestamp(int(value), UTC).isoformat().replace("+00:00", "Z")
        except (OverflowError, OSError, ValueError):
            return None
    return None
