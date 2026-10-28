import csv
import gzip
import hashlib
from pathlib import Path

import pytest

from ml.datasets.stage5d_preparation import (
    _nonfinite_kind,
    feature_names,
    prepare_source,
    project_header,
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_feature_names_apply_only_frozen_exclusions() -> None:
    schema = ["Dst Port", "Protocol", "Timestamp", "Flow Duration", "Label"]
    assert feature_names(schema) == ["Protocol", "Flow Duration"]


def test_projection_uses_named_columns_in_common_order() -> None:
    source = ["Flow ID", "Label", "Protocol", "Dst Port", "Timestamp", "Flow Duration"]
    common = ["Dst Port", "Protocol", "Timestamp", "Flow Duration", "Label"]
    assert project_header(source, common) == [3, 2, 4, 5, 1]


def test_unexpected_missing_numeric_value_fails_closed() -> None:
    with pytest.raises(ValueError, match="missing value"):
        _nonfinite_kind("")


def test_prepare_source_filters_header_and_nonfinite_rows_but_keeps_zero(tmp_path: Path) -> None:
    source = tmp_path / "input.csv"
    output = tmp_path / "prepared.csv.gz"
    source_header = ["Flow ID", "Label", "Protocol", "Dst Port", "Timestamp", "Flow Duration"]
    rows = [
        source_header,
        source_header,
        ["a", "Benign", "0", "80", "t0", "0"],
        ["b", "Attack", "nan", "80", "t1", "4"],
        ["c", "Attack", "6", "+inf", "t2", "2"],
        ["d", "Attack", "17", "443", "t3", "-inf"],
        ["e", "Attack", "6", "53", "t4", "5"],
    ]
    with source.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerows(rows)
    common = ["Dst Port", "Protocol", "Timestamp", "Flow Duration", "Label"]
    stats = prepare_source(
        source,
        output,
        _sha256(source),
        source_header,
        common,
        {"Dst Port", "Protocol", "Flow Duration"},
    )

    assert stats.original_row_count == 6
    assert stats.repeated_header_rows == 1
    assert stats.rows_with_nan == 1
    assert stats.rows_with_positive_infinity == 1
    assert stats.rows_with_negative_infinity == 1
    assert stats.rows_with_nonfinite_numeric_values == 3
    assert stats.final_usable_row_count == 2
    assert stats.excluded_row_count == 4
    assert stats.class_counts == {"Attack": 1, "Benign": 1}
    assert stats.feature_names == ["Protocol", "Flow Duration"]
    with gzip.open(output, "rt", encoding="utf-8", newline="") as stream:
        assert list(csv.reader(stream)) == [
            ["Protocol", "Flow Duration", "Label"],
            ["0", "0", "Benign"],
            ["6", "5", "Attack"],
        ]


def test_prepare_source_fails_closed_on_schema_or_hash_mismatch(tmp_path: Path) -> None:
    source = tmp_path / "input.csv"
    source.write_text("A,B\n1,2\n", encoding="utf-8")
    with pytest.raises(ValueError, match="hash mismatch"):
        prepare_source(source, tmp_path / "out.csv.gz", "0" * 64, ["A", "B"], ["A"], {"A"})

    with pytest.raises(ValueError, match="missing common-schema"):
        project_header(["A"], ["A", "B"])
