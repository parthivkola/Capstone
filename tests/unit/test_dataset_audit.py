"""Small deterministic tests for reusable Stage 5A parsing and duplicate logic."""

from __future__ import annotations

import io

from src.sdn_defense.dataset_audit import audit_csv_stream, duplicate_summary, make_hash_database


def test_stream_audit_infers_schema_counts_labels_and_values() -> None:
    database = make_hash_database(":memory:")
    report = audit_csv_stream(
        io.StringIO("Timestamp,Flow ID,rate,Label\n2024-01-01 00:00:00,f1,1.5,BENIGN\n"),
        display_path="fixture.csv",
        row_hash_sink=database,
    )
    assert report["rows"] == 1
    assert report["repeated_header_rows"] == 0
    assert report["column_count"] == 4
    columns = {column["name"]: column for column in report["columns"]}
    assert columns["rate"]["inferred_type"] == "number"
    assert columns["rate"]["numeric_min"] == 1.5
    assert columns["Flow ID"]["identifier_like_by_name"] is True
    assert columns["Label"]["label_counts"] == {"BENIGN": 1}
    assert columns["Timestamp"]["time_min"] == "2024-01-01T00:00:00"
    database.close()


def test_counts_repeated_header_records() -> None:
    database = make_hash_database(":memory:")
    report = audit_csv_stream(
        io.StringIO("a,b\na,b\n1,2\n"),
        display_path="repeated.csv",
        row_hash_sink=database,
    )
    assert report["rows"] == 2
    assert report["repeated_header_rows"] == 1
    database.close()


def test_duplicate_counts_are_scoped_to_header_schema_and_file() -> None:
    database = make_hash_database(":memory:")
    first = io.StringIO("value,label\na,BENIGN\na,BENIGN\n")
    audit_csv_stream(first, display_path="one.csv", row_hash_sink=database)
    second = io.StringIO("value,label\na,BENIGN\n")
    audit_csv_stream(second, display_path="two.csv", row_hash_sink=database)
    third = io.StringIO("other,label\na,BENIGN\n")
    audit_csv_stream(third, display_path="three.csv", row_hash_sink=database)
    summary = duplicate_summary(database)
    assert summary["per_file"]["one.csv"]["duplicate_rows_beyond_first"] == 1
    assert summary["cross_file"]["shared_distinct_row_signatures"] == 1
    database.close()


def test_missing_and_nonfinite_are_counted_separately() -> None:
    database = make_hash_database(":memory:")
    report = audit_csv_stream(
        io.StringIO("metric,label\n,normal\nNaN,attack\nInf,attack\n-3,normal\n"),
        display_path="edge.csv",
        row_hash_sink=database,
    )
    metric = report["columns"][0]
    assert metric["missing"] == 1
    assert metric["nonfinite"] == 2
    assert metric["numeric_min"] == -3
    assert metric["negative_numeric_count"] == 1
    assert report["columns"][1]["label_percentages"] == {"attack": 50.0, "normal": 50.0}
    database.close()


def test_reports_feature_values_equal_to_observed_label_classes() -> None:
    database = make_hash_database(":memory:")
    report = audit_csv_stream(
        io.StringIO("feature,label\nattack,attack\nnormal,normal\n"),
        display_path="labels.csv",
        row_hash_sink=database,
    )
    assert report["columns"][0]["feature_values_matching_label_classes"] == [
        "attack",
        "normal",
    ]
    database.close()
