"""Tests for Stage 5C read-only schema compatibility decisions."""

from __future__ import annotations

from ml.datasets.schema_compatibility import (
    common_schema_assessment,
    compare_schema,
    normalize_column_name,
)


def _schema(path: str, columns: list[tuple[str, str]], labels: dict[str, int]) -> dict[str, object]:
    return {
        "path": path,
        "columns": [
            {
                "name": name,
                "inferred_type": inferred,
                "label_counts": labels if name == "Label" else None,
            }
            for name, inferred in columns
        ],
        "label_columns": ["Label"],
    }


def test_normalization_compares_formatting_without_changing_original_names() -> None:
    assert normalize_column_name("Flow Byts/b Avg") == "flow_byts_b_avg"
    assert normalize_column_name("  FLOW   BYTS/b AVG ") == "flow_byts_b_avg"


def test_february_schema_additions_and_type_differences_are_explicit() -> None:
    standard = _schema(
        "standard.csv",
        [("Dst Port", "integer"), ("Flow Byts/s", "number"), ("Label", "string/category")],
        {"Benign": 10, "Attack": 2},
    )
    feb = _schema(
        "feb20.csv",
        [
            ("Flow ID", "string/category"),
            ("Dst Port", "integer"),
            ("Flow Byts/s", "number"),
            ("Label", "string/category"),
        ],
        {"Benign": 9, "Other": 3},
    )
    result = compare_schema(standard, feb)
    assert result["columns_only_in_candidate"] == ["Flow ID"]
    assert result["columns_missing_from_candidate"] == []
    assert result["same_name_type_mismatches"] == {}
    assert result["label_column_difference"] is False
    assert result["label_vocabulary_difference"] is True
    assert result["common_columns_same_relative_order"] is True


def test_common_schema_is_blocked_on_type_disagreement() -> None:
    clean = _schema(
        "clean.csv",
        [("Flow Byts/s", "number"), ("Label", "string/category")],
        {"Benign": 4},
    )
    repeated_header = _schema(
        "header-row.csv",
        [("Flow Byts/s", "mixed"), ("Label", "string/category")],
        {"Benign": 3, "Label": 1},
    )
    assessment = common_schema_assessment(
        [clean, repeated_header], excluded_from_features={"Label"}
    )
    assert assessment["ordered_common_columns"] == ["Flow Byts/s", "Label"]
    assert assessment["inferred_type_disagreements"] == {
        "Flow Byts/s": {"clean.csv": "number", "header-row.csv": "mixed"}
    }
    assert (
        assessment["formal_compatibility_status"]
        == "blocked_pending_data_quality_and_semantic_review"
    )


def test_integer_and_float_inference_are_both_numeric_but_mixed_is_not() -> None:
    integer = _schema(
        "integer.csv", [("metric", "integer"), ("Label", "string/category")], {"Benign": 1}
    )
    floating = _schema(
        "float.csv", [("metric", "number"), ("Label", "string/category")], {"Benign": 1}
    )
    assessment = common_schema_assessment([integer, floating], excluded_from_features={"Label"})
    assert assessment["inferred_type_disagreements"] == {}
    assert "metric" in assessment["inferred_type_variants"]
