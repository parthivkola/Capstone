"""Leakage, split, labels, and metric checks for Stage 5B evaluation."""

from __future__ import annotations

import pytest

from ml.evaluation.baselines import (
    TrainOnlyTabularEncoder,
    evaluate_predictions,
    is_excluded_feature,
    majority_predictions,
)
from ml.evaluation.splits import (
    random_stratified_split,
    source_file_split,
    temporal_split,
    validate_cross_dataset_compatibility,
)


def test_random_stratified_split_is_seeded_and_records_distributions() -> None:
    labels = ["normal"] * 20 + ["attack"] * 10
    first = random_stratified_split(labels, seed=19)
    second = random_stratified_split(labels, seed=19)
    assert first == second
    assert first.train_distribution == {"attack": 8, "normal": 16}
    assert first.test_distribution == {"attack": 2, "normal": 4}


def test_source_split_holds_complete_files_and_reports_unseen_labels() -> None:
    labels = ["benign", "attack-a", "benign", "attack-b"]
    sources = ["day1.csv", "day1.csv", "day2.csv", "day2.csv"]
    manifest = source_file_split(labels, sources, held_out_sources={"day2.csv"})
    assert manifest.train_indices == (0, 1)
    assert manifest.test_indices == (2, 3)
    assert "['attack-b']" in manifest.notes[1]
    with pytest.raises(ValueError, match="absent"):
        source_file_split(labels, sources, held_out_sources={"missing.csv"})


def test_temporal_split_orders_timestamps_and_rejects_untrusted_parse() -> None:
    manifest = temporal_split(
        ["later", "earlier", "middle"],
        ["2024-01-03T00:00:00", "2024-01-01T00:00:00", "2024-01-02T00:00:00"],
        train_fraction=2 / 3,
    )
    assert manifest.train_indices == (1, 2)
    assert manifest.test_indices == (0,)
    with pytest.raises(ValueError, match="unparseable"):
        temporal_split(["a"], ["unknown"])


def test_encoder_fits_medians_and_vocabulary_on_training_only() -> None:
    training = [
        {"measure": "1", "service": "http", "id": "1", "label": "Normal"},
        {"measure": "3", "service": "http", "id": "2", "label": "Normal"},
        {"measure": "", "service": "dns", "id": "3", "label": "Attack"},
    ]
    encoder = TrainOnlyTabularEncoder().fit(training)
    assert encoder.vectorizer_ is not None
    assert encoder.numeric_medians_ == {"measure": 2.0}
    assert encoder.feature_names_ == ("measure", "service")
    assert "service=unseen" not in encoder.vectorizer_.get_feature_names_out()
    transformed = encoder.transform([{"measure": "NaN", "service": "unseen", "id": "999"}])
    assert transformed.shape[0] == 1
    assert transformed[0, encoder.vectorizer_.vocabulary_["measure"]] == 2.0


def test_majority_and_metrics_preserve_class_labels_and_report_support() -> None:
    assert majority_predictions(["Normal", "Normal", "Attack"], 2) == ["Normal", "Normal"]
    metrics = evaluate_predictions(
        ["Normal", "Attack", "Attack"],
        ["Attack", "Attack", "Normal"],
        class_labels=["Normal", "Attack"],
    )
    assert metrics["accuracy"] == pytest.approx(1 / 3)
    assert metrics["classes"]["Normal"]["support"] == 1
    assert metrics["classes"]["Attack"]["support"] == 2
    assert metrics["confusion_matrix"] == [[0, 1], [1, 1]]
    assert metrics["false_positive_rate_benign_as_attack"] == 1.0
    assert metrics["false_negative_rate_attack_as_benign"] == 0.5


def test_identifier_and_attack_name_features_are_excluded() -> None:
    for name in ("Flow ID", "Source IP", "Timestamp", "attack_name", "Label"):
        assert is_excluded_feature(name)
    assert not is_excluded_feature("service")


def test_cross_dataset_requires_explicit_compatible_feature_and_label_maps() -> None:
    validate_cross_dataset_compatibility(
        ["bytes", "protocol"],
        ["octets", "proto"],
        {"Normal", "Attack"},
        {"benign", "malicious"},
        feature_mapping={"bytes": "octets", "protocol": "proto"},
        label_mapping={"Normal": "benign", "Attack": "malicious"},
    )
    with pytest.raises(ValueError, match="explicit"):
        validate_cross_dataset_compatibility(
            ["bytes"],
            ["octets"],
            {"Normal"},
            {"Normal"},
            feature_mapping={},
            label_mapping={},
        )
