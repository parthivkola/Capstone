from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

import pytest

from apps.api.project_data import ProjectDataSources


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def test_missing_and_malformed_historical_artifacts_are_reported_not_reconstructed(
    tmp_path: Path,
) -> None:
    source = ProjectDataSources(tmp_path)
    missing = source.historical_results()
    assert missing["records"] == []
    assert len(missing["unavailable_artifacts"]) == 6

    artifact = tmp_path / "experiments/stage5b/unsw-nb15-official-baselines.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("{broken", encoding="utf-8")
    result = ProjectDataSources(tmp_path).historical_results()
    assert not any(row["source_id"] == "unsw-stage5b-baselines" for row in result["records"])
    assert any(
        row["source_id"] == "unsw-stage5b-baselines" for row in result["unavailable_artifacts"]
    )

    write_json(artifact, {"results": None})
    malformed_shape = ProjectDataSources(tmp_path).historical_results()
    assert any(
        row["source_id"] == "unsw-stage5b-baselines"
        for row in malformed_shape["unavailable_artifacts"]
    )


def test_invalid_preparation_manifest_shape_is_unavailable(tmp_path: Path) -> None:
    write_json(
        tmp_path / "experiments/stage5d/cse-preparation.json",
        {"source_statistics": "not-a-list"},
    )
    sources = ProjectDataSources(tmp_path).dataset_sources()
    assert sources["status"] == "UNAVAILABLE"
    assert "must be a list" in sources["reason"]


def make_dataset_source(
    root: Path,
    csv_content: str,
    *,
    labels: list[str] | None = None,
) -> tuple[ProjectDataSources, str, Path]:
    relative = Path("data/processed/stage5d/cse-cic-ids2018/example.model-ready.csv.gz")
    artifact = root / relative
    artifact.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(artifact, "wt", encoding="utf-8", newline="") as stream:
        stream.write(csv_content)
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    stats = {
        "file": "example.csv",
        "output_path": "data/processed/stage5d/cse-cic-ids2018/example.model-ready.csv.gz",
        "output_size_bytes": artifact.stat().st_size,
        "output_sha256": digest,
        "final_usable_row_count": 1,
        "label_vocabulary": labels or ["Benign", "Attack"],
        "feature_count": 1,
        "feature_names": ["feature_x"],
    }
    write_json(root / "experiments/stage5d/cse-preparation.json", {"source_statistics": [stats]})
    return ProjectDataSources(root), "example.csv", artifact


def test_prepared_dataset_preserves_source_label_and_provenance(tmp_path: Path) -> None:
    adapter, file_id, artifact = make_dataset_source(tmp_path, "feature_x,Label\n2.5,Benign\n")
    preview = adapter.dataset_preview(file_id, limit=1)
    record = preview["records"][0]
    assert record["source_label"] == "Benign"
    assert record["prediction"] is None
    assert record["features"] == {"feature_x": 2.5}
    assert record["source_sha256"] == hashlib.sha256(artifact.read_bytes()).hexdigest()
    assert "timestamp" not in record


def test_dataset_row_reads_absolute_file_index(tmp_path: Path) -> None:
    content = "feature_x,Label\n1,Benign\n9,Bot\n"
    adapter, file_id, _artifact = make_dataset_source(
        tmp_path, content, labels=["Benign", "Bot"]
    )
    row = adapter.dataset_row(file_id, 2)
    assert row["row_number"] == 2
    assert row["source_label"] == "Bot"
    assert row["features"] == {"feature_x": 9.0}
    with pytest.raises(ValueError, match="does not contain row"):
        adapter.dataset_row(file_id, 99)


def test_balanced_preview_interleaves_first_benign_and_attack_rows(tmp_path: Path) -> None:
    content = (
        "feature_x,Label\n"
        "1,Benign\n"
        "2,Benign\n"
        "3,Bot\n"
        "4,Benign\n"
        "5,Bot\n"
    )
    adapter, file_id, _artifact = make_dataset_source(
        tmp_path,
        content,
        labels=["Benign", "Bot"],
    )
    preview = adapter.dataset_preview(file_id, limit=4, mix="balanced")
    assert preview["mix"] == "balanced"
    assert [row["row_number"] for row in preview["records"]] == [1, 2, 3, 5]
    assert [row["source_label"] for row in preview["records"]] == [
        "Benign",
        "Benign",
        "Bot",
        "Bot",
    ]


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("wrong,Label\n1,Benign\n", "header does not match"),
        ("feature_x,Label\nNaN,Benign\n", "non-finite"),
        ("feature_x,Label\n1,Unknown\n", "vocabulary"),
        ("feature_x,Label\n1\n", "malformed prepared CSV row"),
    ],
)
def test_prepared_dataset_rejects_malformed_or_untrusted_records(
    tmp_path: Path, content: str, message: str
) -> None:
    adapter, file_id, _artifact = make_dataset_source(tmp_path, content)
    with pytest.raises(ValueError, match=message):
        adapter.dataset_preview(file_id, limit=1)


def test_dataset_source_rejects_unknown_id_bad_limit_and_frozen_hash_mismatch(
    tmp_path: Path,
) -> None:
    adapter, file_id, artifact = make_dataset_source(tmp_path, "feature_x,Label\n1,Benign\n")
    with pytest.raises(ValueError, match="limit"):
        adapter.dataset_preview(file_id, 0)
    with pytest.raises(ValueError, match="unknown"):
        adapter.dataset_preview("../outside.csv")
    artifact.write_bytes(b"changed")
    with pytest.raises(ValueError, match="hash does not match"):
        adapter.dataset_preview(file_id)
