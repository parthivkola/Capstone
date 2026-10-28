"""Explicit, deterministic dataset split helpers."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import datetime

import numpy as np
from sklearn.model_selection import train_test_split


@dataclass(frozen=True, slots=True)
class SplitManifest:
    strategy: str
    seed: int | None
    train_indices: tuple[int, ...]
    validation_indices: tuple[int, ...]
    test_indices: tuple[int, ...]
    input_distribution: dict[str, int]
    train_distribution: dict[str, int]
    validation_distribution: dict[str, int]
    test_distribution: dict[str, int]
    notes: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def _distribution(labels: Sequence[str], indices: Sequence[int]) -> dict[str, int]:
    return dict(sorted(Counter(labels[index] for index in indices).items()))


def random_stratified_split(
    labels: Sequence[str], *, seed: int, test_fraction: float = 0.2
) -> SplitManifest:
    """Create a reference random stratified train/test split."""
    if not 0.0 < test_fraction < 1.0:
        raise ValueError("test_fraction must be between 0 and 1")
    indices = np.arange(len(labels))
    train, test = train_test_split(
        indices,
        test_size=test_fraction,
        random_state=seed,
        stratify=np.asarray(labels),
    )
    train_indices = tuple(int(index) for index in train)
    test_indices = tuple(int(index) for index in test)
    return SplitManifest(
        strategy="random_stratified_reference",
        seed=seed,
        train_indices=train_indices,
        validation_indices=(),
        test_indices=test_indices,
        input_distribution=_distribution(labels, tuple(range(len(labels)))),
        train_distribution=_distribution(labels, train_indices),
        validation_distribution={},
        test_distribution=_distribution(labels, test_indices),
        notes=("Reference only; may place related/duplicate flows in both partitions.",),
    )


def source_file_split(
    labels: Sequence[str], sources: Sequence[str], *, held_out_sources: set[str]
) -> SplitManifest:
    """Hold out whole source files; never invent a source grouping."""
    if len(labels) != len(sources):
        raise ValueError("labels and sources must have equal length")
    if not held_out_sources:
        raise ValueError("at least one explicitly held-out source is required")
    observed_sources = set(sources)
    absent = held_out_sources - observed_sources
    if absent:
        raise ValueError(f"held-out source(s) absent from input: {sorted(absent)}")
    train = tuple(i for i, source in enumerate(sources) if source not in held_out_sources)
    test = tuple(i for i, source in enumerate(sources) if source in held_out_sources)
    train_labels = set(_distribution(labels, train))
    test_labels = set(_distribution(labels, test))
    unseen = sorted(test_labels - train_labels)
    return SplitManifest(
        strategy="source_file_holdout",
        seed=None,
        train_indices=train,
        validation_indices=(),
        test_indices=test,
        input_distribution=_distribution(labels, tuple(range(len(labels)))),
        train_distribution=_distribution(labels, train),
        validation_distribution={},
        test_distribution=_distribution(labels, test),
        notes=(
            f"Held out complete source(s): {', '.join(sorted(held_out_sources))}.",
            f"Test labels absent from training: {unseen}.",
        ),
    )


def temporal_split(
    labels: Sequence[str], timestamps: Sequence[str], *, train_fraction: float = 0.8
) -> SplitManifest:
    """Split chronologically using parseable ISO-like timestamps and stable ties."""
    if len(labels) != len(timestamps):
        raise ValueError("labels and timestamps must have equal length")
    if not 0.0 < train_fraction < 1.0:
        raise ValueError("train_fraction must be between 0 and 1")
    parsed: list[tuple[datetime, int]] = []
    for index, value in enumerate(timestamps):
        try:
            parsed.append((datetime.fromisoformat(value.replace("Z", "+00:00")), index))
        except ValueError as error:
            raise ValueError(f"unparseable timestamp at row {index}: {value!r}") from error
    ordered = [index for _, index in sorted(parsed)]
    boundary = int(len(ordered) * train_fraction)
    train, test = tuple(ordered[:boundary]), tuple(ordered[boundary:])
    return SplitManifest(
        strategy="chronological",
        seed=None,
        train_indices=train,
        validation_indices=(),
        test_indices=test,
        input_distribution=_distribution(labels, tuple(range(len(labels)))),
        train_distribution=_distribution(labels, train),
        validation_distribution={},
        test_distribution=_distribution(labels, test),
        notes=("Order is by parsed timestamp, then original row index.",),
    )


def validate_cross_dataset_compatibility(
    train_features: Sequence[str],
    evaluation_features: Sequence[str],
    train_labels: set[str],
    evaluation_labels: set[str],
    *,
    feature_mapping: dict[str, str],
    label_mapping: dict[str, str],
) -> None:
    """Require explicit one-to-one schema and label mappings before transfer evaluation."""
    mapped_features = [feature_mapping.get(name) for name in train_features]
    if any(name is None for name in mapped_features):
        raise ValueError("every training feature needs an explicit cross-dataset mapping")
    if len(set(mapped_features)) != len(mapped_features):
        raise ValueError("cross-dataset feature mapping must be one-to-one")
    if set(mapped_features) != set(evaluation_features):
        raise ValueError("mapped training features do not exactly match evaluation features")
    mapped_labels = {label_mapping.get(label) for label in train_labels}
    if None in mapped_labels or mapped_labels != evaluation_labels:
        raise ValueError("explicit cross-dataset label mapping must exactly cover both label sets")
