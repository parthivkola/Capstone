"""Fail-closed feature parity checks for prospective live detector inputs.

This module describes compatibility; it does not extract features, fit a model,
or invoke a detector.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any


class FeatureParityStatus(StrEnum):
    """Relationship between a model feature and the current live contract."""

    EXACT = "EXACT"
    DERIVABLE = "DERIVABLE"
    APPROXIMATION_REQUIRED = "APPROXIMATION_REQUIRED"
    UNAVAILABLE = "UNAVAILABLE"
    SEMANTICALLY_INCOMPATIBLE = "SEMANTICALLY_INCOMPATIBLE"


@dataclass(frozen=True, slots=True)
class FeatureCompatibility:
    """One model-feature parity assessment."""

    feature: str
    status: FeatureParityStatus
    live_fields: tuple[str, ...]
    reason: str


class FeatureParityError(ValueError):
    """Raised when live observations cannot supply a model's full input schema."""


def load_feature_matrix(path: str | Path) -> tuple[FeatureCompatibility, ...]:
    """Load and structurally validate the machine-readable compatibility matrix."""

    with Path(path).open(encoding="utf-8") as stream:
        payload: Any = json.load(stream)
    if not isinstance(payload, dict):
        raise ValueError("feature compatibility matrix must be a JSON object")
    rows = payload.get("feature_compatibility")
    if not isinstance(rows, list) or not rows:
        raise ValueError("feature_compatibility must be a non-empty list")

    result: list[FeatureCompatibility] = []
    names: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("each feature compatibility row must be an object")
        feature = row.get("feature")
        status = row.get("status")
        live_fields = row.get("live_fields")
        reason = row.get("reason")
        if (
            not isinstance(feature, str)
            or not feature
            or feature in names
            or not isinstance(live_fields, list)
            or any(not isinstance(field, str) for field in live_fields)
            or not isinstance(reason, str)
            or not reason
        ):
            raise ValueError("feature compatibility row has invalid or duplicate fields")
        if not isinstance(status, str):
            raise ValueError(f"invalid parity status for {feature!r}")
        try:
            parsed_status = FeatureParityStatus(status)
        except ValueError as exc:
            raise ValueError(f"invalid parity status for {feature!r}") from exc
        names.add(feature)
        result.append(
            FeatureCompatibility(feature, parsed_status, tuple(live_fields), reason)
        )

    summary = payload.get("summary")
    if not isinstance(summary, dict):
        raise ValueError("matrix summary must be an object")
    observed = {status.value: 0 for status in FeatureParityStatus}
    for row in result:
        observed[row.status.value] += 1
    if summary != observed:
        raise ValueError("matrix summary does not match feature rows")
    return tuple(result)


def live_inference_blockers(
    matrix: tuple[FeatureCompatibility, ...],
) -> tuple[FeatureCompatibility, ...]:
    """Return features that cannot be supplied with unchanged semantics."""

    return tuple(
        item
        for item in matrix
        if item.status not in (FeatureParityStatus.EXACT, FeatureParityStatus.DERIVABLE)
    )


def require_live_inference_compatible(
    matrix: tuple[FeatureCompatibility, ...],
) -> None:
    """Fail closed unless every model feature has exact or deterministic parity."""

    blockers = live_inference_blockers(matrix)
    if blockers:
        details = ", ".join(f"{item.feature}={item.status.value}" for item in blockers)
        message = f"live inference is not authorized; incompatible features: {details}"
        raise FeatureParityError(message)
