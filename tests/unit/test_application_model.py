from __future__ import annotations

from typing import Any

import pytest

from ml.models.application_linear import (
    FEATURE_SCHEMA_ID,
    LIVE_FEATURE_SCHEMA_ID,
    MODEL_ARTIFACT_FORMAT,
    ModelCompatibilityError,
    OfflineLinearModel,
)


def model_document() -> dict[str, Any]:
    names = [f"feature_{index}" for index in range(77)]
    coefficients = [0.0] * 77
    coefficients[0] = 1.0
    return {
        "artifact_format": MODEL_ARTIFACT_FORMAT,
        "feature_schema_id": FEATURE_SCHEMA_ID,
        "feature_names": names,
        "mean": [0.0] * 77,
        "scale": [1.0] * 77,
        "coefficients": coefficients,
        "intercept": 0.0,
        "classes": ["BENIGN", "INTRUSION"],
    }


def test_safe_linear_model_prediction_and_contributions() -> None:
    document = model_document()
    model = OfflineLinearModel.from_dict(document)
    output = model.predict(
        feature_schema=FEATURE_SCHEMA_ID,
        feature_order=document["feature_names"],
        features={**dict.fromkeys(document["feature_names"], 0.0), "feature_0": 2.0},
    )
    assert output["predicted_label"] == "INTRUSION"
    assert output["confidence"] > 0.5
    assert output["explanation"]["shap_compatible"] is True
    assert output["explanation"]["base_value"] == 0.0
    assert output["explanation"]["top_features"][0]["feature"] == "feature_0"
    assert output["explanation"]["top_features"][0]["shap_value"] == 2.0


@pytest.mark.parametrize(
    ("schema", "order", "features"),
    [
        (
            LIVE_FEATURE_SCHEMA_ID,
            [f"feature_{i}" for i in range(77)],
            dict.fromkeys([f"feature_{i}" for i in range(77)], 0.0),
        ),
        (
            FEATURE_SCHEMA_ID,
            [f"feature_{i}" for i in reversed(range(77))],
            dict.fromkeys([f"feature_{i}" for i in range(77)], 0.0),
        ),
        (FEATURE_SCHEMA_ID, [f"feature_{i}" for i in range(77)], {"feature_0": 0.0}),
        (
            FEATURE_SCHEMA_ID,
            [f"feature_{i}" for i in range(77)],
            {**dict.fromkeys([f"feature_{i}" for i in range(77)], 0.0), "feature_0": float("nan")},
        ),
    ],
)
def test_model_fails_closed_on_incompatible_requests(
    schema: str, order: list[str], features: dict[str, Any]
) -> None:
    model = OfflineLinearModel.from_dict(model_document())
    with pytest.raises(ModelCompatibilityError):
        model.predict(feature_schema=schema, feature_order=order, features=features)


def test_artifact_rejects_live_schema_and_nonfinite_weights() -> None:
    live = model_document()
    live["feature_schema_id"] = LIVE_FEATURE_SCHEMA_ID
    with pytest.raises(ModelCompatibilityError, match="live rule-counter"):
        OfflineLinearModel.from_dict(live)
    bad = model_document()
    bad["scale"][0] = 0
    with pytest.raises(ModelCompatibilityError):
        OfflineLinearModel.from_dict(bad)
