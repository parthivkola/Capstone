"""Safe JSON model contract for offline CSE-CICFlowMeter inference.

The deployable representation contains numeric coefficients only; loading it
does not execute pickle/joblib code. It is intentionally incompatible with the
four-feature live rule-counter contract.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

FEATURE_SCHEMA_ID = "cse-cicflowmeter-77-v1"
FEATURE_SCHEMA_VERSION = 1
MODEL_ID = "cse-cicflowmeter-binary-logistic"
MODEL_VERSION = "1.0.0"
MODEL_ARTIFACT_FORMAT = "sentinel-linear-logistic-json-v1"
LIVE_FEATURE_SCHEMA_ID = "stage7-live-rule-window-v1"


class ModelCompatibilityError(ValueError):
    """The artifact or request does not match the declared model schema."""


@dataclass(frozen=True)
class OfflineLinearModel:
    feature_names: tuple[str, ...]
    means: tuple[float, ...]
    scales: tuple[float, ...]
    coefficients: tuple[float, ...]
    intercept: float
    classes: tuple[str, str]
    model_id: str = MODEL_ID
    version: str = MODEL_VERSION

    @classmethod
    def from_dict(cls, document: object) -> OfflineLinearModel:
        if not isinstance(document, dict):
            raise ModelCompatibilityError("model artifact must be a JSON object")
        if document.get("artifact_format") != MODEL_ARTIFACT_FORMAT:
            raise ModelCompatibilityError("model artifact format is unsupported")
        if document.get("feature_schema_id") != FEATURE_SCHEMA_ID:
            if document.get("feature_schema_id") == LIVE_FEATURE_SCHEMA_ID:
                raise ModelCompatibilityError(
                    "live rule-counter features cannot use this offline model"
                )
            raise ModelCompatibilityError("model feature schema is not supported")
        try:
            names = tuple(document["feature_names"])
            means = tuple(float(item) for item in document["mean"])
            scales = tuple(float(item) for item in document["scale"])
            coefficients = tuple(float(item) for item in document["coefficients"])
            intercept = float(document["intercept"])
            classes = tuple(document["classes"])
        except (KeyError, TypeError, ValueError) as error:
            raise ModelCompatibilityError(f"model artifact fields are invalid: {error}") from error
        count = len(names)
        if (
            count != 77
            or len(set(names)) != count
            or len(means) != count
            or len(scales) != count
            or len(coefficients) != count
            or classes != ("BENIGN", "INTRUSION")
        ):
            raise ModelCompatibilityError("model artifact dimensions or labels are incompatible")
        numbers = (*means, *scales, *coefficients, intercept)
        if not all(math.isfinite(value) for value in numbers) or any(
            value <= 0 for value in scales
        ):
            raise ModelCompatibilityError("model artifact contains invalid numeric state")
        return cls(
            feature_names=names,
            means=means,
            scales=scales,
            coefficients=coefficients,
            intercept=intercept,
            classes=classes,
            model_id=str(document.get("model_id", MODEL_ID)),
            version=str(document.get("version", MODEL_VERSION)),
        )

    def predict(
        self,
        *,
        feature_schema: str,
        feature_order: list[str],
        features: dict[str, Any],
    ) -> dict[str, Any]:
        if feature_schema != FEATURE_SCHEMA_ID:
            raise ModelCompatibilityError(
                f"expected feature schema {FEATURE_SCHEMA_ID}; received {feature_schema}"
            )
        if feature_order != list(self.feature_names):
            raise ModelCompatibilityError("feature_order must exactly match the model schema order")
        missing = [name for name in self.feature_names if name not in features]
        extra = sorted(set(features) - set(self.feature_names))
        if missing or extra:
            raise ModelCompatibilityError(
                f"feature names mismatch; missing={missing[:4]}, unexpected={extra[:4]}"
            )
        values: list[float] = []
        for name in self.feature_names:
            raw_value = features[name]
            if isinstance(raw_value, bool) or not isinstance(raw_value, (int, float)):
                raise ModelCompatibilityError(f"feature {name!r} must be numeric")
            value = float(raw_value)
            if not math.isfinite(value):
                raise ModelCompatibilityError(f"feature {name!r} must be finite")
            values.append(value)
        # Standardized linear terms are exact SHAP values for this logistic model
        # when the background distribution is the training mean used at fit time.
        shap_values = [
            ((value - mean) / scale) * coefficient
            for value, mean, scale, coefficient in zip(
                values, self.means, self.scales, self.coefficients, strict=True
            )
        ]
        base_value = self.intercept
        log_odds_intrusion = base_value + sum(shap_values)
        bounded_log_odds = max(-700.0, min(700.0, log_odds_intrusion))
        intrusion_probability = 1.0 / (1.0 + math.exp(-bounded_log_odds))
        probabilities = {
            "BENIGN": 1.0 - intrusion_probability,
            "INTRUSION": intrusion_probability,
        }
        predicted = "INTRUSION" if intrusion_probability >= 0.5 else "BENIGN"
        direction = 1.0 if predicted == "INTRUSION" else -1.0
        ranked: list[dict[str, Any]] = sorted(
            (
                {
                    "feature": name,
                    "value": value,
                    "shap_value": contribution,
                    "log_odds_contribution_toward_prediction": direction * contribution,
                }
                for name, value, contribution in zip(
                    self.feature_names, values, shap_values, strict=True
                )
            ),
            key=lambda item: abs(item["shap_value"]),
            reverse=True,
        )
        return {
            "predicted_label": predicted,
            "probabilities": probabilities,
            "confidence": probabilities[predicted],
            "confidence_semantics": (
                "Logistic-regression sigmoid score; calibration was not validated."
            ),
            "explanation": {
                "method": "exact linear SHAP / log-odds contributions",
                "shap_compatible": True,
                "shap_note": (
                    "For this standardized linear logistic model, feature attributions "
                    "equal LinearExplainer SHAP values with the training-mean background; "
                    "no sampling approximation is used."
                ),
                "target": "additive contributions to intrusion log-odds",
                "base_value": base_value,
                "prediction_log_odds": log_odds_intrusion,
                "top_features": ranked[:8],
            },
        }
