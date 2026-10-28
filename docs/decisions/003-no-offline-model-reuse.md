# ADR 003: Do not reuse the offline Random Forest on live telemetry

- **Status:** Accepted; ADR 016 adds separate provisional anomaly scoring but does not approve attack classification or reuse the offline model.
- **Context:** The offline RF uses a 77-feature schema; live rule-counter v1 has four features and no established trained artifact.
- **Decision:** Keep live attack classification `UNAVAILABLE` until a compatible artifact is trained and validated from legitimate live-native data. A separately calibrated benign-reference anomaly score may be exposed as such; it must not be represented as attack detection.
- **Alternatives:** Pad, rename, or fabricate the missing features. This creates invalid inputs and misleading predictions.
- **Consequences:** Demo reports abstention. A separate, run-split training/evaluation process must precede live inference.
