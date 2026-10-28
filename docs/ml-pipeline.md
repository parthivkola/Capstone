# ML pipeline and schema boundaries

## Offline pipeline

The offline pipeline reads dataset-specific CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15, and TON_IoT data through research scripts under `scripts/` and `ml/`. Dataset schemas and semantics differ; splits, source holds, and protocols are explicit. Existing reports/results are preserved. No output in this implementation pass overwrites the frozen Stage 5 artifacts.

The prior Random Forest studies use offline CICFlowMeter or dataset predictors (77-feature schema in the CSE work). Those features are not inferable from the four OpenFlow rule-counter features. Do not load the offline estimator for live telemetry.

## Live-native contract

Feature schema `live-rule-counter-v1` contains, in order:

1. `packet_count_delta`
2. `byte_count_delta`
3. `packet_rate_per_second`
4. `byte_rate_per_second`

`src/sdn_defense/live_features.py` requires caller-supplied provenance, collection completeness and a positive maximum gap. It rejects resets/decreases, ambiguous wraps, invalid timing, incomplete snapshots and cross-run/epoch evidence. A detector/model implementation and approved artifact are absent. The API and dashboard therefore report `UNAVAILABLE`; confidence is null.

## Application offline inference baseline

`scripts/train_application_model.py` is an explicit opt-in workflow. It uses prepared CSE-CIC-IDS2018 Stage 5D files and the documented CSE-SFH-A source split, reserves Wednesday 14-Feb for validation, and keeps Friday 23-Feb as the test source. It maps the source label `Benign` to `BENIGN` and all other recorded labels to `INTRUSION`. Deterministic per-source/per-class reservoir sampling is disclosed as non-representative. The scaler is fit on train rows only; duplicate sampled records are removed with train > validation > test priority. The output is safe JSON under ignored `var/models/`, not a pickle and not a frozen Stage 5 artifact. The model is offline-only and does not satisfy the live four-feature schema.

When available, `/api/v1/inference/predict` accepts only named values with exact feature-schema ID and feature order. It returns actual logistic-regression prediction and sigmoid score (not calibration-validated), exact linear log-odds contributions, and model/schema provenance. Only explicit trusted JSON under the configured application model path is loaded. Missing or hash-mismatched artifacts disable inference.

## Training and evaluation

There is no honest live-native train/evaluate command yet because no run-labeled data collected under the frozen four-feature contract is available. Do not use a demonstration fixture as training data or label ordinary traffic as attacks. Once approved data exists, use run-level train/validation/test splits, choose thresholds on validation only, and leave test untouched. Record source hashes, whole-run split identity, schema order/version, seed, environment, configuration, and artifact digest. Report per-class precision/recall/F1, macro F1, benign FPR, attack FNR, confusion matrix, coverage, latency, and uncertainty/calibration only where supported.

## Explanations and failure modes

For the current demo, an explanation says that a scenario label is synthetic and no detector evidence exists. It does not invent feature contributions or confidence. The rule-counter feature builder exposes unavailable conditions, not imputed values. A future rule detector must name the actual rule and threshold; a future tree model must use a faithful, tested contribution method. Missing provenance, incomplete multipart collection, epoch ambiguity, unavailable features, or a missing/incompatible model must abstain.
