# Stage 5B Baseline Evaluation Protocol

## Scope and status

Stage 5B establishes classical reference baselines before graph models. The four datasets remain independent. This protocol does not perform novelty detection, drift adaptation, graph learning, explainability, or mitigation. Stage 5A audit files and raw data are treated as immutable inputs.

The initial executed experiment uses only the UNSW-NB15 official training and testing files. The other dataset conditions are documented as deferred or blocked below; no result is implied for them. The executed pair is the audited `Training and Testing Sets/UNSW_NB15_training-set.csv` and `UNSW_NB15_testing-set.csv`, not the four headerless raw partitions.

## Feature selection and exclusions

Feature eligibility is determined by an explicit name policy and the selected dataset target:

- UNSW target: `attack_cat`, preserved as the 10-class source label. `Normal` is the benign class.
- Exclude target `attack_cat`, alternate target `label`, and row identifier `id`.
- Generic pipeline exclusions include label/class/type/attack names, identifiers, IPs, timestamps, dates, filenames, and source-file identifiers. Do not pass provenance fields into the model.
- UNSW eligible fields are the remaining columns: `dur`, `proto`, `service`, `state`, `spkts`, `dpkts`, `sbytes`, `dbytes`, `rate`, `sttl`, `dttl`, `sload`, `dload`, `sloss`, `dloss`, `sinpkt`, `dinpkt`, `sjit`, `djit`, `swin`, `stcpb`, `dtcpb`, `dwin`, `tcprtt`, `synack`, `ackdat`, `smean`, `dmean`, `trans_depth`, `response_body_len`, `ct_srv_src`, `ct_state_ttl`, `ct_dst_ltm`, `ct_src_dport_ltm`, `ct_dst_sport_ltm`, `ct_dst_src_ltm`, `is_ftp_login`, `ct_ftp_cmd`, `ct_flw_http_mthd`, `ct_src_ltm`, `ct_srv_dst`, and `is_sm_ips_ports`.
- No column is removed based on test statistics. The selected feature list and fitted one-hot feature names are saved in the run artifact.

For CIC-IDS2017, candidate label is `Label`; exclude it, `Flow ID`, `Source IP`, `Destination IP`, and `Timestamp`. For CSE-CIC-IDS2018, candidate label is `Label`; keep files separate and explicitly map the 20-Feb schema before any cross-file analysis. For TON_IoT, candidate binary label is `label`; exclude `type`, IPs, flow/row IDs, timestamps, and filenames. Dataset-specific eligibility remains subject to a checked configuration and schema; the current run does not assert results on these datasets.

## Preprocessing and missing/non-finite policy

The reusable encoder infers numeric versus categorical representation from the training partition only. Empty, documented missing tokens, NaN, and infinities are treated as missing values; rows are retained. Numeric missing values use the training median. Categorical missing values use the training mode. Categorical values are one-hot encoded using a vocabulary fitted on training rows only; categories first seen in validation/test are ignored by the fitted vocabulary. There is no scaling. The runner records the number of affected training rows and values per feature.

The audited official UNSW files contain no missing values according to Stage 5A. The preprocessing path still handles missing and non-finite values, and records its observed training counts. Raw partitions have substantial missingness and are not part of this run. No global row dropping, duplicate removal, or silent coercion is performed. Any future conversion must keep an explicit count of non-finite and unparseable values.

## Split protocols

### Random stratified reference

Use configurable fixed seed `2026`. The reusable helper creates a stratified random split and serializes class distributions. This is a reference baseline only because related flows and duplicates may cross partitions. For the executed UNSW experiment, this split is applied only inside the official training file: 80% fit subset and 20% validation subset. The official testing file is kept entirely held out.

### Source/file-aware

Use whole original source files only where source provenance exists. CIC-IDS2017 ZIP members and CSE-CIC-IDS2018 date files remain separately identifiable. Never synthesize a source-file field when unavailable. Source holdout must report labels present only in test; if the objective is known-class classification, the run is blocked unless all evaluated labels are represented in training or the question is explicitly changed to a held-out-family task. CSE 20-Feb schema differences prevent blind concatenation.

### Temporal

The helper can order parseable timestamps and split earlier rows from later rows. A temporal protocol is enabled only after audit evidence confirms timestamp semantics and timezone/order reliability. The current experiment does not use a temporal split. In particular, do not infer timestamp reliability merely from a column name.

### Cross-dataset

No cross-dataset experiment is executed. A future transfer run requires an explicit intersection/mapping of feature semantics, categorical values, and labels fixed without inspecting test outcomes. It must be labeled generalization evaluation, not an ordinary train/test split. Dataset tables are never merged.

## Labels and baselines

For the UNSW run, Random Forest predicts the original `attack_cat` classes. The binary `label` field is excluded to prevent target leakage. Majority class predicts the most frequent fit-partition class. Isolation Forest is a separately defined benign-versus-attack baseline: fit on `Normal` rows in the fit partition; select a cutpoint from the 5th percentile of benign validation `decision_function` scores; evaluate `Normal` versus `Attack` on the official test set. This threshold uses validation data only.

Random Forest configuration: 100 trees, `max_depth=18`, `max_features="sqrt"`, `min_samples_leaf=2`, `class_weight="balanced_subsample"`, seed 2026, one worker. Class weighting addresses the observed training split imbalance (including `Normal` support 44,800 versus `Worms` support 104); macro and per-class metrics remain primary for interpretation. The maximum depth and leaf size bound fit cost; they were set in response to the first unbounded fit exceeding the local runtime budget, not selected by test performance. No hyperparameter search is performed. XGBoost is not included because it is not installed and is not needed for this stage. Training and inference wall time are recorded where implemented.

## Metrics

Every supervised/multiclass run records accuracy, macro precision, macro recall, macro F1, weighted F1, per-class precision/recall/F1/support, and the labeled confusion matrix. Where `Normal` is identified as benign, report FPR as benign (`Normal`) incorrectly classified as attack divided by benign support, and FNR as attack rows classified as `Normal` divided by all attack support. Binary anomaly evaluation uses the same definitions with `Normal` and `Attack` labels. Accuracy is contextual and is not the selection metric. Timing fields distinguish fit and inference.

## Reproducibility

Configuration lives in `experiments/stage5b/config.json`. Each run JSON records source paths and SHA-256, Stage 5A inventory provenance, exact row indices for fit/validation/test, label distributions, selected/fitted feature names, preprocessing counts and policy, model parameters, package versions, timing, metrics, and duplicate policy. Use `.venv/bin/pip install -e '.[dev,ml]'` to install project and optional scikit-learn dependencies. Re-run with:

```bash
.venv/bin/python scripts/run_stage5b_baselines.py
```

Outputs are written to `experiments/stage5b/unsw-nb15-official-baselines.json`. Raw dataset files must remain unchanged.

## Dataset execution status and limitations

| Dataset | Stage 5B status | Reason / next condition |
| --- | --- | --- |
| UNSW-NB15 official train/test | Executed | Audited 45-column official files, 10-class `attack_cat`; untouched official testing file. |
| CIC-IDS2017 | Deferred | Source-file holdout has attack labels unique to source files; the complete known-class objective is not supported by a simple file holdout. A predeclared reference subset would need a documented row-selection rule and duplicate sensitivity condition. |
| CSE-CIC-IDS2018 | Deferred | Keep 10 files separate; 20-Feb schema differs and labels are source/day concentrated. A source-held-out known-class protocol requires an explicit common feature map and shared label support. |
| TON_IoT | Deferred | Only the public-mirror `train_test_network.csv` artifact is available; internal source split is unverified. A random split is only an IID reference and cannot establish generalization. |
| UNSW-NB15 raw partitions | Not used | Separate from official files; positional headers require verification before feature selection. |

This is a bounded first execution, not a comparison across all four datasets. Stage 5A observed duplicates are reported; no duplicates are removed. Dataset provenance limitations remain as stated in the Stage 5A audit. No result is evidence of security effectiveness, novelty detection, drift handling, or SDN mitigation.
