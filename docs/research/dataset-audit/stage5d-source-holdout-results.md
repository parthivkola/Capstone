# Stage 5D — CSE source-file Random Forest results

**Status:** preflight passed; both frozen source-file holdout Random Forest runs completed. No model other than Random Forest was trained. Stage 5A, 5B, 5C, 5C.1, and 5D-Prep artifacts and raw data were preserved.

## Preflight integrity

The preflight was run before training and repeated immediately before model execution. Both runs passed for all seven prepared files. Artifact SHA-256 digests matched the Stage 5D-Prep manifest. Each file had 77 identical ordered features and exactly one target column (`Label`). Feature values were exhaustively parsed as finite numeric values, then represented uniformly as float32; `Label` remained a string target. The forbidden names were absent from predictor columns. `Label` is necessarily present once as the sole target, as required by the protocol.

Train and test source files were disjoint in both configurations. Every test label had training support. The preflight report is [`cse-preflight.json`](../../../experiments/stage5d/cse-preflight.json).

No fitted feature-preprocessing step was applied: the prepared values are numeric, and parsing to float32 is a fixed type conversion with no data-fitted state. Label integer codes were constructed from training labels only after the support check. The test sources did not influence preprocessing fitting, threshold selection, or model selection.

## Frozen experiment configuration

- Estimator: `sklearn.ensemble.RandomForestClassifier`.
- Seed: `2026`.
- Parameters: 100 trees; maximum depth 18; `max_features="sqrt"`; `min_samples_leaf=2`; `class_weight="balanced_subsample"`; `n_jobs=1`. This matches the Stage 5B RF configuration.
- Input: all model-ready usable rows from the frozen source-file partitions; 77 predictors; `Label` target.
- No random row split, test tuning, imputation, scaling, feature selection, or threshold selection.
- Training and inference timings below measure `.fit` and `.predict`, respectively, excluding CSV-to-array loading. Peak RSS is maximum resident memory for the process, not GPU memory.

## Holdout results

### CSE-SFH-A

Train rows: **13,110,659**; test rows: **1,042,867**; features: **77**.

**Training class distribution:**

- `Benign`: 11,126,732
- `Bot`: 286,191
- `Brute Force -Web`: 249
- `Brute Force -XSS`: 79
- `DDOS attack-HOIC`: 686,012
- `DDOS attack-LOIC-UDP`: 1,730
- `DDoS attacks-LOIC-HTTP`: 576,191
- `DoS attacks-GoldenEye`: 41,508
- `DoS attacks-Slowloris`: 10,990
- `FTP-BruteForce`: 193,354
- `SQL Injection`: 34
- `SSH-Bruteforce`: 187,589

**Test class distribution:**

- `Benign`: 1,042,301
- `Brute Force -Web`: 362
- `Brute Force -XSS`: 151
- `SQL Injection`: 53

| Metric | Value |
|---|---:|
| Accuracy | 0.995351 |
| Macro F1 (supported or predicted labels) | 0.259719 |
| Macro F1 (test-supported labels only) | 0.519438 |
| Macro F1 (all training labels, including unsupported) | 0.173146 |
| Weighted F1 | 0.997353 |
| Benign FPR | 0.004384 |
| Attack FNR as benign | 0.409894 |
| Training time | 3919.73 s |
| Inference time total | 5.10 s |
| Inference time per row | 0.000004893 s |
| Peak process RSS | 5.18 GiB (5,565,132,800 bytes) |

**Per-class metrics:**

| Class | Precision | Recall | F1 | Test support | Predicted count |
|---|---:|---:|---:|---:|---:|
| Benign | 0.999776 | 0.995616 | 0.997692 | 1,042,301 | 1,037,964 |
| Bot | 0.000000 | N/A | 0.000000 | 0 | 1,683 |
| Brute Force -Web | 0.241667 | 0.480663 | 0.321627 | 362 | 720 |
| Brute Force -XSS | 0.505495 | 0.609272 | 0.552553 | 151 | 182 |
| DDOS attack-HOIC | 0.000000 | N/A | 0.000000 | 0 | 456 |
| DDOS attack-LOIC-UDP | N/A | N/A | N/A | 0 | 0 |
| DDoS attacks-LOIC-HTTP | 0.000000 | N/A | 0.000000 | 0 | 586 |
| DoS attacks-GoldenEye | N/A | N/A | N/A | 0 | 0 |
| DoS attacks-Slowloris | 0.000000 | N/A | 0.000000 | 0 | 1,125 |
| FTP-BruteForce | N/A | N/A | N/A | 0 | 0 |
| SQL Injection | 0.139073 | 0.396226 | 0.205882 | 53 | 151 |
| SSH-Bruteforce | N/A | N/A | N/A | 0 | 0 |

**Confusion matrix** (rows are actual labels; columns are predicted labels):

| Actual \ Predicted | Benign | Bot | Brute Force -Web | Brute Force -XSS | DDOS attack-HOIC | DDOS attack-LOIC-UDP | DDoS attacks-LOIC-HTTP | DoS attacks-GoldenEye | DoS attacks-Slowloris | FTP-BruteForce | SQL Injection | SSH-Bruteforce |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Benign | 1,037,732 | 1,660 | 538 | 90 | 456 | 0 | 585 | 0 | 1,125 | 0 | 115 | 0 |
| Bot | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Brute Force -Web | 170 | 4 | 174 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 13 | 0 |
| Brute Force -XSS | 32 | 19 | 6 | 92 | 0 | 0 | 0 | 0 | 0 | 0 | 2 | 0 |
| DDOS attack-HOIC | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| DDOS attack-LOIC-UDP | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| DDoS attacks-LOIC-HTTP | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| DoS attacks-GoldenEye | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| DoS attacks-Slowloris | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| FTP-BruteForce | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| SQL Injection | 30 | 0 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 21 | 0 |
| SSH-Bruteforce | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

Classes with test support and F1 below 0.5 (descriptive flag only): `Brute Force -Web`, `SQL Injection`.

Training classes with neither test support nor predictions are reported with N/A per-class metrics. Predicted-only classes have zero support and their false-positive penalties remain represented in macro-F1.

### CSE-SFH-B

Train rows: **13,110,561**; test rows: **1,042,965**; features: **77**.

**Training class distribution:**

- `Benign`: 11,126,430
- `Bot`: 286,191
- `Brute Force -Web`: 362
- `Brute Force -XSS`: 151
- `DDOS attack-HOIC`: 686,012
- `DDOS attack-LOIC-UDP`: 1,730
- `DDoS attacks-LOIC-HTTP`: 576,191
- `DoS attacks-GoldenEye`: 41,508
- `DoS attacks-Slowloris`: 10,990
- `FTP-BruteForce`: 193,354
- `SQL Injection`: 53
- `SSH-Bruteforce`: 187,589

**Test class distribution:**

- `Benign`: 1,042,603
- `Brute Force -Web`: 249
- `Brute Force -XSS`: 79
- `SQL Injection`: 34

| Metric | Value |
|---|---:|
| Accuracy | 0.990413 |
| Macro F1 (supported or predicted labels) | 0.199560 |
| Macro F1 (test-supported labels only) | 0.399120 |
| Macro F1 (all training labels, including unsupported) | 0.133040 |
| Weighted F1 | 0.994907 |
| Benign FPR | 0.009510 |
| Attack FNR as benign | 0.138122 |
| Training time | 4112.44 s |
| Inference time total | 5.73 s |
| Inference time per row | 0.000005495 s |
| Peak process RSS | 5.18 GiB (5,565,132,800 bytes) |

**Per-class metrics:**

| Class | Precision | Recall | F1 | Test support | Predicted count |
|---|---:|---:|---:|---:|---:|
| Benign | 0.999952 | 0.990490 | 0.995198 | 1,042,603 | 1,032,738 |
| Bot | 0.000000 | N/A | 0.000000 | 0 | 1,632 |
| Brute Force -Web | 0.034429 | 0.791165 | 0.065986 | 249 | 5,722 |
| Brute Force -XSS | 0.335000 | 0.848101 | 0.480287 | 79 | 200 |
| DDOS attack-HOIC | 0.000000 | N/A | 0.000000 | 0 | 639 |
| DDOS attack-LOIC-UDP | N/A | N/A | N/A | 0 | 0 |
| DDoS attacks-LOIC-HTTP | 0.000000 | N/A | 0.000000 | 0 | 599 |
| DoS attacks-GoldenEye | N/A | N/A | N/A | 0 | 0 |
| DoS attacks-Slowloris | 0.000000 | N/A | 0.000000 | 0 | 960 |
| FTP-BruteForce | N/A | N/A | N/A | 0 | 0 |
| SQL Injection | 0.029474 | 0.411765 | 0.055010 | 34 | 475 |
| SSH-Bruteforce | N/A | N/A | N/A | 0 | 0 |

**Confusion matrix** (rows are actual labels; columns are predicted labels):

| Actual \ Predicted | Benign | Bot | Brute Force -Web | Brute Force -XSS | DDOS attack-HOIC | DDOS attack-LOIC-UDP | DDoS attacks-LOIC-HTTP | DoS attacks-GoldenEye | DoS attacks-Slowloris | FTP-BruteForce | SQL Injection | SSH-Bruteforce |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Benign | 1,032,688 | 1,618 | 5,519 | 127 | 639 | 0 | 597 | 0 | 960 | 0 | 455 | 0 |
| Bot | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Brute Force -Web | 29 | 12 | 197 | 4 | 0 | 0 | 2 | 0 | 0 | 0 | 5 | 0 |
| Brute Force -XSS | 8 | 2 | 1 | 67 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| DDOS attack-HOIC | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| DDOS attack-LOIC-UDP | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| DDoS attacks-LOIC-HTTP | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| DoS attacks-GoldenEye | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| DoS attacks-Slowloris | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| FTP-BruteForce | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| SQL Injection | 13 | 0 | 5 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 14 | 0 |
| SSH-Bruteforce | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

Classes with test support and F1 below 0.5 (descriptive flag only): `Brute Force -Web`, `Brute Force -XSS`, `SQL Injection`.

Training classes with neither test support nor predictions are reported with N/A per-class metrics. Predicted-only classes have zero support and their false-positive penalties remain represented in macro-F1.

## Averaging and false-rate definitions

Primary macro precision/recall/F1 are averaged over the union of classes with test support or at least one prediction. This includes predicted-only classes (which have zero support) so their false-positive predictions are visible, and excludes classes neither present nor predicted. The report also provides macro-F1 on test-supported classes only and on the complete training label vocabulary to make the denominator effect explicit. Weighted F1 is weighted by test support.

`Benign FPR` = benign test rows predicted as any attack class divided by benign test rows. `Attack FNR as benign` = attack test rows predicted as benign divided by all attack test rows. These are binary benign-versus-attack views of the multiclass confusion matrix.

## Generalization observations

The reciprocal source-file holdouts show high overall accuracy and weighted F1 alongside much lower macro-F1, reflecting class imbalance and minority-class errors. The held-out attack labels have training support, but some are represented by very few training examples. In A, supported test classes with F1 below 0.5 are Web brute force and SQL injection; in B, Web brute force, XSS brute force, and SQL injection are below 0.5. These observations describe this RF and these splits; they do not establish general security effectiveness.

No within-source reference split is defined by the frozen Stage 5C.1 protocol, and random row splitting is disallowed here. Therefore a source-file generalization gap is not computed.

### Separate UNSW-NB15 reference

Stage 5B reported an UNSW-NB15 official-pair RF accuracy of 0.674124 and macro-F1 of 0.487591. These figures are only a separate-dataset reference. They are not directly comparable to CSE-CIC-IDS2018 because the dataset, features, labels, source structure, and split protocol differ. No cross-dataset performance claim is made.

## GPU note

This run used scikit-learn RF on CPU, matching the Stage 5B estimator implementation. The machine exposes an NVIDIA GeForce GTX 1650 with 4 GiB VRAM, but `cuml`, `cudf`, and `torch` were not installed, and no compatible GPU RF backend was available. The GPU remained unused; the model/configuration was not changed to force GPU execution.

## Reproducibility

Run from the repository root:

```bash
.venv/bin/python scripts/run_stage5d_cse_rf.py
```

The script reruns preflight and exits before training if any integrity condition fails. Full run results, preflight details, configuration, and environment remain in [`cse-source-holdout-rf.json`](../../../experiments/stage5d/cse-source-holdout-rf.json).
