# Stage 5E.2A — CSE Tuesday-20-02 closed-set RF baseline

**Condition:** closed-set unseen-class/source baseline. This is not novelty detection.

## Preflight and split

- Stage 5D artifact preflight: **passed**.
- Training sources: Friday-02-03-2018_TrafficForML_CICFlowMeter.csv, Friday-23-02-2018_TrafficForML_CICFlowMeter.csv, Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv, Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv, Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv, Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv.
- Test source: `Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv`.
- Source-disjoint: **True**.
- Rows: 6,264,231 train; 7,889,295 test.
- Predictors: 77 frozen Stage 5D features.
- Training label vocabulary (11): `Benign`, `Bot`, `Brute Force -Web`, `Brute Force -XSS`, `DDOS attack-HOIC`, `DDOS attack-LOIC-UDP`, `DoS attacks-GoldenEye`, `DoS attacks-Slowloris`, `FTP-BruteForce`, `SQL Injection`, `SSH-Bruteforce`.
- `DDoS attacks-LOIC-HTTP` absent from training: **True**; test support: **576,191**.

## Frozen RF configuration

```json
{
  "name": "RandomForestClassifier",
  "n_estimators": 100,
  "max_depth": 18,
  "max_features": "sqrt",
  "min_samples_leaf": 2,
  "class_weight": "balanced_subsample",
  "random_state": 2026,
  "n_jobs": 1
}
```

Feature handling uses the frozen Stage 5D numeric CSV-to-float32 cast, with no fitted preprocessing. Label codes come from training-source labels only. Tuesday rows are read in chunks for inference; test labels are used only for evaluation. No threshold or hyperparameter was selected on Tuesday.

## Metrics

Macro F1 is averaged over the **2 distinct labels present in the test source**, including LOIC-HTTP. The unseen class receives F1 0 because no output class can represent it.

| Metric | Value |
|---|---:|
| Accuracy | 0.907355 |
| Macro F1 (test-supported classes) | 0.475739 |
| Weighted F1 | 0.881987 |
| Benign FPR | 0.021156 |
| Attack FNR as Benign | 0.998631 |

### Per-test-class metrics

| Test class | Support | Predicted support | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|
| Benign | 7,313,104 | 7,733,793 | 0.925599 | 0.978844 | 0.951477 |
| DDoS attacks-LOIC-HTTP | 576,191 | 0 | 0.000000 | 0.000000 | 0.000000 |

### LOIC-HTTP assignment to known classes

The classifier has no unknown/reject output. Every test LOIC-HTTP flow is therefore assigned to a known training class.

| Predicted known class | Count | Rate among LOIC-HTTP test flows |
|---|---:|---:|
| Benign | 575,402 | 0.998631 |
| Bot | 0 | 0.000000 |
| Brute Force -Web | 2 | 0.000003 |
| Brute Force -XSS | 0 | 0.000000 |
| DDOS attack-HOIC | 0 | 0.000000 |
| DDOS attack-LOIC-UDP | 787 | 0.001366 |
| DoS attacks-GoldenEye | 0 | 0.000000 |
| DoS attacks-Slowloris | 0 | 0.000000 |
| FTP-BruteForce | 0 | 0.000000 |
| SQL Injection | 0 | 0.000000 |
| SSH-Bruteforce | 0 | 0.000000 |

## Confusion matrix

Rows are actual labels; columns are predicted labels. The test-only LOIC-HTTP column is zero because it is not in the model vocabulary.

| Actual \ Predicted | Benign | Bot | Brute Force -Web | Brute Force -XSS | DDOS attack-HOIC | DDOS attack-LOIC-UDP | DDoS attacks-LOIC-HTTP | DoS attacks-GoldenEye | DoS attacks-Slowloris | FTP-BruteForce | SQL Injection | SSH-Bruteforce |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Benign | 7,158,391 | 9,156 | 88,732 | 4,349 | 3,426 | 0 | 0 | 42 | 9,340 | 32 | 39,626 | 10 |
| Bot | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Brute Force -Web | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Brute Force -XSS | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| DDOS attack-HOIC | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| DDOS attack-LOIC-UDP | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| DDoS attacks-LOIC-HTTP | 575,402 | 0 | 2 | 0 | 0 | 787 | 0 | 0 | 0 | 0 | 0 | 0 |
| DoS attacks-GoldenEye | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| DoS attacks-Slowloris | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| FTP-BruteForce | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| SQL Injection | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| SSH-Bruteforce | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

## Timing and memory

- Training: 1985.105 seconds.
- Inference (`predict` calls only): 35.292 seconds total; 0.000004473 seconds per test flow.
- Peak process RSS: 2,556,522,496 bytes. process peak RSS from getrusage; includes preflight and data loading, not GPU memory.

## Context against frozen Stage 5D

The Stage 5D A/B metrics are separate context only. They test known classes on different held-out sources, while this run holds out a source containing a class absent from training. They are not a direct performance comparison; no causal interpretation is made.

| Frozen Stage 5D run | Accuracy | Test-supported macro F1 | Weighted F1 |
|---|---:|---:|---:|
| CSE-SFH-A (separate known-class protocol) | 0.995351 | 0.519438 | 0.997353 |
| CSE-SFH-B (separate known-class protocol) | 0.990413 | 0.399120 | 0.994907 |

## Interpretation limits

This result measures how the frozen closed-set Random Forest assigns a source-held-out, training-unsupported class among known outputs. It does not measure novelty detection, unknown rejection, security effectiveness, or causal effects of training support.

## Reproducibility

Python 3.11.16; NumPy 2.4.6; scikit-learn 1.9.1. Prepared artifact SHA-256 values and the full configuration are recorded in the companion JSON.
