# Stage 5E.2C — CSE RF confidence-based open-set rejection

**Scope:** one confidence-based open-set mechanism under the frozen CSE-CIC-IDS2018 Tuesday source-held-out LOIC-HTTP condition. This is an empirical test, not an assumption that rejection will help or a general zero-day claim.

## Preflight and partitions

- Stage 5D prepared-data integrity preflight: passed before training.
- Training sources: six non-Tuesday sources; Tuesday is test-only.
- RF training rows: 5,011,394.
- Validation rows: 1,252,837; benign validation rows: 971,183.
- Tuesday test rows: 7,889,295.
- Attack rows in six training sources excluded from threshold calibration: 1,408,302. These attack rows remain eligible for supervised RF fitting when assigned to the training partition.
- Attack rows held out in validation and excluded from RF fitting: 281,654. Only benign validation probabilities select thresholds.
- LOIC-HTTP absent from training vocabulary: True.
- Predictors: 77 frozen ordered float32 features.
- Preprocessing: fixed Stage 5D CSV-to-float32 cast; no fitted preprocessing.

The deterministic validation split selects an exact 20% of row ordinals without replacement within each source and training class. The remaining rows fit the RF. Only benign validation `p_max` values select rejection thresholds; validation attack rows do not determine thresholds. Tuesday labels are not inputs to fitting, validation, threshold selection, or model selection.

## Frozen Random Forest configuration

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

## Confidence and threshold protocol

For each flow, `p_max` is the largest RF class probability. If `p_max < threshold`, the output is UNKNOWN; otherwise the RF argmax class is retained. Low confidence is tested as a rejection signal and is not assumed to imply novelty.

Thresholds use benign validation probabilities only. For each target, the selected confidence group boundary gives the closest attainable benign rejection count; confidence ties are indivisible and ties in distance choose fewer rejections. The primary operating point was preregistered at 1%.

Primary threshold: **0.474534474462**; realized validation benign rejection: **0.991986%**.

## Primary 1% results

Benign test rows: 7,313,104; LOIC-HTTP test rows: 576,191.

| Metric | Result |
|---|---:|
| Benign rejection / FPR | 1.309813% |
| LOIC-HTTP unknown recall | 0.053628% |
| LOIC-HTTP known rate | 99.946372% |
| Unknown precision | 0.321550% |
| Unknown F1 | 0.000919 |
| Balanced accuracy | 0.493719 |

### Counts and confusion matrix

- Benign known: 7,217,316; benign UNKNOWN: 95,788.
- LOIC-HTTP known: 575,882; LOIC-HTTP UNKNOWN: 309.

| Actual \ Predicted | Known | Unknown |
|---|---:|---:|
| Benign | 7,217,316 | 95,788 |
| LOIC-HTTP | 575,882 | 309 |

### LOIC-HTTP flows retained as known

| RF predicted known class | Count |
|---|---:|
| Benign | 575,095 |
| Bot | 0 |
| Brute Force -Web | 0 |
| Brute Force -XSS | 0 |
| DDOS attack-HOIC | 0 |
| DDOS attack-LOIC-UDP | 787 |
| DoS attacks-GoldenEye | 0 |
| DoS attacks-Slowloris | 0 |
| FTP-BruteForce | 0 |
| SQL Injection | 0 |
| SSH-Bruteforce | 0 |

## Sensitivity by benign rejection operating point

Tuesday was evaluated once after thresholds were frozen. All operating points use the same test probability stream.

| Target benign rejection | Threshold | Validation benign rejection | Test benign rejection | LOIC-HTTP unknown recall | Unknown precision | Unknown F1 | Balanced accuracy |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 0.5% | 0.459878341575 | 0.491565% | 0.932504% | 0.034884% | 0.293877% | 0.000624 | 0.495512 |
| 1% | 0.474534474462 | 0.991986% | 1.309813% | 0.053628% | 0.321550% | 0.000919 | 0.493719 |
| 2% | 0.499609728416 | 1.992004% | 2.190424% | 0.092157% | 0.330390% | 0.001441 | 0.489509 |
| 5% | 0.653569967995 | 4.998234% | 5.537539% | 0.142140% | 0.201831% | 0.001668 | 0.473023 |

## Context against frozen baselines

Stage 5E.2A is a closed-set RF with no UNKNOWN/reject class; consequently every LOIC-HTTP flow received a known-class prediction. It assigned 575,402 of 576,191 flows (99.8631%) to Benign.

Stage 5E.2B is the benign-only Isolation Forest. At its primary 1% validation operating point, LOIC-HTTP unknown recall was 0.000000%.

These are contextual comparisons of the targeted unknown-rejection behavior, not directly comparable accuracy models. No superiority is assumed or claimed.

## Timing and reproducibility

- Training: 1470.322 seconds.
- Validation inference (`predict_proba` only): 5.261 seconds.
- Tuesday inference (`predict_proba` only): 31.572 seconds; 0.000004002 seconds per test row.
- Peak process RSS: 2,401,521,664 bytes.
- Seed: 2026; environment versions and source hashes are recorded in the companion JSON.

## Limitations

This evaluates one confidence-based rejection mechanism on one CSE-CIC-IDS2018 unseen source/class condition. Confidence can be high for unseen behavior; these results do not establish general unseen-attack detection. The within-source validation partition calibrates a benign rejection rate and is not a separate source-generalization test.
