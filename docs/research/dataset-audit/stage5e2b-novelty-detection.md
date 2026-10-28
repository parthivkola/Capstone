# Stage 5E.2B — explicit novelty detection for CSE LOIC-HTTP

**Status:** validation-calibrated Isolation Forest; Tuesday-20-02 is the test source.

## Preflight and data partitions

- Frozen prepared-data integrity preflight: passed before model fitting.
- Training/validation sources: six non-Tuesday prepared CSE files, each with deterministic per-source benign row partitioning.
- Model-fit rows: 3,884,746 benign flows.
- Threshold-validation rows: 971,183 benign flows.
- Tuesday test rows: 7,889,295 flows.
- Tuesday excluded from fit and threshold selection: True.
- LOIC-HTTP used in fit: False.
- Frozen predictors: 77 ordered float32 features.

The validation partition is a seeded exact 20% sample of benign row ordinals without replacement within each source file. The remaining benign rows from those same six sources fit the detector. Attack rows are ignored; their labels are not supplied to `IsolationForest.fit`. Tuesday remains untouched until final scoring.

## Isolation Forest configuration

```json
{
  "name": "IsolationForest",
  "n_estimators": 100,
  "max_samples": 256,
  "contamination": "auto",
  "max_features": 1.0,
  "bootstrap": false,
  "random_state": 2026,
  "n_jobs": 1
}
```

The configuration follows the project's existing Isolation Forest baseline (100 trees, contamination `auto`, seed 2026, one job); `max_samples=256` states the existing sklearn `auto` sample count explicitly for this dataset size. `contamination=auto` does not set the final decision threshold. The runner uses `score_samples` and its own validation-selected cutpoints.

### Score orientation and threshold selection

`IsolationForest.score_samples` is lower for more anomalous records. The novelty score is its negation, so higher scores mean more novel behavior. The decision is `novelty_score >= threshold → UNKNOWN`; otherwise the flow is KNOWN.

Thresholds are selected only from benign validation novelty scores. For each predeclared target, the runner chooses the attainable score-group boundary nearest the requested rejection count; ties choose the lower realized validation FPR. Equal scores are indivisible, so the realized validation FPR can differ slightly from target.

Primary pre-registered operating point: **1% benign FPR**; selected threshold: **0.62591420546**. Validation benign rows: 971,183; validation unknown count: 9,712; realized validation FPR: 1.000018%.

## Primary 1% operating-point results

Test benign rows: 7,313,104; test LOIC-HTTP rows: 576,191.

| Metric | Result |
|---|---:|
| Benign FPR / rejection rate | 1.079145% |
| LOIC-HTTP unknown recall | 0.000000% |
| Unknown precision | 0.000000% |
| Unknown F1 | 0.000000 |
| Balanced accuracy | 0.494604 |

### Counts and 2×2 confusion matrix

- Benign known: 7,234,185; benign UNKNOWN: 78,919.
- LOIC-HTTP known: 576,191; LOIC-HTTP UNKNOWN: 0.

| Actual \ Predicted | Known | Unknown |
|---|---:|---:|
| Benign | 7,234,185 | 78,919 |
| LOIC-HTTP | 576,191 | 0 |

## Operating-point sensitivity

Each threshold below was independently selected on the same benign validation partition. Tuesday was scored once, and all operating points used the same scores.

| Target validation benign FPR | Threshold | Validation FPR | Test benign FPR | LOIC unknown recall | Unknown precision | Unknown F1 | Balanced accuracy |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 0.5% | 0.653823938992 | 0.500009% | 0.497614% | 0.000000% | 0.000000% | 0.000000 | 0.497512 |
| 1% | 0.62591420546 | 1.000018% | 1.079145% | 0.000000% | 0.000000% | 0.000000 | 0.494604 |
| 2% | 0.594983080931 | 2.000035% | 3.617561% | 0.000000% | 0.000000% | 0.000000 | 0.481912 |
| 5% | 0.537100470929 | 4.999985% | 6.929629% | 0.122008% | 0.138529% | 0.001297 | 0.465962 |

## Context against Stage 5E.2A

Stage 5E.2A is a closed-set classifier with no unknown/reject class. Therefore every LOIC-HTTP flow necessarily received a known-class prediction. Stage 5E.2B adds an explicit UNKNOWN decision. These are not directly comparable accuracy models; this report uses 5E.2A only as context and makes no superiority claim.

Stage 5E.2A assigned all 576,191 LOIC-HTTP test flows to known classes; its known prediction distribution is recorded in the companion result JSON.

## Reproducibility, timing, and memory

- Seed: 2026.
- Training time: 1.347 seconds; validation scoring: 2.402 seconds.
- Test inference (`score_samples` calls only): 18.161 seconds total; 0.000002302 seconds per row.
- Peak process RSS: 1,732,526,080 bytes; process peak RSS from getrusage; includes preflight and data loading; not accelerator memory.
- Environment: Python 3.11.16; NumPy 2.4.6; scikit-learn 1.9.1.
- Raw and prepared artifact hashes are in the JSON. Raw data and earlier stage artifacts were not modified.

## Limitations

This is one dataset/source condition with a validation-calibrated benign operating point. The per-source row partition shares each source across fitting and validation; it calibrates an FPR operating point and is not source-generalization validation. Only Tuesday is held out at source level for final evaluation. The result does not establish broad novelty-detection effectiveness or performance on other unseen attacks.
