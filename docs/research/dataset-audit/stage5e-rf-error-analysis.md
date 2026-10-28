# Stage 5E.1 — CSE RF error and class-support analysis

**Scope:** post-hoc analysis only. Both holdouts use the frozen Stage 5D Random Forest results. No model was trained, and no prior result, raw dataset, prepared dataset, protocol, or RF configuration was changed.

Source artifact: [`cse-source-holdout-rf.json`](../../../experiments/stage5d/cse-source-holdout-rf.json). SHA-256: `48e42d5f90e8a7d4ff27f5d259257fa0efa0598056c4b67f985cd1ba6a2e4362`.

## Method and definitions

The confusion matrices provide aggregate class-prediction counts, so the requested class-level counts and rates are derivable. They do not preserve row-level feature values or an ordered per-flow prediction list; those are not needed for this aggregate analysis. Confusion matrix rows are actual labels and columns are predicted labels.

`attack → benign` rate is the actual attack class's count predicted as Benign divided by that attack class's test support. For an attack class, `benign → this attack` is benign rows predicted as that class divided by all benign test rows. For the Benign row, `benign → attack` is the aggregate benign-to-any-attack count/rate. A ratio is `test support / training support`; it is N/A if training support is zero. These values are descriptive and do not imply causality.

## Existing holdout metrics comparison

The values below are copied from Stage 5D without redefining or overwriting them. Difference is Holdout B minus Holdout A.

| Metric | Holdout A | Holdout B | B − A |
|---|---:|---:|---:|
| Accuracy | 0.995351 | 0.990413 | -0.004938 |
| Weighted F1 | 0.997353 | 0.994907 | -0.002446 |
| Primary test-supported macro F1 | 0.519438 | 0.399120 | -0.120318 |
| Benign FPR | 0.004384 | 0.009510 | 0.005126 |
| Attack FNR as benign | 0.409894 | 0.138122 | -0.271772 |

## CSE-SFH-A

Training rows: 13,110,659; test rows: 1,042,867.

| Class | Train support | Test support | Predicted support | Test/train ratio | Precision | Recall | F1 | Attack → benign (count / class rate) | Benign → attack (count / benign rate) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Benign | 11,126,732 | 1,042,301 | 1,037,964 | 0.093675 | 0.999776 | 0.995616 | 0.997692 | N/A | 4,569 / 0.004384 |
| Bot | 286,191 | 0 | 1,683 | 0.000000 | 0.000000 | N/A | 0.000000 | 0 / N/A | 1,660 / 0.001593 |
| Brute Force -Web | 249 | 362 | 720 | 1.453815 | 0.241667 | 0.480663 | 0.321627 | 170 / 0.469613 | 538 / 0.000516 |
| Brute Force -XSS | 79 | 151 | 182 | 1.911392 | 0.505495 | 0.609272 | 0.552553 | 32 / 0.211921 | 90 / 0.000086 |
| DDOS attack-HOIC | 686,012 | 0 | 456 | 0.000000 | 0.000000 | N/A | 0.000000 | 0 / N/A | 456 / 0.000437 |
| DDOS attack-LOIC-UDP | 1,730 | 0 | 0 | 0.000000 | N/A | N/A | N/A | 0 / N/A | 0 / 0.000000 |
| DDoS attacks-LOIC-HTTP | 576,191 | 0 | 586 | 0.000000 | 0.000000 | N/A | 0.000000 | 0 / N/A | 585 / 0.000561 |
| DoS attacks-GoldenEye | 41,508 | 0 | 0 | 0.000000 | N/A | N/A | N/A | 0 / N/A | 0 / 0.000000 |
| DoS attacks-Slowloris | 10,990 | 0 | 1,125 | 0.000000 | 0.000000 | N/A | 0.000000 | 0 / N/A | 1,125 / 0.001079 |
| FTP-BruteForce | 193,354 | 0 | 0 | 0.000000 | N/A | N/A | N/A | 0 / N/A | 0 / 0.000000 |
| SQL Injection | 34 | 53 | 151 | 1.558824 | 0.139073 | 0.396226 | 0.205882 | 30 / 0.566038 | 115 / 0.000110 |
| SSH-Bruteforce | 187,589 | 0 | 0 | 0.000000 | N/A | N/A | N/A | 0 / N/A | 0 / 0.000000 |

### Confusion matrix

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

## CSE-SFH-B

Training rows: 13,110,561; test rows: 1,042,965.

| Class | Train support | Test support | Predicted support | Test/train ratio | Precision | Recall | F1 | Attack → benign (count / class rate) | Benign → attack (count / benign rate) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Benign | 11,126,430 | 1,042,603 | 1,032,738 | 0.093705 | 0.999952 | 0.990490 | 0.995198 | N/A | 9,915 / 0.009510 |
| Bot | 286,191 | 0 | 1,632 | 0.000000 | 0.000000 | N/A | 0.000000 | 0 / N/A | 1,618 / 0.001552 |
| Brute Force -Web | 362 | 249 | 5,722 | 0.687845 | 0.034429 | 0.791165 | 0.065986 | 29 / 0.116466 | 5,519 / 0.005293 |
| Brute Force -XSS | 151 | 79 | 200 | 0.523179 | 0.335000 | 0.848101 | 0.480287 | 8 / 0.101266 | 127 / 0.000122 |
| DDOS attack-HOIC | 686,012 | 0 | 639 | 0.000000 | 0.000000 | N/A | 0.000000 | 0 / N/A | 639 / 0.000613 |
| DDOS attack-LOIC-UDP | 1,730 | 0 | 0 | 0.000000 | N/A | N/A | N/A | 0 / N/A | 0 / 0.000000 |
| DDoS attacks-LOIC-HTTP | 576,191 | 0 | 599 | 0.000000 | 0.000000 | N/A | 0.000000 | 0 / N/A | 597 / 0.000573 |
| DoS attacks-GoldenEye | 41,508 | 0 | 0 | 0.000000 | N/A | N/A | N/A | 0 / N/A | 0 / 0.000000 |
| DoS attacks-Slowloris | 10,990 | 0 | 960 | 0.000000 | 0.000000 | N/A | 0.000000 | 0 / N/A | 960 / 0.000921 |
| FTP-BruteForce | 193,354 | 0 | 0 | 0.000000 | N/A | N/A | N/A | 0 / N/A | 0 / 0.000000 |
| SQL Injection | 53 | 34 | 475 | 0.641509 | 0.029474 | 0.411765 | 0.055010 | 13 / 0.382353 | 455 / 0.000436 |
| SSH-Bruteforce | 187,589 | 0 | 0 | 0.000000 | N/A | N/A | N/A | 0 / N/A | 0 / 0.000000 |

### Confusion matrix

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

## Observed support/performance association

The held-out classes with weak F1 are the web brute-force and SQL-injection classes in both holdouts, with XSS also weak in B. Their training supports are small relative to Benign and larger training attack classes: Web has 249 (A) or 362 (B), XSS has 79 (A) or 151 (B), and SQL Injection has 34 (A) or 53 (B). Their test supports are also small: 362/249, 151/79, and 53/34, respectively. The per-class table reports corresponding ratios.

This is an observed association between weak minority-class scores and small absolute training and test supports in these two reciprocal files. It does not establish that support caused the errors. Test support affects score uncertainty and resolution; training support is not experimentally varied independently here.

Benign scores remain high, while a portion of attack traffic is predicted as Benign (the Stage 5D attack FNR-as-benign is 0.409894 in A and 0.138122 in B). Benign-to-attack errors differ by predicted attack class and are detailed above. Aggregate accuracy and weighted F1 remain high because Benign dominates test support; test-supported macro F1 is much lower.

## Limits and next step

Only confusion matrices and class-level supports were available in Stage 5D. This supports class-level error analysis, but not per-flow error inspection, confidence analysis, feature attribution, threshold sweeps, or identifying individual misclassified records.

Recommended Stage 5E.2: if finer-grained diagnosis is needed, preserve prediction-level records from a separately authorized evaluation run (source ID, true label, predicted label, and model score), while keeping the existing Stage 5D results frozen. Do not retrain or alter Stage 5D to retrofit this analysis.

Machine-readable analysis: [`cse-rf-error-analysis.json`](../../../experiments/stage5e/cse-rf-error-analysis.json).
