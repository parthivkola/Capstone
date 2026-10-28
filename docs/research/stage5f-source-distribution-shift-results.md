# Stage 5F — Source/Distribution-Shift Adaptation Results

**Study condition: SOURCE/DISTRIBUTION SHIFT.** The imposed source order is not temporal. No concept-drift or temporal-drift claim is made; PSI is an input-distribution signal only.

Research question: Can a detector recognize meaningful changes in network behavior and adapt through bounded, controlled updates without full retraining, while preserving performance on previously learned behavior?

## Integrity and configuration

- Protocol SHA-256: `d8f94bc5d7321ec8b07a5a609c63b3169cbb350160678d01ced696adc1354195`.
- Stage 5D preparation manifest SHA-256: `5de3638478173750eaa4eef5ed966124467cd4131b0f3e398b67cb35026f3137`.
- All seven raw and prepared source hashes passed preflight; headers matched 77-feature schema.
- No raw or prepared source files were modified.
- No Tuesday/LOIC-HTTP rows entered initial fitting; all labels map to Benign or Attack.
- PSI reference/bin edges use only initial-fit data. W4 labels remain evaluation-only.

## Source windows and row counts

| Window | Source | Prepared rows | Benign | Attack |
|---|---|---:|---:|---:|
| W1 | `Friday-02-03-2018_TrafficForML_CICFlowMeter.csv` | 1,044,525 | 758,334 | 286,191 |
| W2 | `Friday-23-02-2018_TrafficForML_CICFlowMeter.csv` | 1,042,867 | 1,042,301 | 566 |
| W3 | `Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv` | 7,889,295 | 7,313,104 | 576,191 |
| W4 | `Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv` | 1,042,965 | 1,042,603 | 362 |

## Strategy results by window

### Static

| Window | Macro F1 mean ± SD | Weighted F1 mean ± SD | Benign FPR mean ± SD | Attack FNR mean ± SD | Benign F1 mean ± SD | Attack F1 mean ± SD |
|---|---:|---:|---:|---:|---:|---:|
| initial_validation | 0.999834 ± 0.000048 | 0.999848 ± 0.000044 | 0.000101 ± 0.000068 | 0.000245 ± 0.000042 | 0.999881 ± 0.000034 | 0.999787 ± 0.000061 |
| W1 | 0.420611 ± 0.000010 | 0.610734 ± 0.000014 | 0.000073 ± 0.000040 | 1.000000 ± 0.000000 | 0.841222 ± 0.000020 | 0.000000 ± 0.000000 |
| W2 | 0.499826 ± 0.000015 | 0.999110 ± 0.000030 | 0.000151 ± 0.000060 | 1.000000 ± 0.000000 | 0.999653 ± 0.000030 | 0.000000 ± 0.000000 |
| W3 | 0.482392 ± 0.000020 | 0.891996 ± 0.000035 | 0.000175 ± 0.000076 | 0.998634 ± 0.000000 | 0.962061 ± 0.000038 | 0.002722 ± 0.000003 |
| W4 | 0.499886 ± 0.000021 | 0.999426 ± 0.000042 | 0.000108 ± 0.000084 | 1.000000 ± 0.000000 | 0.999773 ± 0.000042 | 0.000000 ± 0.000000 |

### Periodic

| Window | Macro F1 mean ± SD | Weighted F1 mean ± SD | Benign FPR mean ± SD | Attack FNR mean ± SD | Benign F1 mean ± SD | Attack F1 mean ± SD |
|---|---:|---:|---:|---:|---:|---:|
| initial_validation | 0.999834 ± 0.000048 | 0.999848 ± 0.000044 | 0.000101 ± 0.000068 | 0.000245 ± 0.000042 | 0.999881 ± 0.000034 | 0.999787 ± 0.000061 |
| W1 | 0.420611 ± 0.000010 | 0.610734 ± 0.000014 | 0.000073 ± 0.000040 | 1.000000 ± 0.000000 | 0.841222 ± 0.000020 | 0.000000 ± 0.000000 |
| W2 | 0.499826 ± 0.000015 | 0.999110 ± 0.000030 | 0.000151 ± 0.000060 | 1.000000 ± 0.000000 | 0.999653 ± 0.000030 | 0.000000 ± 0.000000 |
| W3 | 0.483865 ± 0.000272 | 0.891447 ± 0.000296 | 0.002112 ± 0.000602 | 0.996620 ± 0.000142 | 0.961166 ± 0.000304 | 0.006563 ± 0.000302 |
| W4 | 0.508761 ± 0.002476 | 0.998283 ± 0.000443 | 0.002428 ± 0.000880 | 0.928177 ± 0.003907 | 0.998623 ± 0.000441 | 0.018899 ± 0.004528 |

### Drift Triggered

| Window | Macro F1 mean ± SD | Weighted F1 mean ± SD | Benign FPR mean ± SD | Attack FNR mean ± SD | Benign F1 mean ± SD | Attack F1 mean ± SD |
|---|---:|---:|---:|---:|---:|---:|
| initial_validation | 0.999834 ± 0.000048 | 0.999848 ± 0.000044 | 0.000101 ± 0.000068 | 0.000245 ± 0.000042 | 0.999881 ± 0.000034 | 0.999787 ± 0.000061 |
| W1 | 0.420611 ± 0.000010 | 0.610734 ± 0.000014 | 0.000073 ± 0.000040 | 1.000000 ± 0.000000 | 0.841222 ± 0.000020 | 0.000000 ± 0.000000 |
| W2 | 0.499826 ± 0.000015 | 0.999110 ± 0.000030 | 0.000151 ± 0.000060 | 1.000000 ± 0.000000 | 0.999653 ± 0.000030 | 0.000000 ± 0.000000 |
| W3 | 0.483865 ± 0.000272 | 0.891447 ± 0.000296 | 0.002112 ± 0.000602 | 0.996620 ± 0.000142 | 0.961166 ± 0.000304 | 0.006563 ± 0.000302 |
| W4 | 0.570637 ± 0.005778 | 0.997817 ± 0.000123 | 0.003732 ± 0.000227 | 0.097238 ± 0.033912 | 0.998114 ± 0.000119 | 0.143160 ± 0.011440 |

## PSI by source window

PSI ≥ 0.20 is a frozen operational feature signal; a window is flagged when at least five features signal. It is not a significance test.

### Initial validation false-alarm check

| Seed | Comparison rows | Signaled features | Trigger |
|---:|---:|---:|---|
| 2026 | 10000 | 0 | no |
| 2027 | 10000 | 0 | no |
| 2028 | 10000 | 0 | no |
| 2029 | 10000 | 0 | no |
| 2030 | 10000 | 0 | no |

| Seed | Window | Signaled features | Trigger |
|---:|---|---:|---|
| 2026 | W1 | 37 | yes |
| 2026 | W2 | 34 | yes |
| 2026 | W3 | 34 | yes |
| 2026 | W4 | 32 | yes |
| 2027 | W1 | 37 | yes |
| 2027 | W2 | 36 | yes |
| 2027 | W3 | 34 | yes |
| 2027 | W4 | 30 | yes |
| 2028 | W1 | 38 | yes |
| 2028 | W2 | 33 | yes |
| 2028 | W3 | 33 | yes |
| 2028 | W4 | 30 | yes |
| 2029 | W1 | 32 | yes |
| 2029 | W2 | 32 | yes |
| 2029 | W3 | 32 | yes |
| 2029 | W4 | 31 | yes |
| 2030 | W1 | 35 | yes |
| 2030 | W2 | 36 | yes |
| 2030 | W3 | 34 | yes |
| 2030 | W4 | 32 | yes |

## Update, delay, and rollback events

### Periodic

Attempted: 5; accepted: 5; rejected: 0.

| Seed | Boundary | Attempted | Accepted | Reason | Buffer rows | Latency seconds | Anchor macro F1 | Anchor benign FPR |
|---:|---|---|---|---|---:|---:|---:|---:|
| 2026 | W2 | yes | True | accepted | 60,000 | 31.779889 | 0.998096 | 0.002282 |
| 2026 | W4 | no | — | terminal update prohibited | — | — | — | — |
| 2027 | W2 | yes | True | accepted | 60,000 | 25.750173 | 0.997108 | 0.003740 |
| 2027 | W4 | no | — | terminal update prohibited | — | — | — | — |
| 2028 | W2 | yes | True | accepted | 60,000 | 25.069074 | 0.997886 | 0.002640 |
| 2028 | W4 | no | — | terminal update prohibited | — | — | — | — |
| 2029 | W2 | yes | True | accepted | 60,000 | 24.514611 | 0.997914 | 0.002488 |
| 2029 | W4 | no | — | terminal update prohibited | — | — | — | — |
| 2030 | W2 | yes | True | accepted | 60,000 | 25.194518 | 0.997826 | 0.002541 |
| 2030 | W4 | no | — | terminal update prohibited | — | — | — | — |

### Drift Triggered

Attempted: 10; accepted: 10; rejected: 0.

| Seed | Boundary | Attempted | Accepted | Reason | Buffer rows | Latency seconds | Anchor macro F1 | Anchor benign FPR |
|---:|---|---|---|---|---:|---:|---:|---:|
| 2026 | W2 | yes | True | accepted | 60,000 | 63.521208 | 0.998096 | 0.002282 |
| 2026 | W3 | yes | True | accepted | 70,566 | 47.986171 | 0.997827 | 0.002859 |
| 2026 | W4 | no | — | terminal update prohibited | — | — | — | — |
| 2027 | W2 | yes | True | accepted | 60,000 | 52.571541 | 0.997108 | 0.003740 |
| 2027 | W3 | yes | True | accepted | 70,566 | 47.946331 | 0.997598 | 0.003100 |
| 2027 | W4 | no | — | terminal update prohibited | — | — | — | — |
| 2028 | W2 | yes | True | accepted | 60,000 | 51.399727 | 0.997886 | 0.002640 |
| 2028 | W3 | yes | True | accepted | 70,566 | 47.649719 | 0.997667 | 0.003034 |
| 2028 | W4 | no | — | terminal update prohibited | — | — | — | — |
| 2029 | W2 | yes | True | accepted | 60,000 | 50.312911 | 0.997914 | 0.002488 |
| 2029 | W3 | yes | True | accepted | 70,566 | 46.411521 | 0.997794 | 0.002822 |
| 2029 | W4 | no | — | terminal update prohibited | — | — | — | — |
| 2030 | W2 | yes | True | accepted | 60,000 | 52.051201 | 0.997826 | 0.002541 |
| 2030 | W3 | yes | True | accepted | 70,566 | 49.037244 | 0.997785 | 0.002713 |
| 2030 | W4 | no | — | terminal update prohibited | — | — | — | — |

## Update efficiency, next-window outcomes, and resource costs

- Periodic RF: 5 scheduled W2 updates were attempted and accepted. All had a PSI signal in both preceding completed windows (W1 and W2), so unnecessary-by-trigger updates: **0/5**. The terminal W4 slot was skipped for all seeds.
- PSI-triggered RF: 10 updates (W2 and W3 for each seed) were attempted and accepted; rollbacks: **0**. W1 signals were pending until W1 labels became eligible at the W2 boundary. W4 signals were recorded, with no terminal update.
- No accepted adaptive update lacked a macro-F1 improvement in its next evaluation window under the paired incumbent comparison recorded in the JSON: W2 updates were compared with static RF in W3; W3 updates were compared with the same-seed periodic RF (the W2-updated incumbent) in W4. Mean next-window macro-F1 differences were **+0.001473 (SD 0.000268)** for W2 updates and **+0.061876 (SD 0.004169)** for W3 updates. This is a post-hoc comparison, not a trigger or selection rule.
- Mean release-to-fit-completion adaptation latency was **26.462 s (SD 3.005; 5 updates)** for periodic RF and **50.889 s (SD 4.892; 10 updates)** for PSI-triggered RF. These intervals include buffer assembly and fitting; timestamps and component durations are in JSON.
- Initial RF fits totaled **1,793.575 s**; adaptive RF fits totaled **95.857 s**; total recorded RF fitting time was **1,889.431 s**. Window inference totaled 129.728 s (static), 128.177 s (periodic), and 129.598 s (PSI-triggered); initial validation and anchor inference totaled 11.789 s.
- Peak process RSS was **2,283,622,400 bytes**. RF used `n_jobs=1`; separate CPU utilization and whole-experiment wall time were not recorded.

## Paired strategy comparisons

Differences are left strategy minus right strategy on identical seeds and windows. Seeds are algorithmic repeats on the same finite source files, not independent captures.

| Window | Metric | Pair | Mean difference | Paired 95% t interval | Cohen dz |
|---|---|---|---:|---:|---:|
| W1 | macro_f1 | static minus periodic | 0.000000 | [0.000000, 0.000000] | N/A |
| W1 | macro_f1 | static minus drift_triggered | 0.000000 | [0.000000, 0.000000] | N/A |
| W1 | macro_f1 | periodic minus drift_triggered | 0.000000 | [0.000000, 0.000000] | N/A |
| W1 | benign_fpr | static minus periodic | 0.000000 | [0.000000, 0.000000] | N/A |
| W1 | benign_fpr | static minus drift_triggered | 0.000000 | [0.000000, 0.000000] | N/A |
| W1 | benign_fpr | periodic minus drift_triggered | 0.000000 | [0.000000, 0.000000] | N/A |
| W1 | attack_fnr_as_benign | static minus periodic | 0.000000 | [0.000000, 0.000000] | N/A |
| W1 | attack_fnr_as_benign | static minus drift_triggered | 0.000000 | [0.000000, 0.000000] | N/A |
| W1 | attack_fnr_as_benign | periodic minus drift_triggered | 0.000000 | [0.000000, 0.000000] | N/A |
| W2 | macro_f1 | static minus periodic | 0.000000 | [0.000000, 0.000000] | N/A |
| W2 | macro_f1 | static minus drift_triggered | 0.000000 | [0.000000, 0.000000] | N/A |
| W2 | macro_f1 | periodic minus drift_triggered | 0.000000 | [0.000000, 0.000000] | N/A |
| W2 | benign_fpr | static minus periodic | 0.000000 | [0.000000, 0.000000] | N/A |
| W2 | benign_fpr | static minus drift_triggered | 0.000000 | [0.000000, 0.000000] | N/A |
| W2 | benign_fpr | periodic minus drift_triggered | 0.000000 | [0.000000, 0.000000] | N/A |
| W2 | attack_fnr_as_benign | static minus periodic | 0.000000 | [0.000000, 0.000000] | N/A |
| W2 | attack_fnr_as_benign | static minus drift_triggered | 0.000000 | [0.000000, 0.000000] | N/A |
| W2 | attack_fnr_as_benign | periodic minus drift_triggered | 0.000000 | [0.000000, 0.000000] | N/A |
| W3 | macro_f1 | static minus periodic | -0.001473 | [-0.001806, -0.001140] | -5.495735 |
| W3 | macro_f1 | static minus drift_triggered | -0.001473 | [-0.001806, -0.001140] | -5.495735 |
| W3 | macro_f1 | periodic minus drift_triggered | 0.000000 | [0.000000, 0.000000] | N/A |
| W3 | benign_fpr | static minus periodic | -0.001938 | [-0.002698, -0.001177] | -3.163406 |
| W3 | benign_fpr | static minus drift_triggered | -0.001938 | [-0.002698, -0.001177] | -3.163406 |
| W3 | benign_fpr | periodic minus drift_triggered | 0.000000 | [0.000000, 0.000000] | N/A |
| W3 | attack_fnr_as_benign | static minus periodic | 0.002014 | [0.001838, 0.002191] | 14.152291 |
| W3 | attack_fnr_as_benign | static minus drift_triggered | 0.002014 | [0.001838, 0.002191] | 14.152291 |
| W3 | attack_fnr_as_benign | periodic minus drift_triggered | 0.000000 | [0.000000, 0.000000] | N/A |
| W4 | macro_f1 | static minus periodic | -0.008875 | [-0.011944, -0.005806] | -3.590524 |
| W4 | macro_f1 | static minus drift_triggered | -0.070751 | [-0.077929, -0.063573] | -12.238513 |
| W4 | macro_f1 | periodic minus drift_triggered | -0.061876 | [-0.067052, -0.056699] | -14.841356 |
| W4 | benign_fpr | static minus periodic | -0.002320 | [-0.003425, -0.001215] | -2.607388 |
| W4 | benign_fpr | static minus drift_triggered | -0.003624 | [-0.003927, -0.003321] | -14.861943 |
| W4 | benign_fpr | periodic minus drift_triggered | -0.001304 | [-0.002167, -0.000441] | -1.876323 |
| W4 | attack_fnr_as_benign | static minus periodic | 0.071823 | [0.066972, 0.076674] | 18.384776 |
| W4 | attack_fnr_as_benign | static minus drift_triggered | 0.902762 | [0.860656, 0.944869] | 26.621065 |
| W4 | attack_fnr_as_benign | periodic minus drift_triggered | 0.830939 | [0.788415, 0.873463] | 24.262799 |

## Interpretation and limitations

Report negative outcomes directly, including no PSI triggers, no post-update improvement, or rollbacks. Performance differences are source-specific under this imposed schedule. The source order is not chronological, source/extractor comparability is not verified, and PSI alone does not establish a change in P(Y|X).

## Reproducibility

- Seeds: 2026, 2027, 2028, 2029, 2030.
- Python: 3.11.16; NumPy: 2.4.6; scikit-learn: 1.9.1.
- Peak process RSS: 2,283,622,400 bytes.
- Input hashes, split memberships, model parameters, PSI values, buffer memberships, event records, and per-seed output are in the companion JSON.
