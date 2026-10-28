# Stage 5F — Source/Distribution-Shift Adaptation Protocol

**Status: protocol frozen; design only.** No detector or adaptive model was implemented or trained. Raw data, prepared Stage 5D files, and all Stage 5A–5E.2C outputs remain unchanged.

## Research question

> Can a detector recognize meaningful changes in network behavior and adapt through bounded, controlled updates without full retraining, while preserving performance on previously learned behavior?

Stage 5F’s first experiment is a **source/distribution-shift experiment**, not a temporal concept-drift experiment. The CSE source files are separate captures. Repository provenance does not verify their chronology, clock semantics, consistent capture placement, or equivalent CICFlowMeter settings; timestamp audits also found 1970 values in some files. Therefore, the fixed progression below is an experiment schedule taken from the frozen Stage 5D manifest, not an ordering inferred from source filenames or timestamps.

The protocol can observe empirical changes in input distribution `P(X)` and, after delayed labels are released, binary class prior `P(Y)`. A PSI trigger is only an input-distribution signal. It does not establish concept drift, which would require support for a change in `P(Y|X)`. No Stage 5F claim will call an observed source difference concept drift.

## Frozen data and source identity

The source hashes below are copied from the frozen Stage 5D preparation manifest. Prepared artifacts retain the 77 ordered float32 predictors and `Label`; raw data stays immutable. Stage 5D exclusions remain in force: `Label`, `Flow ID`, `Src IP`, `Dst IP`, `Timestamp`, and `Dst Port` are not predictors. Timestamp and source identity are never model features or ordering signals.

| Manifest position | Source file | Stage 5F role | Raw SHA-256 | Prepared SHA-256 |
|---:|---|---|---|---|
| 0 | `Friday-02-03-2018_TrafficForML_CICFlowMeter.csv` | W4 | `d96f38e7496aba83475031e6fb8c6fdf1abf6aa1b71325a917798f3c7de93de1` | `787787a9a9ffd4d5c267593c44b00653a7beeb9d045174a60dd279d40276a7d7` |
| 1 | `Friday-23-02-2018_TrafficForML_CICFlowMeter.csv` | W2 | `d0a7f5059d9823b6e9b392b759e306481a3502d190dea7a1b5502ae079ea069b` | `c0c7ab2f4bc0ccbf3a7f2a1700e9dcc44d3f7eb4004c2032fead300305681c5d` |
| 2 | `Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv` | W3 | `7287a4d7740a1dddbf330ceb2beb6a4889d33ba63674558a68b5eb50d16711df` | `8a378abbf1706fa4dd6952e7bddb8b969dae3c7ead0deb5fa53b1b94726a9e4a` |
| 3 | `Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv` | Initial training | `fa2947a8256d81ee9103ae16139d62d0e17aa23e696ee80d9e76fb51c01c9c4b` | `e33987b46ba3be7c1ea9d50b56c743698ee281657894ea6d92b2c5766a7a794a` |
| 4 | `Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv` | W1 | `da33c927018274f9d49b145baa00e4ce0526c25b3b890b34c489e247b5e24544` | `038dcf4bd41b72e4580765185fc9d2811483d3149679fc7afcc5d614bc8f2df2` |
| 5 | `Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv` | Initial training | `acff8bc61376ee031d80878ee6099e0b1a87a1bd711d8068298421418c9f8147` | `1adcd2b6de088808b452dd32ae4f34590dc899a83cefb909de048fa617fe4aa9` |
| 6 | `Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv` | Initial training | `a5f4a1c2689e0aa6566c03a58466de9c407c0be0cbd3cc69306544026611be04` | `2439b6f8c140d19dedfb179cbe1f9fc6dccdabc3a5ed48ec23834c94fad60276` |

The prepared path for each file is `data/processed/stage5d/cse-cic-ids2018/<source filename>.model-ready.csv.gz`. The machine-readable protocol records the Stage 5D preparation-manifest SHA-256, all source and prepared hashes, and the exact ordered feature list. Later implementation must verify those values before loading any model data.

All seven sources have already appeared in earlier stages. Stage 5F is consequently a protocol-defined within-dataset comparison, not an untouched external holdout. Earlier Stage 5E.2A–5E.2C artifacts remain frozen context and cannot be used to tune this protocol.

## Task, initial window, and source progression

To keep the output label space stable across files that contain different attack families, map `Benign` to `Benign` and every other frozen source label to `Attack`. This is binary detection only. It does not test family classification, novelty rejection, or unseen-class identification.

Initial sources are Wednesday 14-February, Thursday 15-February, and Wednesday 21-February. The selection provides multiple benign/attack source profiles. Within each source and binary label, rank rows deterministically by SHA-256 of `(seed, source filename, prepared-file row ordinal)` with row ordinal as a tie-breaker. Seed 2026 assigns the first 70% to initial fit, the next 15% to validation, and the final 15% to a sealed forgetting-regression anchor. These row roles are disjoint. The validation partition is for initial baseline and detector false-alarm reporting only; it does not tune model parameters, detector bins, or thresholds. The anchor is never used for fitting or adaptation.

Sequential windows use all prepared rows in complete source files, in this fixed order:

1. **W1:** Thursday 22-February
2. **W2:** Friday 23-February
3. **W3:** Tuesday 20-February
4. **W4:** Friday 02-March

This order follows the remaining source entries’ order in the frozen Stage 5D manifest. It is not asserted to reflect capture time. Processing row order within a file is for reproducible reading only and is not treated as temporal order.

At each window the current model predicts, and the drift monitor sees `X` only. Current-window labels are hidden from the detector and adaptation. Labels for Wk are released only after W(k+1) closes. W4 labels are evaluation-only and are never used for adaptation. Label release is a simulated delay over retrospective dataset labels, not an operationally observed labeling process.

Record class counts and benign/attack prevalence per window after the label release. Compare feature-distribution signals (`P(X)`) and observed class priors (`P(Y)`) separately. Neither difference alone establishes `P(Y|X)` change.

## Identical model and strategy comparison

All three strategies use the same 77 features, fixed Stage 5D float32 conversion, binary label mapping, and `RandomForestClassifier` architecture and parameters:

- `n_estimators=100`
- `max_depth=18`
- `max_features="sqrt"`
- `min_samples_leaf=2`
- `class_weight="balanced_subsample"`
- `n_jobs=1`
- paired run seeds: **2026, 2027, 2028, 2029, 2030**

The strategies differ only in whether and when the model is rebuilt:

| Strategy | Frozen rule |
|---|---|
| Static RF | Fit on initial-fit rows once; never update. |
| Periodic RF | Rebuild at every second completed-window boundary regardless of detector output, using only labels released under the one-window delay. Execute only when a later evaluation window remains, so W2 may update the model for W3; W4 is terminal and has no update. |
| Drift-triggered RF | Rebuild only after the frozen PSI criterion fires. Triggering uses current-window features only. Wait until eligible earlier-window labels are released before rebuilding. |

The update mechanism is a **from-scratch rebuild on a bounded rolling buffer**, not warm-start or incremental RF learning. This is simple and auditable, but it remains model retraining; the protocol makes no claim of a no-retraining continual-learning method.

Each rebuild uses at most 100,000 rows:

- Initial replay: up to 20,000 rows per binary class from the initial-fit pool.
- Recent data: up to 10,000 rows per binary class from each of at most the three most recent eligible labeled windows.
- Select records deterministically using the run seed, source/window identity, and binary class. Do not duplicate records across buffer components.
- Rebuild at most once per window boundary. Do not queue repeated updates.

Only verified labels from windows that have passed the one-window release delay may enter the buffer. Never use current/future window labels, W4 labels, or anchor labels. After an accepted update, reset the PSI reference from an X-only sample of the accepted fit buffer. A rejected update does not reset the reference.

## Frozen PSI input-shift detector

Use one detector: **Population Stability Index (PSI)** across all 77 model features.

- Reference: deterministic 50,000-row X-only sample from initial-fit rows.
- Comparison: deterministic hash-selected sample of 10,000 rows from each complete evaluation window.
- Minimum sample sizes: 50,000 reference and 10,000 comparison rows. If either is not met, that window produces no trigger and is marked insufficient.
- For each feature, fit decile cut points from the reference sample only. Freeze the unique cut points before W1, include underflow and overflow bins, and define a three-bin rule for a constant reference feature (`below`, `equal`, `above`). Never derive bins from validation or evaluation data.
- Add 0.5 to each bin count before estimating proportions.
- Per-feature statistic: `PSI_j = Σ_b (q_jb − p_jb) ln(q_jb / p_jb)`, where `p` and `q` are the smoothed reference and comparison proportions.
- A feature crosses its threshold at **PSI ≥ 0.20**. A window triggers when **at least 5 of 77 features** cross in that same window.

PSI is a pre-registered operational threshold, not a p-value. There is no formal multiple-testing correction or familywise significance claim. The five-feature requirement limits one-feature triggers, but feature dependence remains. Run this rule on the disjoint initial validation rows and report the signal without adjusting bins or thresholds. A signal is described as a measured input-distribution shift only.

At a window boundary, the detector may trigger from current-window `X`; it cannot see labels. At the same boundary, only labels released from earlier windows are eligible for an update. Thus a Wk signal cannot train on Wk labels. A W4 signal is recorded but cannot produce an update because there is no later evaluation window.

## Rollback and forgetting protection

Evaluate every candidate rebuild on the unchanged sealed initial anchor. Compare against the initial accepted model’s anchor metrics. Reject and discard a candidate if either:

- anchor macro F1 falls by more than **0.05 absolute**, or
- anchor benign FPR rises by more than **0.02 absolute**.

On rejection, retain the prior accepted model and record candidate fit time and rollback. Report anchor macro F1, per-class F1, and benign FPR before/after every update. These fixed regression thresholds are guardrails, not values selected after observing evaluation results.

## Evaluation measures

Primary measures, reported for initial validation and every W1–W4 window:

- Macro F1 over the fixed `Benign` / `Attack` labels.
- Per-class F1.
- Benign FPR: benign predicted `Attack` / all benign.
- Attack FNR as benign: attack predicted `Benign` / all attack.

Secondary: weighted F1, support and class prevalence, per-feature PSI, adaptation latency, update/rollback counts, and CPU/memory when available. Report performance before any update in every window; identify the first PSI-triggered window’s pre-adaptation performance; report the first evaluation window after an accepted update; and report forgetting-anchor results after every update.

Report absolute metric changes versus initial validation and versus the immediately pre-adaptation window. A recovery ratio is only calculated if a measured degradation exists; otherwise mark it not applicable. Measure adaptation latency from eligible label release and update decision to candidate fit completion. For periodic RF, count executed scheduled updates with no PSI signal in the previous two windows as unnecessary-by-trigger. Record the terminal W4 schedule as skipped, not as an adaptation. For drift-triggered RF, report rejected/rolled-back updates and separately identify updates with no next-window macro-F1 improvement as non-beneficial; this is post-hoc evaluation, never a trigger input.

## Statistical comparison

Run each strategy with the same five seeds, source order, partitions, and evaluation windows. Report per-window mean and standard deviation across seeds. Compute paired strategy differences within each seed and window; report paired mean difference, 95% paired t interval, and Cohen’s `dz` when paired-difference standard deviation is nonzero. Seeds are algorithmic repeats over the same finite sources, not independent captures. The four source windows are fixed cases, not a random sample of network conditions. Keep inference limited to this dataset and protocol; do not treat the repeats as broad population evidence.

## Reproducibility and required artifacts

The protocol JSON at [`experiments/stage5f/drift-adaptation-protocol.json`](../../../experiments/stage5f/drift-adaptation-protocol.json) is the machine-readable authority for source identities/hashes, feature names, partition rules, model parameters, seed set, windows, PSI limits, adaptation buffer, rollback, and metrics.

A future implementation must write a run manifest and per-window artifacts without changing the frozen protocol. Record input hashes, partition membership hashes, feature schema, label counts, detector reference and bin edges, per-feature PSI, predictions or confusion aggregates, adaptation-buffer membership hashes, model configuration/seed, label release boundaries, update/rollback events, software versions, timing, and resource use. Expected tables/plots are specified in the JSON: metrics by strategy/window, benign FPR and attack FNR, PSI by feature/window, update/rollback timeline, and anchor performance across updates.

## Interpretation limits and next evidence needed

This protocol tests adaptation under a reproducible progression of source distributions. It does not prove chronological drift, concept drift, causal change in `P(Y|X)`, or performance on new networks. Source capture and extractor comparability are not verified; source identity may explain observed `P(X)` differences. All selected files were used in prior project stages, so this is not a pristine external holdout. A later claim about concept drift requires a trustworthy timestamp/capture order or a controlled intervention with stable source instrumentation and labels sufficient to examine `P(Y|X)`.

Stage 5F-PROTOCOL itself executes no model, PSI computation, adaptation, or experiment. It creates no result values.
