# Research Design: Explainable Adaptive SDN-Based Network Defense Appliance

## 1. Problem statement

An SDN-based intrusion-defense appliance must classify malicious network activity and apply mitigation through the controller. In a real network, its operating conditions do not remain fixed: traffic mixes, hosts, services, and attack techniques change over time. A classifier that scores well on a fixed benchmark may therefore fail on a new attack family or after the normal traffic distribution shifts. Further, an automated controller action can disrupt legitimate users if its evidence or confidence is poor.

This project investigates whether a small, reproducible SDN defense appliance can detect known attacks, flag previously unseen behavior, adapt to measurable concept drift, and make bounded mitigation decisions with an explanation of the evidence, risk, and selected action.

## 2. Motivation

SDN makes network-wide observation and flow-rule enforcement practical from one control point. That control also concentrates risk: a false positive may block a legitimate flow, while a delayed or unexplained decision can make incident response hard to trust. Static intrusion-detection evaluation alone does not answer whether a system remains useful as traffic changes, or whether its automated response is safe.

The capstone addresses these practical concerns with a deliberately limited prototype and a set of controlled experiments. The aim is evidence about trade-offs among detection quality, adaptability, explanation quality, resource use, and response time; it is not a claim that one learning method is universally best.

## 3. Research gap

Many intrusion-detection studies report aggregate benchmark accuracy under random train/test splits. Such splits can leak closely related flows into both partitions and do not test deployment conditions such as a held-out attack family or time-ordered traffic. Other work evaluates anomaly detection, drift handling, explainability, or SDN enforcement separately. There is a smaller body of reproducible, end-to-end experiments that evaluates all four concerns under the same data contracts and clearly separates offline benchmark performance from live controller behavior.

This project fills a bounded version of that gap by comparing a few representative models under matched protocols, then validating selected configurations in a small Mininet topology. The study will report where evidence is insufficient rather than extrapolating benchmark outcomes to operational effectiveness.

## 4. Research objectives

1. Establish fair, reproducible baselines for known-attack classification using the same feature policy, data splits, tuning budget, and metrics.
2. Measure the ability to flag attack families or abnormal behavior absent from training.
3. Measure degradation under time-ordered distribution change and the benefit and cost of a bounded adaptation policy.
4. Design and evaluate a constrained mitigation policy that records understandable reasons and limits harm from incorrect automated decisions.
5. Validate selected offline configurations in a live Mininet-based SDN scenario, measuring end-to-end latency and resource use separately from benchmark scores.

## 5. Research questions and testable hypotheses

### RQ1 — Known-attack detection and fair comparison

**RQ1.** Under identical preprocessing, split definitions, class-handling policy, and tuning budget, how do Random Forest, XGBoost, and GraphSAGE compare for classifying known attack classes? How does Isolation Forest compare when framed as an anomaly detector rather than a multi-class classifier?

**H1a.** At least one supervised candidate model will obtain a macro F1 score higher than a majority-class baseline on each benchmark protocol.

**H1b.** Differences between candidate supervised models will vary by dataset and class; no model is assumed to dominate across all datasets. A paired comparison across the same splits will determine whether an observed difference is stable.

**H1c.** Macro F1 and per-class F1 will reveal materially different conclusions from accuracy on imbalanced data. This hypothesis is supported if ranking or acceptability changes when class-balanced metrics are considered.

### RQ2 — Previously unseen or novel behavior detection

**RQ2.** Can the appliance flag a held-out attack family or other out-of-distribution behavior while keeping false alarms on benign traffic within a stated operating point?

**H2a.** In a leave-one-attack-family-out protocol, at least one anomaly-oriented configuration will achieve recall above its benign-traffic false-positive rate at a pre-registered threshold, and will perform better than a known-class classifier used without an unknown-behavior rejection rule.

**H2b.** Detection of a held-out family will differ by family and dataset. Results will therefore be reported per held-out family, not only as a pooled average.

The threshold and the maximum acceptable false-positive rate must be fixed from a validation partition before testing. Isolation Forest is the primary novelty baseline; supervised models may participate only when coupled with a defined uncertainty or rejection score. This keeps the comparison aligned with each model's intended use.

### RQ3 — Concept drift and adaptive learning

**RQ3.** How much does detection performance degrade under time-ordered traffic change, and can a bounded drift-triggered update restore performance without causing unacceptable false positives or resource cost?

**H3a.** A model trained on an earlier time window will show lower macro F1 or recall on at least one later window than on an IID test split from its training period.

**H3b.** When a pre-defined drift signal persists for a fixed number of windows, an update using newly labelled, verified data will improve subsequent-window macro F1 or recall relative to a no-update baseline, without exceeding the same false-positive operating point.

**H3c.** Adaptation has a measurable cost in update time, CPU, and memory. It will be considered useful only when its performance recovery is reported alongside those costs; it is not assumed to be beneficial in every stream.

The project will simulate online operation with ordered windows from the datasets and optionally controlled changes in the live testbed. It will not claim fully autonomous continuous learning: updates require a bounded schedule and verified labels.

### RQ4 — Explainable risk-aware mitigation

**RQ4.** Can explanations and a risk-aware decision policy make mitigation decisions auditable and reduce harmful automated actions while retaining timely response to high-confidence threats?

**H4a.** For evaluated alerts, the appliance can produce a concise decision record containing the predicted event or anomaly score, confidence, leading evidence, risk level, selected action, and expiry. Explanation fidelity and stability will be measured against the model decision; absence of a faithful explanation is a failed explanation, not an inferred success.

**H4b.** A risk-aware policy with confidence, novelty, and protected-flow guardrails will produce a lower false-mitigation rate than an always-block policy at comparable malicious-flow containment, with any increase in mitigation latency reported.

**H4c.** Temporary, flow-scoped actions with expiry and rollback will limit the duration and scope of an erroneous mitigation compared with an indefinite block.

## 6. Candidate models

Model selection is an experimental question. All candidates will use the same predefined feature availability rules for a given protocol, and resource cost will be part of the comparison.

| Model | Role in the study | Scope and comparison conditions |
| --- | --- | --- |
| Random Forest | Strong tabular supervised baseline for known-class classification | Train on flow features; compare with the same splits and tuning budget as XGBoost. |
| XGBoost | Gradient-boosted tabular supervised candidate | Train on the same tabular features and evaluate under the same protocols as Random Forest. |
| Isolation Forest | Unsupervised or semi-supervised anomaly baseline | Fit on benign or permitted training data; evaluate with a validation-selected anomaly threshold. It is not treated as a like-for-like multi-class classifier. |
| GraphSAGE | Graph-based candidate when an explicit host/flow graph can be constructed | Use only if graph construction is defined without test leakage and is feasible within the project schedule. Compare it with tabular baselines on matched data windows and report graph-building cost. |

For supervised models, explanations will identify influential input evidence for the individual decision. For graph-based decisions, the study will also record the local nodes or edges and features that most influenced the result. The exact explanation method is selected only after it can be applied consistently and evaluated for fidelity and stability; explanation graphics alone are not evidence of correctness.

## 7. Candidate datasets and data protocol

The candidate datasets are CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15, and TON_IoT. They provide differing traffic contexts, attack labels, feature schemas, and class balances. They will not be merged into one synthetic universal dataset because feature and label meanings differ. Each dataset receives its own documented preprocessing and split manifest.

For each included dataset, the study will document source version, acquisition date, license or access terms, selected files, label mapping, removed fields, missing-value policy, duplicate handling, feature scaling or encoding, and random seeds. Split units must prevent direct flow-level leakage where possible: use documented capture/session, source-time, or day-based grouping rather than a naive row-random split. If a dataset cannot support a particular protocol faithfully, that limitation will be recorded and that protocol omitted for the dataset.

The B.Tech scope is to fully execute a core pair of datasets selected after the initial data audit, with the remaining two used only if their preprocessing fits the same schedule. A compact cross-dataset check may be included after the primary experiments; it is supplementary, not a substitute for within-dataset evaluation.

## 8. Benchmark evaluation

Benchmark evaluation is offline experimentation on fixed dataset partitions. Its purpose is to measure detection behavior reproducibly; it does not measure controller or network enforcement latency.

Three complementary protocols will be used where dataset metadata permits:

1. **Known-attack protocol:** grouped or time-aware train/validation/test partitions containing the same known label set, for RQ1.
2. **Novel-behavior protocol:** leave one attack family out of training, tune thresholds only on validation data, then test detection of the held-out family and benign traffic, for RQ2.
3. **Drift protocol:** train on earlier windows and evaluate on later windows, with a fixed no-update baseline and a pre-defined, verified-label update condition, for RQ3.

All candidate models receive comparable tuning effort, fixed seed sets, and the same held-out test data. Hyperparameters, selected thresholds, and failed runs are retained. Confidence intervals across seeds or partitions will accompany point estimates when sample size permits. Model ranking will not be based on accuracy alone.

## 9. Live Mininet-based evaluation

Live evaluation is a separate, small-scale operational test. A Mininet topology will contain benign clients and services, traffic sources that reproduce a limited set of safe, authorised attack-like scenarios, OpenFlow switches, and the SDN controller under test. It will use the appliance's actual feature-collection and decision path where feasible.

The live study answers different questions from benchmark evaluation:

| Benchmark evaluation | Live Mininet evaluation |
| --- | --- |
| Offline flow records and fixed labels | Generated traffic and controller observations in a controlled topology |
| Classification, novelty, and drift metrics | Detection-to-action timing, enforcement behavior, and host resource cost |
| Reproducible partition-level comparison | End-to-end behavior in a repeatable network scenario |
| Does not establish operational latency | Does not establish real-world Internet-scale generalization |

Each run will include a benign baseline and one controlled scenario at a time. The recorded timeline is: traffic event starts, feature window closes, alert is emitted, policy decision is made, flow rule is installed, and the action takes observable effect. The testbed will remain intentionally small; its role is validation of the control loop, not a claim of production scalability.

## 10. Explainable, risk-aware mitigation policy

The mitigation policy converts detection output into a bounded action. It considers classification or anomaly evidence, calibrated confidence where available, novelty or drift status, flow context, and a configurable protected-flow list. Every decision must write an explanation record before enforcement.

| Risk band | Example policy outcome | Safety controls |
| --- | --- | --- |
| Low or uncertain | Alert and observe; no automatic disruptive action | Preserve traffic and retain evidence for review. |
| Medium | Temporary, flow-scoped rate limit or quarantine where the testbed supports it | Expiry, audit record, and a protected-flow exemption. |
| High confidence with high risk | Temporary, flow-scoped block | Short time-to-live, rollback path, audit record, and no controller-wide or topology-wide rule. |

The final mapping, thresholds, and time-to-live values will be declared before live testing. The policy will not automatically modify its own guardrails. A mitigation is counted as false when it affects traffic labelled or configured as benign; an action is counted as effective when the intended malicious test flow is contained within the measured response window without violating the protected-flow rule.

## 11. Evaluation metrics

The metric set is reported by dataset, protocol, class or attack family where applicable, model, and seed/window. Definitions and measurement points are fixed before experiments.

| Area | Metrics | Notes |
| --- | --- | --- |
| Known-class detection | Accuracy, precision, recall, macro F1, per-class F1 | Accuracy is contextual only; macro and per-class scores address imbalance. |
| Error behavior | False-positive rate, false-negative rate | Report with the threshold and the definition of the benign/positive class. |
| Novel behavior | Held-out-family recall, false-positive rate, precision, macro F1 where labels support it | Report each held-out family and the validation-selected threshold. |
| Drift and adaptation | Metric change by time window, recovery after update, update time | Compare with the same no-update baseline. |
| Live responsiveness | Detection latency, mitigation latency | Detection latency: observable event/window completion to alert. Mitigation latency: alert/policy decision to observable rule effect. Report the chosen timestamp convention. |
| System cost | CPU and memory | Measure process/container or host scope consistently during idle, benign load, detection, and mitigation. |
| Explanation and mitigation | Explanation fidelity, explanation stability, false-mitigation rate, containment rate, action scope/duration | These evaluate whether the decision record reflects the model and whether actions cause avoidable disruption. |

For latency and resource metrics, report median and tail values (for example, p95) over repeated live runs, alongside run counts and machine specification. Clock sources and synchronisation assumptions will be documented.

## 12. Experimental matrix

The full Cartesian product is deliberately avoided. The matrix below defines a staged, feasible set of experiments; later stages use configurations that have passed data and baseline checks in earlier stages.

| Stage | Research question | Data / environment | Models | Core comparison and outputs |
| --- | --- | --- | --- | --- |
| A | Data audit | Each candidate dataset | None | Schema, labels, imbalance, leakage risks, feasible split units, and selection of core datasets. |
| B | RQ1 | Core benchmark datasets; known-attack protocol | Random Forest, XGBoost; GraphSAGE if graph data contract is feasible | Same features/splits/tuning budget; accuracy, precision, recall, macro F1, per-class F1, FPR/FNR, CPU, memory. |
| C | RQ2 | Core datasets; leave-one-family-out protocol | Isolation Forest; eligible supervised configurations with a rejection rule | Held-out-family recall versus benign FPR at fixed validation thresholds. |
| D | RQ3 | Core datasets with reliable time order | Best one or two configurations from B/C | Earlier-to-later window degradation; no-update versus declared update policy; cost and recovery. |
| E | RQ4 | Mininet scenarios | One or two selected configurations and the policy baseline | Risk-aware policy versus always-block baseline; explanation records, false mitigation, containment, detection/mitigation latency, CPU, memory. |
| F | Robustness check, time permitting | One additional candidate dataset or a small cross-dataset transfer | Best configuration(s) only | Generalization evidence with explicitly limited claims. |

Each benchmark experiment will use repeated seeds or documented partitions. Each live scenario will be repeated under the same topology and traffic parameters. The number of seeds and repetitions will be selected after a pilot run to fit available compute and time, then fixed before the main comparison.

## 13. Threats to validity

| Threat | Why it matters | Mitigation or disclosure |
| --- | --- | --- |
| Dataset representativeness | Public captures may not resemble a deployment network. | Evaluate multiple candidate datasets where feasible, describe their context, and limit generalization claims. |
| Leakage and split bias | Related records in training and test inflate scores. | Use grouped/time-aware manifests, audit identifiers and duplicates, and preserve split definitions. |
| Label quality | Ground-truth labels can be incomplete or inconsistent. | Use dataset documentation, retain label mappings, inspect anomalies, and report known limitations. |
| Class imbalance | Accuracy can conceal poor minority-class detection. | Use macro F1, per-class F1, FPR, FNR, and class-specific tables. |
| Unequal tuning | More optimisation for one model invalidates comparison. | Apply a shared tuning budget and validation-only model selection. |
| Threshold selection bias | Choosing on test data overstates anomaly performance. | Select thresholds on validation data before test evaluation. |
| Graph construction leakage | Graphs can expose future/test connectivity or labels. | Define graph construction by allowed observation window and keep test labels unavailable. |
| Simulated drift | Ordered datasets and Mininet changes approximate, but do not reproduce, all real drift. | State the drift source and avoid claims of universal adaptation. |
| Mininet fidelity and scale | Virtualised topology differs from hardware and Internet-scale traffic. | Treat it as control-loop validation; report topology, host capacity, and scenario limits. |
| Explanation interpretation | Plausible explanations may not be faithful to the decision. | Evaluate fidelity and stability, retain decision records, and do not equate readability with correctness. |
| Mitigation safety | A small testbed cannot prove production safety. | Use short-lived, scoped rules, protected flows, rollback, and explicit boundaries on claims. |

## 14. Reproducibility requirements

Before the main experiments, create and version the following artefacts within the project or an approved archival location:

1. A data manifest with source URLs or identifiers, version/date, checksums where permitted, selected files, licences, and acquisition instructions. Raw datasets need not be redistributed when licensing prevents it.
2. A preprocessing specification describing features, label mapping, cleaning rules, split-generation rules, thresholds, and any graph-construction contract.
3. Experiment configuration files or tables stating model parameters, tuning budget, seeds, compute environment, software versions, and metric definitions.
4. Immutable split manifests and time-window definitions, so every result can be regenerated from the same inputs.
5. Run-level outputs: predictions or sufficient aggregates, confusion matrices, thresholds, latency timestamps, resource samples, explanation records, controller action logs, and failures.
6. A Mininet scenario manifest with topology, traffic parameters, controller version, rule expiry values, protected-flow configuration, host specification, and number of repeats.
7. A results-reporting template that separates validation decisions from held-out test results and records deviations from the plan.

Random seeds alone are not sufficient: dataset version, split identity, timing policy, and the exact mitigation configuration must also be recoverable.

## 15. Criteria for a successful result

A successful result is a defensible empirical finding, rather than a target score. The project succeeds if it delivers all of the following:

1. Reproducible, leakage-aware benchmark results for the core datasets and stated protocols, including class-sensitive metrics and model resource costs.
2. A fair comparison that identifies the conditions under which each candidate model is competitive or limited, without assuming a GraphSAGE advantage over Random Forest or any other baseline.
3. Evidence about at least one held-out attack-family or anomaly-detection setting, reported with its false-positive trade-off.
4. Evidence about at least one time-ordered drift setting and a comparison with a no-update baseline, whether or not adaptation improves it.
5. Repeated live Mininet runs that demonstrate the bounded decision-to-mitigation path, recorded explanations, detection and mitigation latency, CPU, memory, and observed enforcement outcome.
6. A clear account of limitations and a reproducibility package sufficient for another student to recreate the configured experiments.

## 16. Negative but scientifically useful results

The following outcomes would still be valuable if documented faithfully:

- Random Forest or XGBoost matches or exceeds GraphSAGE after a fair comparison, especially when graph construction adds cost without reliable benefit.
- Isolation Forest detects some held-out families only by accepting an operationally high false-positive rate, showing the boundary of unsupervised novelty detection for the evaluated data.
- All candidates degrade substantially on later windows, or the bounded update policy fails to restore performance without increasing false positives or cost. This shows that the chosen drift signal, labels, features, or update timing are insufficient.
- Explanations are unstable or have weak fidelity even when detection metrics are strong, demonstrating that explanation quality must be evaluated separately.
- A cautious risk-aware policy lowers false mitigation but delays containment, making the safety-versus-speed trade-off explicit.
- Mininet results expose controller or feature-window latency that offline benchmark metrics did not reveal.

Such findings remain useful when the experiment protocol, data limitations, and uncertainty are fully reported. No experiment in this design fabricates outcomes or uses a null result to imply operational safety.

