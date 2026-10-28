# Research Protocol

## Project scope

This protocol operationalises the authoritative [research design](research-design.md) for the B.Tech CSE project **Explainable Adaptive SDN-Based Network Defense Appliance**. This is a documentation specification only. It defines experiments and evidence requirements; it does not prescribe implementation code or assert results.

## 1. Problem statement

An SDN-based intrusion-defense appliance must classify malicious activity and apply controller-mediated mitigation while traffic mixes, hosts, services, and attack techniques change. A classifier that performs well on a fixed benchmark can fail on a new attack family or after the benign traffic distribution shifts. Automated controller actions can also harm legitimate traffic when evidence or confidence is inadequate.

The research investigates whether a small, reproducible appliance can detect known attacks, flag previously unseen behavior, adapt to measurable concept drift, and make bounded mitigation decisions with an explanation of the evidence, risk, and action.

## 2. Motivation

SDN provides network-wide observation and flow-rule enforcement from a single control point. The same central control increases the consequence of false positives, delayed responses, and decisions that an operator cannot inspect. Static detection scores do not establish usefulness under changing behavior or safe automated response.

The project examines the trade-offs among detection quality, adaptability, explanation quality, resource use, and response time in a deliberately limited prototype. It does not presume that any learning method is universally best.

## 3. Research gap

Studies often report aggregate accuracy from random splits that may leak related flows across partitions and do not test held-out attack families or time-ordered traffic. Anomaly detection, drift handling, explanation, and SDN enforcement are also frequently evaluated separately.

This project performs a bounded comparison under shared data contracts and validates selected configurations in a small Mininet topology. Offline benchmark findings and live controller behavior are separate evidence streams.

## 4. Research objectives

1. Establish fair, reproducible known-attack baselines using the same feature policy, splits, tuning budget, and metrics.
2. Measure the ability to flag attack families or abnormal behavior absent from training.
3. Measure performance change under time-ordered distribution change and the benefit and cost of a bounded adaptation policy.
4. Evaluate a constrained mitigation policy that records understandable decision reasons and limits harm from incorrect automation.
5. Validate selected configurations in Mininet, measuring end-to-end timing and resource use separately from offline benchmark scores.

## 5. Research questions and hypotheses

### RQ1 — Known-attack detection and fair comparison

**RQ1.** Under identical preprocessing, split definitions, class-handling policy, and tuning budget, how do Random Forest, XGBoost, and GraphSAGE compare for known attack classes? How does Isolation Forest compare when used as an anomaly detector rather than a multi-class classifier?

- **H1a.** At least one supervised candidate model will achieve macro F1 above a majority-class baseline on each benchmark protocol.
- **H1b.** Supervised-model differences will vary by dataset and class; no model is assumed to dominate across all datasets. Paired comparisons on the same splits determine whether a difference is stable.
- **H1c.** Macro F1 and per-class F1 will lead to materially different conclusions from accuracy on imbalanced data when rankings or acceptability change under class-balanced metrics.

### RQ2 — Previously unseen or novel behavior detection

**RQ2.** Can the appliance flag a held-out attack family or other out-of-distribution behavior while keeping benign false alarms within a stated operating point?

- **H2a.** In leave-one-attack-family-out evaluation, at least one anomaly-oriented configuration will achieve recall above its benign-traffic false-positive rate at a pre-registered threshold and will exceed a known-class classifier used without an unknown-behavior rejection rule.
- **H2b.** Detection of held-out families will differ by family and dataset; results are reported per family, not only as a pooled average.

Thresholds and the maximum acceptable false-positive rate are fixed on validation data before testing. Isolation Forest is the primary novelty baseline. A supervised configuration may be included only with a defined uncertainty or rejection score.

### RQ3 — Concept drift and adaptive learning

**RQ3.** How much does performance degrade under time-ordered traffic change, and can a bounded drift-triggered update restore performance without unacceptable false positives or resource cost?

- **H3a.** A model trained on an earlier window will have lower macro F1 or recall on at least one later window than on an IID test split from its training period.
- **H3b.** After a pre-defined drift signal persists for a fixed number of windows, an update using newly labelled, verified data will improve subsequent-window macro F1 or recall against a no-update baseline without exceeding the same false-positive operating point.
- **H3c.** Adaptation has measurable update-time, CPU, and memory cost. It is useful only when reported performance recovery is considered with those costs.

Online operation is simulated with ordered dataset windows and, if used, controlled live-testbed changes. The study does not claim fully autonomous continual learning.

### RQ4 — Explainable risk-aware mitigation

**RQ4.** Can explanations and a risk-aware policy make mitigation auditable and reduce harmful automated actions while retaining timely response to high-confidence threats?

- **H4a.** Each evaluated alert can produce a decision record containing predicted event or anomaly score, confidence, leading evidence, risk, selected action, and expiry. Explanation fidelity and stability are measured against the model decision.
- **H4b.** A policy with confidence, novelty, and protected-flow guardrails will produce a lower false-mitigation rate than an always-block policy at comparable malicious-flow containment, with mitigation-latency changes reported.
- **H4c.** Temporary, flow-scoped actions with expiry and rollback will limit the duration and scope of an erroneous mitigation relative to an indefinite block.

## 6. Candidate models

| Model | Study role | Protocol constraints |
| --- | --- | --- |
| Random Forest | Tabular supervised known-class baseline | Same flow features, splits, and tuning budget as XGBoost. |
| XGBoost | Tabular supervised candidate | Same feature and evaluation contract as Random Forest. |
| Isolation Forest | Unsupervised or semi-supervised anomaly baseline | Fit only on benign or permitted training data; select anomaly threshold on validation data. |
| GraphSAGE | Graph-based candidate | Included only if a graph can be constructed without test leakage and within project scope; report graph-building cost. |

Model choice remains an experimental question. Supervised explanations identify influential input evidence. Graph explanations also identify relevant local nodes, edges, or features. Readability alone is not accepted as evidence of explanation fidelity.

## 7. Dataset protocol

Candidate datasets are CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15, and TON_IoT. They are evaluated as separate datasets because their feature schemas and labels differ; they must not be blindly merged.

For each included dataset, record source version and acquisition date, access terms, selected files, label mapping, removed fields, missing-value handling, duplicate handling, feature encoding or scaling, seeds, and split manifest. Use capture/session, source-time, or day-based grouping where available to reduce leakage. When a dataset cannot support a protocol faithfully, record the limitation and omit that protocol for that dataset.

The core scope is two fully executed datasets chosen after a data audit. The other candidates are optional only if preprocessing remains feasible. Any cross-dataset check is supplementary.

## 8. Benchmark protocols

Benchmark evaluation uses fixed offline partitions and measures detection behavior. It does not measure network-rule enforcement latency.

1. **Known-attack protocol (RQ1):** grouped or time-aware train/validation/test partitions contain the same known label set.
2. **Novel-behavior protocol (RQ2):** leave one attack family out of training; select thresholds on validation data; test the held-out family and benign traffic.
3. **Drift protocol (RQ3):** train on earlier windows and evaluate later windows; compare a no-update baseline with a declared update condition using verified labels.

Use comparable tuning effort, fixed seed sets, and identical held-out test partitions for eligible candidates. Preserve hyperparameters, validation choices, selected thresholds, failures, and confidence intervals when sample size permits.

## 9. Live Mininet evaluation protocol

Live evaluation is a small, controlled operational test. The topology contains benign clients and services, authorised traffic sources for limited attack-like scenarios, OpenFlow switches, and the controller under test. It uses the appliance's feature-collection and decision path where feasible.

For every scenario, run a benign baseline and one controlled scenario at a time. Record: event start, feature-window close, alert emission, policy decision, flow-rule installation, and observable rule effect. Repeat each configured scenario with unchanged topology and traffic parameters.

Benchmark evaluation establishes classification and anomaly behavior on fixed data. Mininet establishes detection-to-action timing, enforcement behavior, and resource use in a controlled topology. It does not establish Internet-scale performance.

## 10. Explainable risk-aware mitigation policy

Every enforcement decision writes a decision record before action. The policy considers classification or anomaly evidence, calibrated confidence where available, novelty or drift status, flow context, and protected-flow configuration.

| Risk band | Policy outcome | Boundaries |
| --- | --- | --- |
| Low or uncertain | Alert and observe | No disruptive action; retain evidence. |
| Medium | Temporary flow-scoped rate limit or quarantine where supported | Expiry, audit record, protected-flow exemption. |
| High confidence and high risk | Temporary flow-scoped block | Short TTL, rollback path, audit record, no controller-wide or topology-wide rule. |

Declare the risk mapping, thresholds, TTL values, and protected-flow rules before live testing. The policy must not modify its own guardrails. A false mitigation affects benign-configured or benign-labelled traffic. Effective containment is the intended malicious test flow being contained within the response window without violating the protected-flow rule.

## 11. Metrics

| Area | Metrics |
| --- | --- |
| Known-class detection | Accuracy, precision, recall, macro F1, per-class F1 |
| Error behavior | False-positive rate, false-negative rate |
| Novel behavior | Held-out-family recall, FPR, precision, macro F1 where labels permit |
| Drift and adaptation | Metric change by time window, recovery after update, update time |
| Live responsiveness | Detection latency; mitigation latency |
| System cost | CPU; memory |
| Explanation and mitigation | Explanation fidelity, explanation stability, false-mitigation rate, containment rate, action scope and duration |

Report metrics by dataset, protocol, class or attack family where relevant, model, and seed/window. Use accuracy as contextual information, not the basis for model selection. For live latency and resource measurements, report median and tail values with run counts, machine specification, and timestamp conventions.

## 12. Experimental matrix

| Stage | RQ | Data/environment | Models | Required comparison |
| --- | --- | --- | --- | --- |
| A | Preparation | Each candidate dataset | None | Data audit, label/schema review, leakage risks, feasible split units, core-dataset choice. |
| B | RQ1 | Core benchmark datasets | Random Forest, XGBoost; GraphSAGE if feasible | Matched features, splits, and tuning budget. |
| C | RQ2 | Core benchmark datasets | Isolation Forest; eligible supervised candidates with rejection rule | Held-out-family recall versus benign FPR at validation-fixed threshold. |
| D | RQ3 | Core datasets with reliable time order | Best one or two configurations from B/C | Earlier-to-later degradation; no update versus declared update condition. |
| E | RQ4 | Mininet scenarios | One or two selected configurations and policy baseline | Risk-aware versus always-block policy, explanation records, containment, latency, CPU, memory. |
| F | Optional robustness | One additional dataset or small cross-dataset transfer | Best configuration(s) only | Limited generalisation evidence. |

## 13. Threats to validity

| Threat | Response |
| --- | --- |
| Dataset representativeness | Describe context and limit generalisation claims. |
| Leakage and split bias | Use grouped/time-aware manifests and audit duplicates and identifiers. |
| Label quality | Retain label mappings, inspect anomalies, and report dataset limitations. |
| Class imbalance | Report macro F1, per-class F1, FPR, FNR, and class-specific results. |
| Unequal tuning | Apply a shared tuning budget and validation-only selection. |
| Threshold selection bias | Fix thresholds on validation data before testing. |
| Graph-construction leakage | Restrict graphs to allowed observation windows and hide test labels. |
| Simulated drift | State drift source and do not claim universal adaptation. |
| Mininet fidelity and scale | Treat it as control-loop validation and report topology and host constraints. |
| Explanation interpretation | Measure fidelity and stability; do not equate plausible wording with faithfulness. |
| Mitigation safety | Use scoped, short-lived actions, protected flows, rollback, and bounded claims. |

## 14. Reproducibility requirements

Version the following before main experiments:

1. Dataset manifest: source identifiers, versions/dates, checksums where permitted, selected files, licences, and acquisition steps.
2. Preprocessing specification: features, label mapping, cleaning, split generation, thresholds, and graph contract where applicable.
3. Experiment configurations: model parameters, tuning budget, seeds, compute environment, software versions, and metric definitions.
4. Immutable split and time-window manifests.
5. Run outputs: predictions or sufficient aggregates, confusion matrices, thresholds, timestamps, resource samples, explanation records, controller actions, and failures.
6. Mininet scenario manifest: topology, traffic parameters, controller version, TTL values, protected-flow configuration, host specification, and repetitions.
7. Reporting template that separates validation choices from held-out test results and records deviations.

## 15. Success criteria

Success is a defensible empirical finding, not a preselected score. It requires reproducible leakage-aware benchmark results for the core datasets; a fair comparison of candidate-model conditions and limitations; evidence from at least one held-out-family setting; evidence from one time-ordered drift setting against no update; repeated Mininet control-loop runs with explanations, timing, resource use, and enforcement outcomes; and a reproducibility package sufficient to recreate configured experiments.

## 16. Negative or scientifically useful outcomes

Useful outcomes include: tabular models matching or exceeding GraphSAGE; Isolation Forest requiring an unacceptably high FPR to detect some held-out families; all candidates degrading under later windows or adaptation failing to recover performance safely; explanations lacking fidelity or stability; a cautious policy reducing false mitigation while delaying containment; and Mininet exposing latency invisible to offline scores. These outcomes are useful only when data limitations, protocol, and uncertainty are reported faithfully.

