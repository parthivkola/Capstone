# Assumptions and Decisions

This register distinguishes decisions inherited from the research design from unresolved items that must be fixed before experiments. It does not authorise implementation.

## Fixed research decisions

| Decision | Rationale and effect |
| --- | --- |
| GraphSAGE is not assumed to outperform Random Forest. | Model choice is an experimental question. GraphSAGE is included only if a leakage-free graph contract is feasible. |
| Accuracy is not the primary metric. | Use macro F1, per-class F1, FPR, and FNR to interpret imbalanced classes; accuracy remains contextual. |
| Test data must never be used for threshold selection. | Thresholds and maximum acceptable FPR are fixed on validation data before held-out testing. |
| Dataset-specific preprocessing is allowed. | Dataset schemas and labels differ. Each preprocessing policy must be documented and reproducible. |
| Datasets will not be blindly merged. | CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15, and TON_IoT have different feature and label semantics. |
| Novel behavior and known-class classification are different tasks. | Isolation Forest is evaluated as an anomaly baseline; supervised novelty experiments require a defined rejection or uncertainty score. |
| Drift adaptation requires verified labels. | Bounded updates use newly labelled, verified data after a pre-declared trigger; this is not fully autonomous continual learning. |
| Automated mitigation must be bounded and reversible. | Use temporary, flow-scoped actions, TTL, rollback, audit records, and protected-flow exemptions. |
| Offline benchmark latency differs from live SDN mitigation latency. | Offline evaluation measures detection behavior; Mininet measures detection-to-action timing and enforcement behavior. |
| Mininet validates the control loop and does not establish Internet-scale performance. | The topology is intentionally small and controlled; claims must remain within that scope. |
| The project will fully execute a core pair of datasets. | Remaining candidates are optional after the data audit, keeping the project feasible for a B.Tech capstone. |
| The full experimental Cartesian product is out of scope. | Later stages use eligible configurations selected from earlier evidence, with selections recorded before the next stage. |
| Explanation quality requires evaluation. | Fidelity and stability are measured; plausible explanation text or visuals alone do not establish faithfulness. |
| Risk-policy guardrails are fixed before live testing. | Risk mapping, thresholds, TTL values, and protected-flow rules must not be modified by the policy itself during reported runs. |
| Live test scenarios are controlled and authorised. | Use a benign baseline and one controlled scenario at a time; do not generalise these runs to production networks. |

## Unresolved assumptions to fix before execution

| Item | Why it is unresolved | Required decision point |
| --- | --- | --- |
| Core two datasets | Candidate datasets require a data audit for metadata, labels, and feasible split units. | After EXP-A01. |
| Exact feature policy per dataset | Feature availability and leakage risk depend on source schema. | Before preprocessing and split manifests are frozen. |
| GraphSAGE feasibility | A graph schema and non-leaking observation-window contract have not been specified. | Before EXP-B03. |
| Seed count and live repetition count | They must fit compute and schedule while supporting repeatable measurement. | After pilot planning, before main runs. |
| Shared tuning budget | Fairness requires the same declared resource budget across eligible candidates. | Before EXP-B01/B02/B03. |
| Maximum acceptable FPR and novelty thresholds | They must be pre-registered from validation needs; the design does not set numerical values. | Before EXP-C01/C02. |
| Drift signal, persistence rule, and window sizes | These define when an update is permitted and must be fixed before later-window evaluation. | Before EXP-D01/D02. |
| Risk mapping, confidence thresholds, TTLs, and protected-flow list | They shape live policy behavior and safety boundaries. | Before EXP-E01/E02. |
| Exact Mininet topology and authorised scenario set | Required for repeatable live evaluation but intentionally not prescribed in the research design. | Before live scenario manifest is created. |
| Explanation method per model | The method must support consistent fidelity and stability evaluation for the selected models. | Before RQ4 explanation evaluation. |
| CPU and memory measurement scope | Must consistently identify process, container, or host scope. | Before any resource measurement. |
| Latency timestamp convention and clock assumptions | Detection and mitigation latency require unambiguous start/end events. | Before live runs. |

## Decisions requiring human approval

1. Select the two core datasets after the data audit.
2. Approve whether GraphSAGE proceeds after its graph-contract feasibility review.
3. Approve the shared tuning budget and experiment repetition/seed counts.
4. Approve pre-registered novelty FPR operating point and threshold-selection procedure.
5. Approve the drift trigger, persistence rule, update window, and verified-label source.
6. Approve the live Mininet topology, authorised scenario set, protected-flow list, risk mapping, TTLs, rollback process, and always-block baseline boundaries.
7. Approve the explanation method and its fidelity/stability measurement plan.

