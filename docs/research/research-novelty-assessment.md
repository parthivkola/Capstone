# Research Novelty Assessment — Live SDN Evidence and Safe Adaptation

## Scope

This is a focused, non-systematic literature and repository assessment made
on 2026-10-13. It does not establish novelty, implement a detector, or report
new results. Search terms covered SDN intrusion detection with OpenFlow/flow
features, packet-plus-flow monitoring, explainable SDN IDS, feature-set
generalization, and adaptive/drift-aware SDN IDS. A formal contribution claim
requires a documented systematic search and comparison against the closest
systems.

## Established prior art

### SDN flow monitoring, classification, and mitigation

Using SDN switch flow statistics for intrusion detection is established.
Prior work has combined flow-based and packet/header-based mechanisms and
used detection results for mitigation. For example, *A multi-layered
intrusion detection system for software defined networking* describes
flow-based and packet-based detection and mitigation actions
([DOI: 10.1016/j.compeleceng.2022.108042](https://doi.org/10.1016/j.compeleceng.2022.108042)).
The repository's planned use of OVS/Ryu observations, an RF or other
classifier, and OpenFlow mitigation is therefore not novel by itself.

Explainable ML applied in an SDN security architecture is also prior art.
*Explainable Security in SDN-Based IoT Networks* describes automated flow
feature extraction, Random Forest classification, and explanations in an
SDN application
([Sensors 2020, 20(24), 7326](https://www.mdpi.com/1424-8220/20/24/7326)).
An explainable model or SHAP output alone is not a defensible novelty claim.

### Feature semantics and cross-dataset generalization

The difference between feature definitions/datasets and the impact of
standardized feature sets are already research topics. The study *An
Explainable Machine Learning-based Network Intrusion Detection System for
Enabling Generalisability in Securing IoT Networks* compares NetFlow and
CICFlowMeter feature sets across datasets and emphasizes feature
generalization and explanation
([arXiv:2104.07183](https://arxiv.org/abs/2104.07183)). This supports the
importance of feature semantics, but it does not establish that this
project's particular telemetry-contract/audit workflow is novel.

The CICFlowMeter reference implementation defines packet-derived,
bidirectional flow state and feature calculations in source such as
[BasicFlow.java](https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java)
and exports columns through
[FlowGenerator.java](https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/FlowGenerator.java).
The project's Stage 5 preparation does not pin that exact producer build or
all generation settings, so this audit's central result is a project-specific
compatibility finding, not a new CICFlowMeter method.

### Drift/adaptation in SDN IDS

Adaptive and hybrid drift-aware SDN intrusion detection has been proposed.
For example, an incremental hybrid adaptive SDN NIDS combines adaptive
classification/anomaly methods and drift response
([Alqahtani, arXiv:2404.01109](https://arxiv.org/abs/2404.01109)). Therefore
adding drift signals, retraining, or a hybrid detector is not novel by
itself. The repository's Stage 5F also already evaluates source/distribution
shift with PSI, and found PSI signaled all four evaluation windows; PSI is not
attack evidence and cannot alone authorize adaptation.

### Safe action policy and reversible mitigation

Detection-to-mitigation integration and flow actions are common in SDN
security research. The cited layered IDS work includes mitigation, and the
repository's Stage 7 policy already freezes risk-aware bounded actions,
TTL/re-evaluation, protected scopes, rollback, and independent OVS
confirmation. Reversibility is a necessary safety property here, but the
architecture alone is not a demonstrated unique contribution.

## Candidate contribution — not yet demonstrated

A defensible candidate is a **traceable evidence-to-action evaluation** in
which:

1. features are defined from actual SDN-visible observations with explicit
   source, scope, timing, loss/coverage, reset, and missingness semantics;
2. training and inference use the same versioned observation builder, rather
   than mapping incompatible CICFlowMeter columns onto OpenFlow rules;
3. distribution shift, performance/uncertainty evidence, matured labels, and
   candidate validation are separate adaptation gates; and
4. detector outputs remain separated from a validation-calibrated risk policy
   and bounded, independently verified, reversible OVS actions.

This combination may be useful, but this audit has not conducted a complete
prior-art search for the combination, and no detector or end-to-end adaptive
defense result demonstrates it. Use “candidate contribution” until a scoped
systematic review and empirical comparisons establish differentiation.

The most project-specific engineering finding currently demonstrated is
negative: the Stage 5 RF's 77 CICFlowMeter predictors do not have semantic
parity with current OpenFlow rule snapshots. The Stage 7 packet-observation
path is also not frozen: the B1 repeatability attempt found 33 IPv6 frames
above the requested 54-byte boundary and inconsistent evidence about the
selected source port. This establishes a reason to separate the offline and
live planes; it does not establish detector value.

## Demonstrated contribution status

| Claim | Status now | Evidence boundary |
|---|---|---|
| Stage 5 RF works on its frozen offline evaluation features | Demonstrated within Stage 5 protocols | Offline datasets only; no live inference authorization |
| Current Stage 4 `FlowRecord` reproduces 77 RF predictors | Refuted by compatibility audit | 1 exact, 0 derivable, 2 approximation-required, 61 unavailable, 13 incompatible |
| Synthetic detection can traverse policy/enforcement | Demonstrated as integration validation | Synthetic fixtures; not detector performance |
| OVS can independently confirm bounded block/rollback in the validated test | Demonstrated in the prior isolated enforcement validation | Does not prove a real detector or attack evaluation |
| Packet-evidence coverage is repeatable and safe across tested traffic | Not demonstrated; current mechanism remains unfrozen | B1 failure stopped repeatability campaign |
| Evidence-quality/adaptation/reversibility gates improve outcomes | Not demonstrated | Requires prospective ablation experiments |
| The combined architecture is novel relative to literature | Unresolved | Requires systematic review and comparator mapping |

## Minimum literature work before claiming novelty

1. Define the claimed unit of contribution: feature semantic alignment,
   observation coverage, adaptation gating, safe action evaluation, or their
   composition.
2. Search IEEE Xplore, ACM Digital Library, SpringerLink, Scopus/Web of
   Science, arXiv, and relevant SDN/security venues using dated, recorded
   search strings and inclusion/exclusion rules.
3. Trace references/citations for flow-stat and packet-header SDN IDS,
   CICFlowMeter/NetFlow parity, explainable SDN IDS, concept-drift adaptation,
   confidence/uncertainty gates, false-positive action calibration, and
   reversible/TTL-based SDN mitigation.
4. Build a comparator matrix covering data source, observation completeness,
   feature definitions, split unit, online inference, calibration, adaptation
   evidence, mitigation scope/TTL/rollback, independent enforcement proof,
   explanations, and resource/availability evaluation.
5. Avoid novelty claims based on implementing familiar components or on
   benchmark metrics from non-comparable row splits/features.

## Minimum empirical ablations

All experiments below are future work and require their own preregistered
protocol. No thresholds should be tuned on final held-out runs.

### Evidence and feature-quality ablations

- Same held-out runs with generic PacketIn/rule counters versus a validated
  bounded packet-header observer; first report capture/coverage/loss, then
  compare detection only on valid, coverage-qualified examples.
- Proposed combined live schema versus rule-counter-only and packet-header-
  only feature groups.
- Coverage/missingness gate enabled versus disabled, holding model, split,
  and validation-selected operating point fixed; measure missed/invalid
  evidence and false actions as well as classification.
- Compare observer feature output against an independently instrumented
  ground-truth source in a small validation harness. Ground truth must not be
  a detector feature and must be kept separate from the test input pipeline.

### Adaptation ablations

- HOLD-only/static model versus update after distribution-shift signal alone
  versus update only after shift plus matured-label performance or calibrated
  uncertainty evidence.
- Candidate update with and without sealed-anchor validation/rollback,
  measuring post-update per-class behavior, benign FPR, update rejection,
  latency, and resource cost.
- Label delay and bounded-buffer behavior under run-level temporal splits;
  current-window and sealed-test labels must never enter triggering/training.

### Decision and mitigation ablations

- Frozen Policies A–D after thresholds are selected on disjoint validation
  runs, evaluated on the same sealed runs.
- Risk-aware policy without reversible TTL/re-evaluation versus risk-aware
  reversible policy, with matched detector decisions; measure attack
  containment and legitimate-flow disruption/mitigation duration/rollback.
- Independent OVS confirmation and exact cookie/scope rollback versus
  submission-only measurement; report enforcement failure and latency rather
  than treating FlowMod submission as successful action.

### Evaluation unit and metrics

Split whole scenario runs, not rows/windows from the same run. Hold out
parameter variants or topology/device groups where feasible. Use validation
runs to calibrate confidence/action-rate constraints. Report macro F1,
per-class F1, benign FPR, attack FNR, coverage-qualified detection latency,
false-block rate, containment rate/latency, legitimate disruption, action
duration, unnecessary action count, rollback correctness, policy/execution
latency, CPU, memory, and inference/explanation cost. Treat run as the
experimental unit; windows from the same run are correlated.

## References

- Alqahtani, A. H. “An incremental hybrid adaptive network-based IDS in
  Software Defined Networks to detect stealth attacks.” arXiv:2404.01109
  (2024). <https://arxiv.org/abs/2404.01109>
- “A multi-layered intrusion detection system for software defined
  networking.” *Computers & Electrical Engineering* (2022), DOI
  10.1016/j.compeleceng.2022.108042.
  <https://doi.org/10.1016/j.compeleceng.2022.108042>
- “Explainable Security in SDN-Based IoT Networks.” *Sensors* 20(24), 7326
  (2020). <https://www.mdpi.com/1424-8220/20/24/7326>
- Sarhan et al. “An Explainable Machine Learning-based Network Intrusion
  Detection System for Enabling Generalisability in Securing IoT Networks.”
  arXiv:2104.07183 (2021). <https://arxiv.org/abs/2104.07183>
- CICFlowMeter upstream reference source:
  <https://github.com/ahlashkari/CICFlowMeter> (BasicFlow and FlowGenerator;
  current upstream files consulted, exact dataset producer commit unknown).

## Stage 7I.1 update — contract and falsifiable comparisons

This update preserves the assessment above. The versioned live-native
specification is in
[`live-feature-contract-v1.md`](live-feature-contract-v1.md); planned
fixture-level validation is in
[`live-feature-validation-plan.md`](live-feature-validation-plan.md), and
prospective hypotheses/ablations are consolidated in
[`research-hypotheses-and-ablations.md`](research-hypotheses-and-ablations.md).

**Established evidence is unchanged:** current OpenFlow rule-counter windows
are not CICFlowMeter flows; the Stage 5 RF remains offline-only; and packet
observation is unfrozen after the B1 overlength/source-selection discrepancy.
The four rule-counter deltas/rates can be specified with existing telemetry
semantics, but do not establish packet/endpoint coverage or detector utility.
No packet-event predictor is promoted to v1. No new data or result was
collected for this addendum.

**Falsifiable candidate claim:** a single versioned observation builder,
explicit coverage validity, delayed-label adaptation gates, and
switch-confirmed reversible actions may produce a more auditable and safer
live defense evaluation than feature- or decision-only baselines. This claim
will be rejected if prospective whole-run comparisons fail to show the
pre-registered benefit/cost trade-offs. Planned contrasts include static vs
adaptive detector, evidence-unaware vs evidence-gated decisions, baseline vs
risk-bounded reversible mitigation, submitted vs independently confirmed
enforcement, and performance across measured coverage levels. Primary
measures include macro/per-class F1, FPR/FNR, false mitigation rate, benign
service disruption, confirmation and rollback success, adaptation cost, and
detection/decision latency.

These are planned experiments, not results. Prior art already covers SDN
flow/packet IDS, explainable IDS, adaptation, and mitigation. The potentially
differentiating claim is the empirically evaluated composition of semantic
feature parity, measured evidence coverage, separate adaptation/action
gates, and independent reversible enforcement. A systematic prior-art
comparison and the listed ablations remain necessary; novelty and improvement
are unresolved.
