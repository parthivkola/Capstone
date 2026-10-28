# Stage 7I.1 — Research Hypotheses and Ablations

## Status

This document preregisters candidate questions and comparisons for future
work; it contains no new experiment, detector, or result. All hypotheses are
falsifiable and may be rejected. The packet observation mechanism remains
unfrozen, so detector experiments are blocked until its evidence coverage and
byte-exposure boundary are validated. Stage 5 and the Stage 7 defense
protocol remain frozen.

## Research question

Can a detector trained and evaluated on a versioned, live-native observation
schema provide sufficiently reliable evidence for a separate, coverage-aware
and risk-bounded defense policy, and do the coverage, adaptation, and
reversibility gates measurably improve security/availability outcomes?

“Sufficiently reliable” must be operationalized in a separately frozen
protocol using disjoint validation runs and the existing policy constraints.
This document intentionally chooses no numerical operating point.

## Falsifiable hypotheses

### H1 — Live-native feature semantics

**Hypothesis:** using one identical, versioned feature builder for data
collection/training and inference produces stable feature values on held-out
controlled runs and avoids the semantic mismatch found between Stage 5
CICFlowMeter features and Stage 4 OpenFlow rule snapshots.

**Falsification:** golden fixtures or independent replay cannot reproduce the
same values/order/validity states, or held-out runs reveal a material
collector/feature-builder semantic discrepancy.

### H2 — Evidence coverage gating

**Hypothesis:** conditioning decisions on explicit observation validity and
coverage reduces false actions and unjustified absence-based conclusions
relative to an otherwise identical evidence-unaware policy, at a measurable
availability or missed-event cost.

**Falsification:** the gate does not reduce false mitigation/unsupported
absence in held-out runs, or its cost is disproportionate under the
pre-registered multi-objective criteria.

### H3 — Adaptation gate

**Hypothesis:** adapting only after shift plus matured behavior/performance or
validation-calibrated uncertainty evidence, eligible delayed labels, bounded
fit, candidate validation, and anchor protection has lower degradation or
false-action cost than a static detector and than a shift-only update policy,
after accounting for adaptation cost.

**Falsification:** the gated policy fails to improve pre-registered
held-out-run outcomes, causes anchor regression, or its cost exceeds any
benefit. PSI alone is not attack evidence and is not an adaptation
authorization.

### H4 — Reversible bounded mitigation

**Hypothesis:** risk-bounded, exact-scope, TTL-limited mitigation with
independent enforcement confirmation and rollback reduces legitimate-flow
disruption and unresolved action failures relative to an immediate/unbounded
baseline, while retaining adequate containment on eligible controlled runs.

**Falsification:** the bounded policy does not improve availability/rollback
measures or fails containment criteria fixed before testing.

### H5 — Coverage-level dependence

**Hypothesis:** detector behavior degrades in a measurable, monotonic or
otherwise reproducible way as observation coverage falls, and explicit
coverage gating prevents incomplete evidence from being treated as a
negative observation.

**Falsification:** repeated held-out runs do not show stable relationship
between measured coverage strata and performance, or the coverage field fails
to identify the induced/observed loss conditions. Any coverage strata must
come from safe, pre-registered instrumentation conditions, not from
post-hoc filtering to favor results.

## Planned comparisons

| Comparison | Controlled contrast | Required controls |
|---|---|---|
| Static vs adaptive detector | Frozen static model vs candidate update gate using matured evidence | Same feature schema, whole-run split, candidate evaluation data, anchor set, and seeds; report update cost and rollback/rejection. Include shift-only as a negative-control policy, not an assumed winner. |
| Evidence-unaware vs evidence-gated decision | Same detector predictions with coverage/validity gate disabled vs enabled | Same validation-calibrated thresholds and held-out runs; log incomplete windows and abstentions; never convert missingness to zero. |
| Unbounded/baseline mitigation vs risk-bounded mitigation | Protocol-approved baseline arm vs exact-scope TTL/re-evaluation/rollback arm | Same eligible decisions, protected-flow configuration, workload, and independent switch-state verifier. Do not implement permanent automatic block without protocol authorization. |
| Requested vs independently confirmed enforcement | Submission-only count vs independently observed exact-cookie/scope state | Keep outcomes distinct: SUBMITTED is not CONFIRMED. Measure confirmation latency, failures, and exact rollback. This is an instrumentation comparison, not permission to weaken confirmation semantics. |
| Coverage levels | Compare predeclared levels/conditions of measured observer coverage | Independently measure offered/generated evidence and collector accepted/dropped/unknown counts. Include unknown coverage and unsupported IP families as explicit strata. |
| Feature-source ablation | Rule-counter-only vs packet-header-only vs combined, only after packet source validation | Same whole-run partitions and fixed model-selection procedure; treat rule counters as rule-level and packet observations as observer-delivered events. |

Policy A–D definitions remain governed by the frozen Stage 7 protocol. This
document does not redefine them, tune their thresholds, or claim they have
been experimentally compared on attack traffic.

## Evaluation design

### Experimental unit and partitions

Use whole controlled runs as the primary independent unit. Keep every window
from one run in one partition. If run variants share a topology/configuration,
seed, or scenario generation process that makes them dependent, define a
stricter group and keep that group intact. Prefer held-out scenario parameter
combinations or host/topology variants for a generalization analysis. Use
explicit benign-only runs for false-positive and false-mitigation assessment.

Train on training runs only. Select model/configuration and calibrate
confidence/action operating points on disjoint validation runs. Seal test
runs until all features, preprocessing, thresholds, policies, adaptation
gates, and metrics are frozen. Report per-run distributions and uncertainty;
do not treat overlapping windows as independent samples. Stage 5 data and
splits do not become the training source for this live-native schema unless a
separate audit proves exact semantics, which is not currently established.

Scenario journals remain separate contextual artifacts. Scenario-derived
labels are coarse run/window labels and not per-flow ground truth. Define
time/scope overlap, warmup/cooldown, ambiguous intervals, and benign periods
before inspecting test outcomes. Uncertainly attributed windows stay
unlabeled/excluded under the pre-registered rule.

### Primary metrics

Report as applicable, with denominators and run-level uncertainty:

- macro F1 and per-class F1;
- false-positive rate and false-negative rate, with benign/attack class
  definitions and valid-coverage population stated;
- false mitigation rate on benign eligible intervals;
- benign service disruption (duration and affected-flow count under the
  controlled testbed definition);
- action confirmation rate, distinguishing submitted, confirmed, failed,
  rejected, and unsupported actions;
- rollback success rate and rollback latency, with independent switch-state
  verification;
- adaptation cost: training/update time, CPU, memory, candidate rejection,
  rollback, and any anchor performance change;
- detection latency and policy-decision latency, measured from the relevant
  observation/event time and reported only for coverage-qualified evidence.

Also report containment rate/latency, mitigation duration, unnecessary action
count, resource overhead, and missing/unknown coverage where the future
protocol supports them. Do not collapse security and availability into a
single scalar unless cost weights are selected and justified before test
results; a multi-objective table is the default.

## Minimum ablations before a contribution claim

1. **Coverage gate:** identical evidence/model with gate on/off, including
   incomplete and unknown-coverage runs.
2. **Evidence family:** rule counters vs validated packet metadata vs
   combined, with feature builder and split held fixed.
3. **Adaptation:** static vs full gate, plus shift-only and no-anchor controls;
   report update rejection/rollback and cost.
4. **Action safety:** protocol baseline vs risk-bounded reversible actions;
   report both service disruption and containment.
5. **Confirmation:** local submission accounting vs independent OVS
   confirmation, while retaining the same enforcement outcome definitions.
6. **Coverage robustness:** held-out runs stratified by independently
   measured coverage and supported IP family/protocol.
7. **Explanation, if later included:** evidence-level explanation fidelity
   and stability under repeated seeds/nearby windows; plausible wording alone
   is not evidence of faithfulness.

No novelty or improvement claim follows from implementing these controls.
Each comparison must be frozen in a future protocol, and negative results
must be retained.

## Current evidence versus future work

**Established:** Stage 5's RF is an offline 77-feature CICFlowMeter model;
current Stage 4 FlowRecord semantics do not provide its required feature
parity. Stage 5F found PSI signaled every evaluation window and does not
authorize adaptation by itself. Stage 7's bounded enforcement substrate has
been independently verified in its controlled integration tests. The
packet-mirror B1 run did not validate a universal snaplen boundary or
intended source selection.

**Proposed, not demonstrated:** live-native feature parity, evidence-gated
decision benefit, adaptive benefit, mitigation utility, coverage robustness,
and research novelty of the combined system. No detector metrics or live
effectiveness results exist under this contract.

## Novelty position

Prior work already includes SDN flow/packet IDS, explainable SDN IDS, adaptive
or drift-aware IDS, and detection-triggered SDN mitigation. The candidate
contribution is narrower: an auditable chain from semantically defined,
coverage-qualified live observations through independently evaluated
adaptation/action gates to switch-confirmed reversible enforcement. This is a
hypothesis for comparative study, not an established novelty claim. A
scoped systematic literature review and the ablations above are prerequisites
for a stronger claim; see
[`research-novelty-assessment.md`](research-novelty-assessment.md).
