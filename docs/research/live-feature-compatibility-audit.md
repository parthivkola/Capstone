# Stage 7I — Live/Training Feature Semantic Alignment Audit

## Scope and conclusion

This is a repository audit and design recommendation only. No detector,
training, inference, traffic generation, or mitigation was performed.

**Recommendation: Architecture B, a separately specified live-native schema,
after observation coverage is made trustworthy.** Do not adapt Stage 5's
77-column RF input to current live telemetry. Its persisted model artifact is
not present, and its feature contract is not reproduced by Stage 4/7
observations. The existing live packet observation path also remains
unfrozen, so a live-native model is not ready to implement or train yet.

The prior compatibility audit's 77 features are reproduced in the machine
readable [feature mapping](live-feature-mapping.csv). Counts are:

| Status | Count | Consequence |
|---|---:|---|
| EXACT | 1 | `Protocol`, conditionally present as the OpenFlow `ip_proto` selector |
| DERIVABLE | 0 | No feature is deterministically derivable with unchanged meaning from the current telemetry |
| APPROXIMATION_REQUIRED | 2 | `Flow Byts/s`, `Flow Pkts/s`; rule counters divided by rule age would alter semantics |
| UNAVAILABLE | 61 | Required packet-level/bidirectional or stateful measurements are absent |
| SEMANTICALLY_INCOMPATIBLE | 13 | A related field exists but has different meaning, especially rule age and TCP match selectors |

**Important qualification:** the one exact feature does not make a usable
77-feature input. It is optional on wildcarded/non-IP rules, and the other 76
features do not have verified parity.

## Repository evidence

### Stage 5 input and preprocessing — VERIFIED FROM REPOSITORY

The authoritative feature order is in `experiments/stage5d/cse-preparation.json`
and repeated in the Stage 5D source-holdout result. The dataset is prepared
CSE-CIC-IDS2018 CICFlowMeter-derived flow rows. `Label` is the target, not a
predictor. Stage 5D uses a numeric CSV-text-to-`float32` conversion, no fitted
transform, and no imputation; rows with a non-finite projected numeric value
are excluded. Stage 5D records an RF configuration of 100 trees, maximum
depth 18, `max_features=sqrt`, `min_samples_leaf=2`, balanced-subsample class
weights, seed 2026, and one worker. These details describe the frozen offline
experiment; they are not live deployment authorization.

The compatibility JSON identifies no persisted trained model artifact in the
project tree. The result JSON/configuration is not itself a serializable
trained estimator. Thus even a perfect feature extractor would not make the
current repository able to perform RF inference without a separately
authorized artifact/provenance decision.

Stage 5D preparation excludes `Flow ID`, `Src IP`, `Dst IP`, `Timestamp`, and
`Dst Port` from the predictor matrix. The retained feature columns therefore
do not include several identifiers that might otherwise be used to group
live traffic. The Stage 5 split/protocol is not changed by this audit.

### Stage 4/7 input — VERIFIED FROM REPOSITORY

`src/sdn_defense/flow_records.py` defines `FlowRecord` from OpenFlow flow
statistics: rule selectors, datapath/table/priority/cookie, rule duration,
cumulative packet/byte counters, and observation provenance/time. These are
rule-level snapshots, not packet-flow records. `ObservationWindow` pairs
complete snapshots by canonical rule identity and derives rule-counter
deltas/rates with reset/gap semantics. Those rate names intentionally remain
`rule_packet_rate_per_second` and `rule_byte_rate_per_second`.

PacketIn events are best-effort: OVS may forward packets under learned rules
without sending them to Ryu. The previous live scan collection observed only
one probe's PacketIn metadata. A later packet-mirror B1 run exceeded the
requested 54-byte limit for 33 IPv6 frames and conflicted with the intended
source-port selection. Packet observation is consequently not a trusted,
complete packet source at present. The separate 54-byte no-options IPv4/TCP
boundary test is narrow evidence, not a universal guarantee.

## 77-feature audit

The [CSV](live-feature-mapping.csv) has one row per frozen predictor in its
original schema order. It records the local definition status, a clearly
qualified CICFlowMeter reference interpretation, numeric cast/preprocessing,
required packet granularity/directionality/state, current live fields,
compatibility, instrumentation, tests, and safe-use boundary.

### Definitions and units — VERIFIED VS UNRESOLVED

The local frozen Stage 5 artifacts establish ordered column names and numeric
conversion but do not pin the exact CICFlowMeter build/export configuration
that generated the training rows. Accordingly, the mapping does **not** claim
that a current upstream source checkout is the exact producer. The upstream
[CICFlowMeter BasicFlow implementation](https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java)
and [FlowGenerator export code](https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/FlowGenerator.java)
provide reference formulas and fields, including bidirectional packet totals,
duration from first/last timestamps, rates, and directional IAT/flag state.
They are a reference to pin and verify, not proof of the dataset's exact
producer version. Exact release, patches, timeout settings, timestamp units,
and edge-case behavior must be recovered from dataset provenance or
reconstructed with a golden-trace comparison before parity is claimed.

### Feature families — DESIGN INFERENCE GROUNDED IN THE AUDIT

- **Protocol:** exact numeric protocol selector where an OpenFlow IP protocol
  match is present. It is absent on wildcard/non-IP rules and describes a
  rule selector, not a universal per-flow observation.
- **Duration, rates, counts, packet lengths, header lengths, and packet IATs:**
  require packet-derived flow lifecycles or per-packet histories. OpenFlow
  rule duration/counters aggregate every packet matching a rule and cannot
  reconstruct directional distributions, packet order, or first/last packet
  times.
- **TCP flag fields:** 13 values are semantically incompatible with
  `FlowRecord.tcp_flags`, which is a match selector rather than counts of
  packets carrying flags. Selected PacketIn headers show individual delivered
  events only, not the complete stream.
- **Bulk/subflow/active-idle/window fields:** require CICFlowMeter-specific
  grouping, direction, flow timeout, subflow, bulk, TCP initialization, and
  activity rules. Current live telemetry has none of that full state.

For the two approximation-required rate predictors, `byte_count /`
`duration_seconds` or `packet_count / duration_seconds` would be a rate over
an OpenFlow rule's age and scope. It is not a CICFlowMeter bidirectional
packet-flow rate. Such values must not be substituted into the Stage 5 RF.

## Architecture A — reproduce Stage 5 input

### Mandatory requirements

1. Recover and pin the exact CICFlowMeter producer release/commit, export
   configuration, timeout/active-timeout values, and the data-generation
   semantics used for the CSE-CIC-IDS2018 training rows.
2. Observe every packet needed for each modeled flow, with capture coverage,
   ordering, timestamp precision, packet-loss/drop counters, and protocol
   parsing recorded. Current PacketIn is not total visibility; current OVS
   mirror evidence failed the universal truncation/selection assumptions.
3. Maintain a bidirectional flow table keyed consistently with the reference
   extractor, orient forward/backward direction from the same first-packet
   rule, account for fragments/tunnels/VLANs/options, and implement exact
   flow timeout, TCP FIN/RST termination, idle/active period, and subflow/bulk
   semantics.
4. Retain per-packet sizes and timestamps long enough to calculate directional
   lengths, counts, IAT statistics, rates, TCP flag counts, headers, windows,
   and active/idle summaries. If payload is excluded, verify which length and
   bulk fields still match the exact extractor; the 54-byte mirror does not
   expose original full frame length by itself.
5. Reproduce missing/undefined/non-finite behavior and the frozen feature
   order/dtype exactly. Current Stage 5D drops rows with non-finite numeric
   features and does no imputation; an online path may not quietly fill a
   missing live value with zero or a training statistic.
6. Provide a model artifact with hash/version, training protocol/split,
   dependency and schema provenance. No such reusable trained RF artifact was
   found in the project tree.
7. Golden-test every feature over controlled traces against the pinned
   reference build, then validate flow keys, boundary cases, data loss,
   reconnects, and missingness before comparing any predictions.

### Optional enhancements

Parallel collectors, high-availability buffering, richer application
inspection, accelerated packet processing, or hardware taps may improve
scale/coverage but are not substitutes for the mandatory semantic and
coverage checks. Full payload storage is not inherently required for every
feature, but whether payload-free observation preserves every Stage 5 feature
must be proven per field.

### Feasibility blockers

This is a substantial packet-flow-meter implementation, not a conversion from
the existing `FlowRecord`. The project does not pin the feature producer
version and has no trained model artifact. The current PacketIn path is
incomplete, while the attempted mirror path is unfrozen and had an observed
IPv6/source-selection failure. Rebuilding 77 fields correctly would need new
instrumentation and an exact reference implementation comparison, followed
by a separately authorized model-artifact decision. The frozen RF evaluation
cannot be redefined to accommodate what the live stack happens to observe.

## Architecture B — separately train a live-native model

Define a compact, versioned schema over header-only observer events and
complete OpenFlow rule-counter windows. Candidate fields and exact formulas
are in [the live contract proposal](live-feature-contract-proposal.md).
Examples include observed distinct TCP destination-port cardinality per
source/window, observed SYN-without-ACK event counts, and separately named
rule-counter deltas. Every feature is scoped to *observed* evidence and
includes collection coverage/missingness. The design does not assume that an
unseen event did not happen.

This architecture is a better fit for what the system can eventually collect,
but only after a telemetry configuration audit and bounded observer path
reliably establish source/port mapping, IPv4/IPv6 truncation, packet loss or
unknown coverage, and preservation of forwarding. The current B1 evidence
blocks treating the existing mirror as validated. The new schema needs new
training examples collected through the exact same observation code used at
inference; it cannot inherit Stage 5 metrics or model weights.

### Data availability — VERIFIED / CONDITIONAL

Local Stage 5A manifests and raw headers show that:

- CSE-CIC-IDS2018 raw CICFlowMeter CSV rows have timestamp, source/destination
  addresses, destination port, protocol, and flow-summary features. Some
  observer-style cardinalities could be recomputed by binning these flow rows,
  but the output would be based on flow records, not packet-capture events;
  exact timestamp/flow row semantics and completeness are not verified as
  equivalent to the proposed OVS mirror stream.
- CIC-IDS2017 MachineLearningCSV feature rows do not expose the full
  source-address plus timestamp/port fields needed for per-source temporal
  cardinalities in the locally audited schema.
- UNSW-NB15 and TON_IoT have endpoint/protocol and connection/event fields,
  but their record grain and aggregation semantics differ from an OVS mirror
  event. No local pipeline establishes a byte-for-byte or event-for-event
  mapping to the proposed contract.

Thus no existing dataset is currently established as faithful training data
for the proposed live-native contract. Future primary data should be collected
in controlled runs using the exact observer and feature builder. Keep the
scenario journal separate, correlate by run ID/time/scope, and call labels
scenario-derived coarse labels—not per-flow ground truth. Use complete
run-level training/validation/sealed-test splits. Use validation-only benign
runs to calibrate false-positive/action-rate operating points; hold out entire
runs and preferably parameter/topology variants for final generalization.

## Comparison and recommendation

| Criterion | A: Stage 5 77-feature parity | B: live-native schema |
|---|---|---|
| Semantic correctness | High only if exact CICFlowMeter version, lifecycle, packet coverage, and all feature formulas are reproduced; current parity fails | Can be precise by defining new measured-observation semantics and explicit coverage; not yet validated |
| Engineering effort | Very high: packet-flow meter plus 77 feature implementations and golden parity | Moderate but nontrivial: stable observer, bounded aggregation, coverage, and a smaller feature builder |
| Reproducibility | Potentially strong after producer pin and trace fixtures; currently missing both | Strong if schema, time windows, capture config, and run metadata are frozen before collection |
| Dataset compatibility | Existing prepared data matches the 77 schema, but no model artifact; does not solve live feature production | Existing datasets are not established equivalent; requires new controlled observations for primary training |
| Evaluation validity | Would preserve Stage 5 only after a separate live parity audit; cannot reuse online behavior as Stage 5 results | Supports an honest new detector protocol and run-level evaluation; no inherited Stage 5 claims |
| Live observability | Current control-plane counters and PacketIn cannot supply 76 predictors | Candidate header events and rule counters fit the target telemetry better, subject to fixing/validating coverage |
| Research value | Strong engineering replication if parity can be proven, but limited distinct research claim | Better opportunity to study evidence quality/coverage and separate gates; contribution is only established by controlled ablations |

**Primary path: B.** Preserve Stage 5 as offline research. First make the
observation source trustworthy, then preregister and collect a new
live-native dataset, then train/evaluate a new model on whole-run splits.
Do not present B as a Stage 5 RF deployment or as a demonstrated detector.
Architecture A may remain an optional future reference-parity project, but it
is not a minimal bridge.

## Future evaluation and required ablations

Separate three study layers:

1. **Instrumentation validation:** packet-boundary and family coverage,
   missing/drop visibility, timestamp/provenance, forwarding preservation,
   and replay determinism. No classifier metrics.
2. **Detector research:** rule/statistical baseline versus a lightweight
   model on identical whole-run splits; report macro F1, per-class F1,
   benign FPR, attack FNR, run-level detection latency, coverage-qualified
   rates, and resource use. Explanations must be generated from recorded
   evidence and assessed for stability/faithfulness.
3. **System evaluation:** detection-only, policy without context gates,
   evidence/coverage gate, adaptation gate, and reversible mitigation arms.
   Measure false/true containment, time to containment, legitimate-flow
   disruption, action duration, rollback correctness, decision/execution
   latency, and cost/resources. Keep policy thresholds frozen from validation.

Minimum ablations for candidate claims:

- packet evidence versus generic PacketIn/rule counters, on the same runs,
  with coverage reported separately from detection performance;
- full proposed evidence schema versus rule-counter-only and header-only
  families;
- evidence-quality/coverage gate enabled versus disabled, while holding the
  detector and validation-selected threshold fixed;
- adaptation gate with performance/uncertainty plus matured labels versus
  shift-signal-only trigger; do not interpret PSI alone as attack evidence;
- risk-aware non-reversible comparator versus the frozen reversible action
  policy, evaluated for availability cost and rollback, not only classification;
- policy arms A–D under identical held-out runs, only after a detector and
  calibration protocol are frozen.

No threshold, model, or ablation is selected by final-test results. Evaluate
confidence calibration/action-rate constraints on separate validation runs.
Use paired run-level results; multiple windows within one run are not
independent samples.

## What remains unresolved

- Exact CICFlowMeter generator version and all export/timeout semantics for
  the training files.
- Whether payload-free packet copies preserve original frame/packet size
  inputs needed by any reference feature.
- Repeatable, family-complete mirror truncation and port selection; B1 failed
  this assumption and the configuration auditor could not read live OVSDB
  under current unprivileged permissions.
- Accurate mirror/collector loss counters and host/port/source identity.
- Scenario/run label semantics at the window level and enough independent
  runs for a powered final evaluation.
- Whether a compact live-native feature set generalizes outside this
  controlled Mininet topology.
- Novelty relative to the full SDN IDS, flow monitoring, drift adaptation,
  explainability, and safe mitigation literature.

## Sources inspected

Repository sources include `AGENTS.md`; the Stage 5A audit and Stage 5C.1/5D
preparation protocols/artifacts; `experiments/stage5b/config.json`;
`experiments/stage5d/cse-source-holdout-rf.json`;
Stage 5E/5F result artifacts; `docs/architecture/stage7-real-detector-feature-compatibility.json`;
`src/sdn_defense/flow_records.py`; `src/sdn_defense/telemetry.py`;
`docs/architecture/stage7-live-observation-telemetry.md`; and the Stage 7
packet-observation audit/validation reports. Raw data was not edited or
re-prepared.

External reference code and literature links, consulted 2026-10-13, are
listed in [the novelty assessment](research-novelty-assessment.md). The
external feature definitions are not substituted for the missing exact
training-export provenance.
