# Stage 7I.2 — Offline Rule-Counter Feature Builder

## Status and boundaries

`src/sdn_defense/live_features.py` implements the first offline feature
builder for the live-native rule-counter contract. Its tests use synthetic
`FlowRecord` snapshots only. It does not read live telemetry, launch network
services, inspect packet data, train/infer a model, produce `DetectionResult`,
or invoke policy/mitigation. This is implementation validation against the
contract, not validation against live traffic.

Stage 5 remains frozen and its RF is not used. FlowRecord retains its Stage 4
meaning as an OpenFlow rule-stat snapshot. Packet-derived features remain
excluded because packet observation is unfrozen.

## Existing interfaces and decisions

- `FlowRecord` is an immutable parsed flow-stat row with cumulative rule
  packet/byte counters and rule selectors.
- `FlowSnapshot` associates a FlowRecord with collector monotonic time and an
  optional run ID without changing the Stage 4 record.
- `CounterDeltaEngine` pairs successive snapshots and emits
  `ObservationWindow`; it has an optional maximum-gap setting.
- v1 requires a maximum admissible pair interval to be fixed before a future
  dataset is collected, but the numeric value is not frozen. The new builder
  therefore requires `maximum_gap_seconds` explicitly. The code has no
  default and these unit-test values are synthetic fixture settings, not
  research thresholds.
- v1 treats counter decreases as reset/wrap ambiguity. The builder does not
  infer modulo wraparound; it returns unavailable invalid evidence.
- Rates require collector monotonic timing. UTC wall-clock fallback is not
  substituted for an absent monotonic clock.

## Stage 7I.3 — snapshot-pairing prerequisite audit (2026-10-21)

This addendum separates semantics implemented in code from provenance that
the offline builder cannot establish by itself.

### Verified in code and synthetic tests

- `RuleCounterFeatureBuilder` requires a finite, positive
  `maximum_gap_seconds`; there is no default. It accepts a pair when elapsed
  monotonic time is equal to the configured limit and rejects it when elapsed
  time is greater. Rejection returns null predictors with `INCOMPLETE` state
  and `OBSERVATION_GAP_EXCEEDS_CONFIGURED_LIMIT`.
- `CounterDeltaEngine` has an optional gap; with no value it applies no gap
  cutoff. The Stage 2 Ryu controller currently constructs it with a literal
  `30.0` seconds. This is existing runtime behavior, not a preregistered or
  measured Stage 7I feature-window policy and not a default for
  `RuleCounterFeatureBuilder`.
- Snapshot pairing uses collector monotonic nanoseconds for rates and requires
  increasing aware UTC timestamps as a separate ordering check. Missing
  monotonic time, equal/reversed time, run-boundary crossing, duplicate record,
  rule-identity change, incomplete collection, epoch mismatch, counter
  decrease/reset/wrap ambiguity, or an over-limit gap produces unavailable
  features. Equal counters yield measured zero only on an otherwise valid
  pair. No reset or gap value is imputed.
- `SnapshotEvidence` rejects a missing collection ID, non-boolean completeness
  flag, or empty datapath epoch ID. A boolean `False` completeness flag is
  rejected by the builder as incomplete. These are input-shape safeguards;
  they do not authenticate the source of a `True` flag or epoch string.
- The multipart assembler returns a collection only after a final multipart
  part, retains datapath/XID identity, and emits incomplete timeout/disconnect
  records. The Ryu handler writes snapshots only for completed collections
  whose run ID is still active. The controller calls the counter engine's
  datapath-disconnect boundary handler.

### Gap policy decision: BLOCKED

The contract's units and comparator are established: seconds measured between
collector monotonic completion times; `elapsed <= configured_limit` is
eligible, `elapsed > configured_limit` is incomplete. A missing/invalid clock
is invalid, not substituted by wall-clock time. The limit must be frozen in a
versioned collection/feature configuration and the identical value must reach
the collector pairing path and the feature builder.

No evidence in the repository justifies a numeric maximum for live feature
windows. The Stage 2 controller's 30-second literal is not evidence that a
30-second interval is statistically or operationally appropriate for feature
collection. The unit tests use synthetic limits only. Therefore **no numeric
limit is selected or frozen here**. Before choosing one, the separately
approved safe validation must measure the real monitor cadence, multipart
completion latency, scheduler delay, gaps and reconnect behavior using
rule-counter-only telemetry. It must not use attack labels or model outcomes
to choose the limit. The eventual value and boundary rule must be frozen
before any live-native dataset is collected.

### Completeness and datapath-epoch provenance: BLOCKED for live use

The builder currently accepts caller-supplied `collection_complete: bool`
and a non-empty `datapath_epoch_id`. Synthetic tests prove the builder rejects
false completeness, missing fields, and mismatched epochs. They do **not**
prove a live source generated those fields correctly. For live eligibility,
each snapshot pair must reference two collection IDs whose recorder events
show a completed multipart response (final part received, matching XID and
datapath, no timeout, disconnect, duplicate, rejection, or run-boundary
crossing). A positive boolean copied from outside that lifecycle is not
adequate provenance.

Likewise, each epoch ID must be created by the collector when a datapath
connection becomes active and invalidated on disconnect; its provenance must
link to connection-boundary events. A caller-provided arbitrary non-empty
string is not proof of a datapath epoch. If either record is absent, ambiguous,
or cannot be tied back to source events, the pair must remain unavailable and
must not enter training. `datapath_id` alone does not distinguish reconnects.

### Evidence status and current gate

| Item | Status | Evidence / remaining work |
|---|---|---|
| Four feature names/order/units | Implemented, contract specified | Builder constant and synthetic tests; no change in this addendum. |
| Invalid and measured-zero separation | Implemented for represented input states | Synthetic tests cover equal counters vs missing/reset/gap. |
| Gap comparison boundary | Implemented and now explicitly tested | Equality is accepted; strictly greater is incomplete. Numeric research limit remains blocked. |
| Multipart completion | Implemented in assembler and Ryu handler | Unit tests and prior telemetry artifact exist; no live experiment run in this task. |
| Complete flag provenance | Structurally required; live origin not verified by builder | Must link each feature input to recorder `flow_collection` complete record. |
| Datapath epoch | Required by builder; live epoch creation is not represented on `FlowSnapshot` itself | Must add/verify source-backed epoch association before live feature generation. |
| Counter decreases | Invalid, null features | No modulo wrap inference. |
| Stage 2 runtime `30.0s` limit | Existing implementation only | Not adopted as a live-feature contract value. |

**Stage 7I.3 outcome: not ready for live feature collection or inference.**
The deterministic feature builder is ready for offline synthetic testing. The
next safe prerequisite is a reviewed collector-provenance design that links
complete collection IDs and connection epochs to each input snapshot, followed
by an approved rule-counter-only quality validation. The numeric maximum gap
decision remains open until that validation provides cadence and gap evidence.
No packet observation, detector, model, risk, or mitigation path is enabled.

## Data flow

```text
FlowRecord + collector timing/run ID
          ↓
SnapshotEvidence
  (collection ID, complete flag, datapath epoch)
          ↓
explicit SnapshotPair
          ↓
RuleCounterFeatureBuilder
          ↓
LiveRuleFeatureVector v1
  ├── predictor projection: fixed four-column order + per-value validity
  └── provenance: pair/window/rule/run/source IDs and interval metadata
```

The builder receives an explicit pair. It does not search, sort, or infer
which snapshots belong together. `build_many` only sorts already-built
vectors deterministically; it does not pair records.

## Accepted inputs and validation

`SnapshotPair` includes a stable caller-supplied `pair_id` and optional
previous/current `SnapshotEvidence`. Each evidence item contains a
`FlowSnapshot`, collection ID, explicit complete/incomplete status, and
datapath connection epoch ID. The pair may also carry collector,
telemetry-provenance, and OVS versions. Unknown versions remain null. The
schema-builder version is fixed as `stage7-live-feature-builder-v1`.

The builder rejects or marks values unavailable for:

- absent previous or current snapshots;
- incomplete statistics collections;
- datapath epoch or run boundary;
- duplicate record IDs;
- missing/ambiguous canonical rule identity or changed rule identity;
- changed source, missing timestamps, missing monotonic timing, zero or
  negative elapsed interval, or out-of-order snapshots;
- interval greater than the required caller-supplied maximum gap;
- missing, negative, non-integer, out-of-range, decreasing, or uint64-wrap-
  ambiguous counters.

No feature is imputed. Structural failures yield null values with an explicit
state and reason. A missing packet counter invalidates packet delta/rate;
byte delta/rate may remain measured if their own counters and the shared pair
are valid. A valid equal-counter pair yields measured numeric zero. A first
snapshot is not zero traffic.

## Features and exact semantics

The versioned schema ID is `stage7-live-rule-window-v1`; schema version is
`1`. `feature_order` is fixed:

1. `rule_packet_delta`: current cumulative OpenFlow rule packet counter minus
   previous counter, packets.
2. `rule_byte_delta`: current cumulative OpenFlow rule byte counter minus
   previous counter, bytes.
3. `rule_packet_rate_per_second`: packet delta divided by measured monotonic
   elapsed seconds, packets/s.
4. `rule_byte_rate_per_second`: byte delta divided by measured monotonic
   elapsed seconds, bytes/s.

The interval is between two explicitly paired complete statistics
collections for one canonical rule identity and datapath epoch. The features
remain rule-level and can aggregate multiple transport conversations. They
do not reproduce packet flow duration, packet IAT, bidirectional flow counts,
or CICFlowMeter features. No aggregation across rules is performed because
overlapping rule matches may count the same traffic more than once.

## Training/inference interface and serialization

`LiveRuleFeatureVector.predictor_dict()` returns only the schema version,
schema ID, fixed feature order, numeric values, and per-feature validity.
Identifiers, run metadata, rule identity, timestamps, labels, scenario names,
and evaluation outcomes are excluded from that projection. The full
`to_dict()`/`to_json()` representation retains provenance separately. Strict
`from_dict()`/`from_json()` validation rejects changed schema, order, feature
set, state/value inconsistency, and malformed metadata.
The full record separately carries `coverage_state`, source record IDs,
datapath epoch, and source-version provenance. Counter coverage describes
statistics collections only; it is not packet-observer coverage.

Future training and inference adapters must call this same deterministic
builder and consume the same `predictor_dict()` contract. Any fitted
transformation belongs in a separately versioned training-only artifact;
this component performs no fitting, scaling, feature selection, or
imputation. It creates no label field and accepts no scenario label.

## Tests

`tests/unit/test_live_feature_builder.py` covers positive deltas/rates,
measured zeros, missing snapshots and counters, incomplete collections,
changed rule/epoch/run identity, resets and uint64 wrap ambiguity, duplicate
and out-of-order snapshots, zero duration, excessive gaps, missing monotonic
timing, deterministic ordering for multiple rules, schema/order stability,
serialization round trip, predictor metadata exclusion, invalid evidence
not becoming zero, and explicit gap configuration. All fixtures are
synthetic; no network services or packet data are used.
For this implementation, the focused builder plus telemetry suites passed 33
tests; the full suite passed 234 with two privileged live-enforcement tests
skipped by their opt-in guards. Ruff passed, and targeted mypy passed for the
builder and its tests. These results validate software behavior on fixtures,
not live telemetry.

## Limitations and prerequisites for live use

- No numeric maximum gap/polling interval has been selected in a frozen
  research protocol. The caller must provide one; it must be frozen before
  data collection.
- The pair wrapper's `collection_complete` and `datapath_epoch_id` are
  supplied metadata. This module does not verify a live multipart collector
  or independently establish connection epochs.
- The builder cannot detect an omitted rule unless the caller pairs a
  complete switch snapshot and reports the absence; no pair is not a zero.
- A rule counter is not a packet-level flow. It cannot split aggregate counts
  by endpoints not selected by the rule.
- Packet observation remains unfrozen after B1's oversized IPv6 frames and
  unresolved mirror selection. This implementation consumes no packet
  observations and resolves none of those issues.
- There is no detector, trained model, inference, threshold calibration,
  action authorization, live mitigation, or live feature parity result.

Before live observation, separately freeze the maximum gap and collection
eligibility protocol, independently verify collection-complete and datapath
epoch metadata in the real source, and resolve the packet-observation safety
blockers before proposing any packet-derived feature. This builder itself
can now be tested offline with synthetic inputs.

**Stage 7I.3 verification performed for this reconciliation:** the focused
command `.venv/bin/python -m pytest tests/unit/test_live_feature_builder.py tests/unit/test_live_observation_telemetry.py -q` completed with 36 passed.
Ruff passed for the two test modules and `src/sdn_defense/telemetry.py`;
targeted mypy passed for those three Python files. SHA-256 checks matched all
24 raw dataset inventory entries and all 7 Stage 5D prepared outputs, plus
the recorded Stage 5C.1, Stage 5D, Stage 5F, and Stage 7 protocol/reference
hashes. No repository commit could be recorded because this workspace has no
Git metadata. These checks validate synthetic software behavior and artifact
integrity only; they do not validate a live collection cadence or provenance.

## Stage 7I.3 — source-record provenance audit

`src/sdn_defense/live_provenance.py` adds a pure, offline audit over the
append-ordered telemetry recorder records. `RuleCounterFeatureBuilder.build`
remains the deterministic transform for unit/synthetic pairs.
`build_source_verified` first requires the provenance audit to accept the
pair, then applies the unchanged four-feature builder and caller-supplied gap
limit. It does not select a gap value.

The audit result exposes typed `CollectionProvenance` and
`DatapathEpochProvenance`. Collection terminal states include complete,
incomplete, timed out, cancelled, disconnected, and ambiguous; only `COMPLETE`
is eligible. Datapath lifecycle states distinguish active, closed, and
ambiguous epochs. These are evidence-contract states, not new Ryu runtime
events: the current controller does not emit the epoch identifiers required
to construct an accepted live provenance result.

### Source lifecycle found in code

The current Ryu path has these steps:

1. `_request_flow_statistics` assigns the OpenFlow XID and calls
   `MultipartFlowStatsAssembler.start`, capturing the datapath/XID, run ID and
   collector start times. Ryu records a `flow_collection` event with
   `state=requested` before sending the request.
2. The reply handler adds each part under datapath/XID. The assembler returns
   a `FlowStatsCollection` only on a reply without the multipart-more flag.
   Timeout, disconnect, duplicate/unmatched replies, and run changes are
   recorded as incomplete/rejected conditions. A successful empty final part
   is still a complete collection.
3. Ryu records `complete=true` and then emits `flow_snapshot` records carrying
   the collection ID, run ID, FlowRecord and collector monotonic timestamp.
4. Datapath lifecycle records currently record connected/disconnected state
   and datapath ID, but have no connection epoch ID. An early disconnect may
   have no datapath ID. The collection request/completion and snapshot records
   likewise have no epoch ID.

This supports collection completion and snapshot-to-collection linkage in
source code, subject to event ordering and JSONL integrity. It does not
currently support source-backed connection-epoch linkage. The recorder file
is not cryptographically authenticated; this is structural lineage checking,
not tamper-proof provenance.

### Offline source audit

`audit_snapshot_pair_provenance` requires exactly one request and one
successful completion for each collection ID; rejects incomplete terminal
events, mismatched XID/datapath/run IDs, missing snapshot-to-collection
references, missing or contradictory epoch IDs, absent/closed/ambiguous
connection lifecycle, cross-epoch and run boundaries, and invalid record
ordering. `build_source_verified` raises before feature computation on an
audit rejection. Counter decrease/reset, invalid timing, and gap handling
remain the existing builder's responsibility; they remain unavailable, never
imputed. The caller must still provide a future approved maximum gap.

Synthetic recorder fixtures exercise a same-epoch accepted pair, one- and
multi-part completion metadata, timeout/incomplete rejection, reconnect and
ambiguous disconnect rejection, run-boundary rejection, and the existing
reset/timing/gap cases. These fixtures are synthetic. The current Ryu records
are expected to fail `build_source_verified` because `datapath_epoch_id` is
absent. Thus no live-use gate is complete.

### Remaining prerequisite

Before live feature collection, Ryu must create an epoch ID from each observed
connection lifecycle and include it in connection-boundary, collection
request/completion/incomplete, and snapshot records. Requests and replies
must be associated with the active epoch; disconnect/reconnect and an
unidentified disconnect must invalidate affected pending collections and
feature pairs. Then validate the emitted JSONL lineage with an approved,
rule-counter-only test. Only after cadence/gap evidence is reviewed may a
numeric maximum-gap policy be frozen. No network run was performed for this
addendum.

**Stage 7I.3 final check:** the focused feature/telemetry suites passed 41
tests; Ruff passed on changed Python files; targeted mypy passed on changed
Python files. Post-task hashes matched 24 raw dataset inventory entries, 7
prepared outputs, and 7 frozen protocol/reference hashes. This is synthetic
offline validation only.

## Stage 7I.3 implementation addendum — epoch propagation

The source instrumentation has now been implemented offline in
`networking/ryu/stage2_controller.py`, `src/sdn_defense/telemetry_io.py`, and
the additive `FlowSnapshot` fields in `src/sdn_defense/telemetry.py`. This
addendum supersedes the earlier statement above that the Ryu source does not
emit epoch IDs. It does **not** supersede the live-use gate: Ryu was not run
for this change, so real event lineage remains unvalidated.

### Implemented lifecycle semantics

- `DatapathEpochTracker` creates a controller-process nonce once, then mints
  each epoch from that nonce, the observed datapath ID, and a monotonic
  controller-local connection sequence. It receives the Ryu datapath object
  from `MAIN_DISPATCHER` or `EventOFPSwitchFeatures`; duplicate observations
  of the same active object are idempotent. A distinct object for an already
  active datapath closes the prior epoch as ambiguous and starts a new one.
- Multipart requests retain the source-generated epoch. Collection IDs
  include epoch, datapath ID, and XID. Replies are resolved against the exact
  Ryu datapath object and matched on datapath/XID/epoch; a reply from a closed
  or unknown connection is rejected before snapshot emission.
- Complete records explicitly carry `terminal_state=COMPLETE`. Timeout,
  disconnection, run change, malformed/duplicate multipart part, shutdown,
  and ambiguous invalidation carry a non-complete terminal state and do not
  produce snapshots. A reply arriving at or after the configured assembler
  timeout is rejected even if the periodic timeout sweep has not run yet.
- Multipart part timestamps must increase monotonically. XIDs must increase
  within an epoch; a stale or reused XID fails closed. An unidentified
  disconnect invalidates every active epoch and pending collection and
  records the affected epoch IDs. A late disconnect for a known old
  connection does not invalidate its replacement connection.
- Observed run-context changes cancel pending collections from the prior
  context. A completed collection whose run no longer matches is recorded as
  cancelled and produces no snapshots.
- Every Ryu-created `FlowSnapshot` and JSONL `flow_snapshot` record now carry
  both `collection_id` and `datapath_epoch_id`. `FlowRecord` and the four
  feature names, order, units, and rule-counter meanings are unchanged.
- Structured Ryu connection-boundary, collection-request, and completed-
  collection log events carry the same epoch/correlation fields as JSONL.
- Recorder envelope schema 2 is used for connection-boundary, flow-collection,
  flow-snapshot, incomplete-collection, and recorder-metadata records. The
  read-only validator continues to accept historical schema-1 records; it
  does not retrofit epoch provenance onto them.

The source audit additionally requires a matching connection-boundary record
whose epoch ID agrees with controller-instance nonce, datapath ID, and sequence.
It requires one request, one complete terminal record, and a uniquely linked
snapshot per source record. It rejects missing/contradictory epoch linkage,
incomplete terminal events, stale ordering, reconnect/disconnect boundaries,
run boundaries, and cross-epoch pairs. These recorder checks are structural
and do not cryptographically authenticate JSONL files.

### Offline evidence and remaining gate

Synthetic lifecycle tests cover two connection objects for one datapath,
idempotent duplicate connection notifications, reconnect cancellation and
same-XID reuse in a new epoch, old-connection replies, unknown/global
disconnect cancellation, timeout and late replies, duplicate terminal replies,
monotonic part ordering, run-boundary cancellation, typed snapshot linkage,
and the existing counter reset, gap, and timing behavior. They are not live
Ryu validation.

**Current status:** epoch instrumentation is implemented and tested offline;
real Ryu event lineage is not yet validated; the live feature-collection and
inference gate remains **BLOCKED**. The prior 30-second `CounterDeltaEngine`
runtime setting was not changed and is not an approved maximum-gap policy.
No numeric gap is selected here. The next permitted step is a separately
approved rule-counter-only validation that checks actual emitted connection,
collection, terminal, and snapshot lineage, then measures snapshot cadence,
collection completeness, and observed gaps. Review those measurements before
choosing any maximum-gap policy. Packet-derived telemetry remains disabled.

**Validation for this addendum:** 47 focused offline telemetry/feature tests
passed after the final test additions; Ruff passed on the changed Python
files. Targeted mypy passed for `telemetry_io.py`, `telemetry.py`, and
`live_provenance.py`; including the Ryu controller reports one existing
`PacketEvidenceBudget | None` narrowing error at `stage2_controller.py:497`.
No Ryu runtime, network, or privileged validation was performed.

## Stage 7I.3 review addendum — live lineage gate remains blocked

The source review confirms the callback chain in code: `MAIN_DISPATCHER`
state-change and `EventOFPSwitchFeatures` both feed the epoch tracker;
`switch_features_handler` requests initial flow stats; the monitor requests
later snapshots; each request stores datapath/XID/epoch/run identity before
send; reply handling resolves the exact datapath object and only publishes
after the final multipart flag; timeout, disconnect, shutdown, replacement,
and observed run changes emit non-complete outcomes. The unknown-DPID
disconnect path invalidates all active epochs and pending collections. These
are implementation facts, not evidence that the deployed Ryu event stream
follows the expected lineage.

The source-verification path requires schema-2 connection, request/completion,
and snapshot records. The general JSONL replay validator accepts historical
schema-1 envelopes for compatibility, but those records do not meet the
source-verified pair gate. An offline regression test now checks that schema-1
records cannot pass `build_source_verified`.

The audit is structural consistency checking over plain JSONL, not
cryptographic authentication. A caller able to fabricate or edit a complete
internally consistent schema-2 stream could satisfy the structural checks.
Production-grade origin authenticity is not claimed or needed for this
controlled test, but artifacts must be preserved with externally recorded
hashes when collected.

Remaining review risks: the assembler enforces numerically increasing XIDs
within an epoch; the local source tree does not include Ryu's XID allocator,
so wrap/reuse behavior was not verified. The planned validation should use a
fresh, short-lived controller process and record XIDs; long-running operation
across XID wrap remains unverified. The tracker retains observed datapath
objects and the controller retains recorded epoch IDs until process exit, so
memory use grows with reconnect count; this is bounded for a short validation
process but needs a retention policy before long-running use. Run context is
read from the configured context file at request/completion and other
controller event boundaries; this is fail-closed for a completed collection
whose run differs at completion, but it is not an atomic subscription to
context-file changes.

The former mypy error at the packet-evidence branch was a clear nullable-value
narrowing issue. A second explicit `budget is not None` guard now narrows the
type inside the accepted branch without changing runtime behavior. Packet
evidence remains disabled for the proposed rule-counter-only validation.

The concrete approval plan is in
[`stage7i3-rule-counter-live-validation-plan.md`](stage7i3-rule-counter-live-validation-plan.md).
No live validation was performed, no numeric maximum-gap policy was selected,
and the live feature-collection/inference gate remains **BLOCKED** pending
separate approval and real event-lineage/cadence evidence.

### Stage 7I.3 offline prerequisite update (2026-10-21)

The separate benign-only runner is `scripts/run_stage7_rule_counter_validation.py`.
It explicitly starts Ryu with `--ofp-tcp-listen-port 6653`, creates a fresh
output directory, and does not dispatch any attack scenario. It sets
`SDN_STAGE2_RECORD_PACKETIN_TELEMETRY=false` while leaving the existing
table-miss learning-switch behavior in place. Consequently this is a
rule-counter-feature-only collection, not a zero-PacketIn-visibility test:
Ryu can still receive and parse table-miss PacketIns for forwarding. PacketIn
metadata recording is suppressed by the handler setting and packet/port
observations are excluded from feature-pair and cadence evidence.

`src/sdn_defense/telemetry_audit.py`, invoked through
`scripts/audit_stage7_rule_counter_telemetry.py`, validates generic JSONL
schemas, exact request/terminal/snapshot links, connection epoch continuity,
and source-verifies adjacent rule snapshots using
`audit_snapshot_pair_provenance()`. It reports monotonic request cadence,
completion cadence and collection duration only when the corresponding
recorded integer monotonic timestamps exist. Schema-1 records remain usable
for general replay but cannot qualify as a source-verified pair. Historical
schema-2 records without the new monotonic fields are not assigned reconstructed
times. The tool does not build feature vectors or select a maximum-gap value.

The runner and auditor are unexecuted. Synthetic offline test success does not
validate Ryu callback lineage, live PacketIn behavior, Mininet cleanup, or
actual snapshot cadence. The live feature-collection gate remains BLOCKED
pending separate review and an approved benign-only run.

### Final benign rule-counter runner/auditor safety review (2026-10-22)

The offline review made the runner's fresh-output guard reject dangling
symlinks before preflight and moved UUID allocation before external preflight
commands. The JSONL auditor refuses output paths that resolve to or share an
inode with the input and reports unwritable output paths as an incomplete
command result. On successful collection, the runner summary records bounded
tool-version output, controller PID/argv, the fixed workload and timestamps,
relevant controller settings, and hashes for the source/config files used by
the collection and audit. Its summary distinguishes raw terminal/snapshot records,
collections with valid complete lineage, lineage-linked snapshots, and
source-verified pairs. Cadence reports request-to-request intervals,
completion-to-completion intervals, request-to-completion durations, and
same-rule snapshot gaps only for accepted source-provenance pairs. It still
does not select a maximum-gap policy or generate feature vectors.

The selected PacketIn policy remains Policy A: packet-in telemetry records
are suppressed by configuration while ordinary table-miss PacketIns may
reach Ryu and are parsed for forwarding. This validates the rule-counter
evidence boundary in source, not zero packet visibility. No live runner or
network component was executed. Four focused test modules passed 87 tests
after this review; that synthetic/offline result does not validate live
collection lineage, timing, or cleanup. The live-use gate remains blocked:
the runner has no deadline around synchronous Mininet topology startup, host
command waits, or topology teardown. Resolve this bounded-orchestration
blocker offline before requesting approval for even the benign run.


Final offline safety review (2026-10-22): an early check now verifies that
the runner interpreter can locate the Mininet Python module before external
preflight processes. This does not bound synchronous Mininet startup, host
command, or teardown calls. The focused regression suite passed 88 tests;
Ruff and targeted mypy passed. The live-use gate remains blocked.
