# Stage 7I.1 — Live Feature Contract Validation Plan

## Status

This is a future, offline-testable validation plan for
[`live-feature-contract-v1.md`](live-feature-contract-v1.md). It does not
launch Mininet/OVS/Ryu, generate traffic, capture packets, train a model, or
perform inference. The packet observer remains unfrozen. Passing these tests
would establish implementation semantics only, not live coverage or detector
effectiveness.

## Validation layers

1. **Pure contract tests:** typed fixtures in memory; no network or OS state.
2. **Recorded-observation integration tests:** immutable synthetic
   FlowRecord/ObservationWindow/TelemetryObservation fixtures and temporary
   JSONL; no live services.
3. **Data-pipeline parity tests:** the same deterministic transform and
   feature order for training and inference adapters, still using fixtures.
4. **Split/leakage tests:** synthetic run-group metadata and windows; no real
   Stage 5 rows or labels.
5. **Separate future live validation:** requires a new approved protocol and
   safe observer. It is explicitly outside this plan and was not performed.

## Deterministic fixture set

Commit or otherwise version a small fixture corpus containing:

- two complete snapshots for one rule with increasing counters and monotonic
  times;
- equal counters across a positive interval (measured zero);
- first/baseline-only snapshot;
- missing packet or byte counter;
- counter decrease/reset and uint64 wrap ambiguity;
- repeated same snapshot ID;
- a missing rule followed by reappearance;
- same selector with changed cookie, table, priority, datapath epoch, or
  datapath ID;
- valid and incomplete multipart collections;
- a gap below and above the frozen maximum gap;
- UTC fallback and missing monotonic timing;
- event records with duplicate observation IDs and same-valued distinct IDs;
- IPv4 and IPv6 records, malformed/truncated headers, and absent transport
  metadata;
- run, scenario, label, split group, and post-action metadata stored in
  separate records.

Fixtures must contain metadata only. They must not contain raw packet bytes,
payload, real credentials, real network identifiers, or attack labels in
predictor objects.

## Test matrix

| Area | Deterministic test | Expected behavior |
|---|---|---|
| Measured zero vs missing | Pair equal complete counters over positive monotonic elapsed time; separately test baseline-only, missing counter, and absent rule | Equal paired counters yield measured numeric zero. Baseline/missing/absent produces a typed unavailable state and null numeric value. |
| Counter deltas | Increase packet/byte counters independently | Exact nonnegative differences in packets and bytes; rates equal delta divided by measured elapsed seconds. |
| Reset and wrap | Decrease a counter; include `2^64-1` followed by a small value | Both produce invalid `COUNTER_DECREASE_RESET_OR_WRAP`; never negative and never silently modulo-adjusted in v1. |
| Gaps and multipart | Incomplete multipart response, timeout, missing snapshot, interval over frozen maximum | No complete snapshot/window is synthesized; no numeric delta; explicit incomplete reason. |
| Duplicate events | Same observation ID twice; same payload under distinct IDs | Exact repeated ID is deduplicated once by the explicit deduplication stage; distinct IDs remain separate observations. |
| Endpoint cardinality | IPv4 repeated endpoint, IPv6 endpoint, IPv4-mapped IPv6, changed protocol/destination port | Canonical family-aware identity; only the exact defined tuple contributes once. These tests validate a deferred aggregator, not v1 predictors. |
| IPv4/IPv6 coverage | IPv4 valid, IPv6 valid, unknown ethertype, truncated IP header, IPv4 fragment, IPv6 extension chain without transport header | Family counts only when the required family header is complete; transport-derived fields are incomplete when the transport header is unavailable. No absence inference. |
| TCP flags | Complete TCP base header, truncated flags field, same packet observed in both directions | A flag observation requires a complete header; tuple direction remains explicit; no handshake state inferred from one flag event. |
| Incomplete windows | Disconnect/reconnect, run boundary, rule replacement, missing timestamp, invalid elapsed time | Counter state is reset/separated; no cross-boundary pairing or fabricated zero. |
| Direction and identity | Reverse endpoint tuple and changed canonical rule selector/cookie | Canonical identity and declared direction differ; rule counter values are not paired across different identities. |
| Schema stability | Serialize with fixed v1 order; attempt missing, extra, reordered, or changed semantic feature IDs | Exact schema and `feature_order` required; incompatible semantic change requires new version. |
| Training/inference parity | Run the identical pure feature builder on the same fixture via both adapters | Same values, states, units, order, and deterministic output digest. No adapter-specific imputation. |
| Leakage | Put `scenario_id`, attack label, run ID, probe IDs, target ports, timestamps, and post-action outcome in context/label tables | Predictor projection rejects these keys/fields; no values enter the model matrix. |
| Whole-run split isolation | Generate multiple windows per run, including overlapping windows, then assign run groups | Every window from one run is in exactly one partition; no run or overlap group crosses train/validation/test. |
| Coverage semantics | Zero accepted events with known loss, unknown loss, cap hit, inactive observer, or unsupported protocol | Zero is measured only for explicitly complete, active coverage; otherwise count is missing/incomplete. |

## Required assertions and failure behavior

- All timestamps are timezone-aware UTC for serialization. Elapsed time used
  for rates comes from monotonic collector timing. A wall-clock fallback is
  retained as provenance but does not silently qualify a rate as a model
  feature.
- Counter values are unsigned 64-bit values. Negative, out-of-range,
  decreasing, or missing counters fail validation.
- Counter pairing requires identical canonical rule identity, datapath
  connection epoch, run context, complete snapshots, and valid elapsed time.
- A rule with zero current matched packets can yield zero only if both
  snapshots are valid and its counters are equal. “No row” and “no PacketIn”
  are not numeric zero.
- Any incomplete coverage state makes absence/cardinality features
  unavailable. Do not convert unknown loss to zero drops.
- Feature IDs and order are explicit and immutable for v1. A formula, unit,
  scope, or missingness change is a version change, even if its column name
  remains the same.
- Training and inference must share the transform implementation or pass a
  byte-for-byte golden parity suite over the same typed fixture corpus.
- Label/context join happens after predictor construction, by explicit
  immutable IDs. Predictor builder APIs should not accept label records.

## Split and leakage validation

The split unit is an entire scenario run. Create a test fixture where a run
has multiple non-overlapping and overlapping windows and verify that all
remain in one fold. If multiple run IDs share a single topology/configuration
or repeated seed condition whose windows are not independent, support a
stricter `split_group_id` that groups those runs. Partition assignment is
made before any row/window-level class balancing or model fitting.

Training data may fit a model and any learned preprocessing. Validation runs
may choose model/configuration and validation-calibrated operating points.
Sealed test runs may only be used once for final metrics. Stage 5 splits and
artifacts are not inputs to this live-native split plan. Benign-only
validation runs are needed to estimate false-positive and false-mitigation
rates at pre-registered operating points; test runs remain sealed.

Scenario labels are run-context-derived, not per-flow ground truth. A future
labeling procedure must define exact time/scope overlap, warmup/cooldown,
ambiguous windows, and uncontaminated benign intervals before inspecting
held-out results. Uncertain associations remain unlabeled. Scenario name,
generated probe identifiers, target list, and attack type are context or
label metadata, never predictor columns.

## What passing this plan establishes

Passing establishes deterministic schema handling, missingness behavior,
counter semantics, provenance, feature parity across software interfaces,
and split isolation on controlled fixtures. It does not establish:

- actual OVS mirror selection, truncation, IPv6 support, packet coverage, or
  loss measurement;
- that PacketIn is complete traffic visibility;
- parity with CICFlowMeter or Stage 5's 77 predictors;
- that a feature predicts an attack;
- calibrated confidence, false-positive rates, detection quality, or a safe
  action threshold;
- live resource cost or safe mitigation authorization.

Those claims require separate, preregistered research and live validation.
