# Proposed Live-Native Feature Contract

## Status and boundary

This is a design proposal only. It defines no detector, thresholds, labels,
confidence, risk score, or mitigation request. Stage 5's 77-column schema is
unchanged and remains an offline research input. `FlowRecord` remains an
OpenFlow rule-stat snapshot; `ObservationWindow` remains a derived interval
of rule-counter changes. The proposed packet/event features are separate
records and must not be renamed to CICFlowMeter feature names.

**Telemetry is evidence collection, not attack classification.** A future
detector should consume evidence plus coverage/provenance and emit a
`DetectionResult` only under a separately reviewed protocol.

## Proposed input shape

Use one row per fixed, non-overlapping observation interval and one explicit
scope key. Freeze the interval width, timestamp convention, scope key, parser
version, OVS mirror configuration, and event coverage behavior before
collecting any model data. Let `W` denote that preregistered interval in
seconds; this proposal does not choose its numerical value.

```text
LiveObservationWindow
  schema_version
  window_id
  start_at_utc, end_at_utc, measured_elapsed_seconds
  datapath_id, ingress_port, source_scope_key
  run_id (metadata only; excluded from model inputs)
  source_observation_ids[]
  telemetry_config_id, parser_version, coverage_state
  coverage counters (accepted, dropped, queue overflow, cap status)
  protocol evidence features (nullable values + missing reason)
```

Run ID, source addresses, destination addresses, scenario ID, labels, and
configuration identifiers are provenance/context. Exclude them from the
predictor vector by default. A separate approved ablation may test scope
identity leakage, but it must not silently enter the primary model.

### Candidate numeric evidence fields

The table gives exact definitions for a possible *new* live schema. Definitions
refer to events actually delivered to the observer; they do not claim complete
network visibility. Fields remain candidates until the observation path is
revalidated, including the B1 mirror-selection/oversized-IPv6 failure.

| Proposed field | Exact formula and unit | Scope/window | Raw evidence | Missing/reset behavior and limits |
|---|---|---|---|---|
| `observed_l2_event_count` | Count of accepted Ethernet-header observations; events | ingress port and fixed `W` | Parsed mirror/PacketIn metadata with unique observation IDs | Null if collection state is unknown; zero only when collection is known active and no qualifying events arrived. It is observer count, not total packets forwarded. |
| `observed_ipv4_event_count` | Count of accepted IPv4 observations; events | ingress port and `W` | IPv4 header metadata | Same coverage rule; fragmented/unsupported frames need an explicit parser state. |
| `observed_tcp_event_count` | Count of accepted TCP observations; events | source-scope key and `W` | TCP header metadata | Null on incomplete header or coverage failure; does not represent all TCP packets unless coverage is validated. |
| `observed_udp_event_count` | Count of accepted UDP observations; events | source-scope key and `W` | UDP header metadata | Same as TCP; protocol payload is not needed for this count. |
| `distinct_tcp_destination_ports_observed` | Cardinality of observed TCP destination-port set; ports | source-scope key and `W` | Source identity, destination port, protocol | Null when metadata is incomplete or dropped; zero only with known complete scope coverage. Source identity stays metadata, not a model column. |
| `distinct_tcp_destination_ips_observed` | Cardinality of observed TCP destination-IP set; addresses | source-scope key and `W` | Source identity and destination IP | Same coverage rule; can identify target/testbed layout if raw addresses are included, so model input receives only cardinality. |
| `tcp_syn_without_ack_observed_count` | Count TCP events where SYN bit is set and ACK bit is clear; events | source-scope key and `W` | Complete TCP flags and source/destination tuple | Null on truncated/invalid TCP header or coverage gap; it is observed SYN evidence, not handshake failure or attack classification. |
| `tcp_syn_ack_observed_count` | Count events where SYN and ACK bits are set; events | bidirectional tuple group and `W` | TCP flags and tuple direction | Does not establish successful connection completion without later ACK/sequence-aware state. |
| `tcp_rst_observed_count` | Count events where RST bit is set; events | source-scope key and `W` | TCP flags | Coverage-qualified observed count only. |
| `distinct_arp_sender_claim_pairs` | Cardinality of unique `(sender_protocol_address, sender_hardware_address)` pairs; pairs | ingress port and `W` | Complete ARP metadata | Missing if ARP header unavailable. A pair count is evidence, not proof of spoofing or authoritative ownership. |
| `arp_binding_conflict_observed_count` | Count of newly observed conflicting MAC claims for an IP against a versioned, independently maintained binding table; conflicts | datapath/port and `W`, with binding state across windows | ARP sender IP/MAC, observation time, trusted binding/inventory provenance | Null until an authoritative binding source and reset policy exist. A conflict may be legitimate mobility, failover, or stale inventory. |
| `new_source_mac_port_pairs` | Count of source MAC/ingress-port pairs absent from a versioned approved inventory at window start; pairs | datapath and `W` | Ethernet source MAC, ingress port, inventory snapshot | Null without inventory or if coverage incomplete. Not a device-authorization verdict; inventory drift can create false evidence. |
| `rule_packet_delta` | Later complete-snapshot rule packet counter minus prior counter; packets | canonical OpenFlow rule, paired snapshots | `ObservationWindow` source FlowRecord IDs | Preserve existing invalid/reset/gap reasons; never substitute zero for baseline/reset/missing. Rule-level aggregation, not packet-flow count. |
| `rule_byte_delta` | Later complete-snapshot rule byte counter minus prior counter; bytes | canonical OpenFlow rule, paired snapshots | `ObservationWindow` source FlowRecord IDs | Same reset/gap semantics; rule counters may cover many transport flows. |

The list is intentionally split between packet observations and rule-counter
evidence. It does not combine those into a purported CICFlowMeter record.
DNS/DHCP message fields should be a later, separately validated extension;
no payload or application contents are proposed here.

## Coverage and missingness contract

Coverage is part of the data contract, not optional operational logging. Each
window should include collector-active duration, accepted observation count,
intentional sample/drop count, queue overflow count, per-run cap state, and
the applicable OVS mirror/configuration identity. If the source cannot report
a reliable drop/loss denominator, record that as `unknown`; do not claim
complete coverage. A window with incomplete coverage is ineligible for a
zero-valued absence feature. Distinguish:

- measured zero under verified active and complete observation;
- missing because a header/event was unavailable;
- incomplete because sampling, queue loss, reconnect, parser error, or run
  boundary occurred;
- not applicable because the protocol/scope does not define the field.

The current packet-observation path is not frozen: prior B1 evidence included
oversized IPv6 frames beyond the requested 54-byte boundary and an unresolved
source-selection mismatch. Therefore none of the packet-event fields above
may yet be treated as a guaranteed production input.

## Candidate data preparation and leakage controls

The feature builder should be a deterministic, versioned transform over
metadata-only observations. Deduplicate only by immutable observation ID;
preserve duplicate/retransmitted packets as separate events if they are
distinct observations. Sort by collector timestamp plus stable tie-breaker;
record clock source and monotonic timing. Windows are fixed in advance, never
aligned to a label or scenario event after inspection. Counter resets,
datapath reconnects, incomplete statistics collections, run boundaries, and
coverage failures split/reset state and yield explicit missingness.

Scenario ID, run ID, workload label, source/destination addresses, selected
ports, and start/end times must not become model predictors. Scenario journals
remain separate contextual artifacts. Uncertain overlap or incomplete
scenario attribution is excluded from supervised labels rather than assigned
the nearest scenario label.

## Can existing offline data train this schema?

No existing dataset is established as semantically equivalent to the proposed
observer-window table.

- CSE-CIC-IDS2018 raw flow CSV headers contain timestamp, endpoint, protocol,
  and destination-port columns, but Stage 5D intentionally excludes endpoint,
  timestamp, and destination-port identifiers from its 77 predictors. A
  separate aggregation of source flow rows could estimate per-source distinct
  destinations/ports in timestamp bins, but it would be a flow-record
  aggregation, not the live collector's packet-evidence population or coverage
  semantics. The source extractor/version and timestamp anchoring would need
  verification before calling it equivalent.
- The inspected CIC-IDS2017 MachineLearningCSV schema does not provide the
  complete source identity plus timestamp/port combination needed for the
  proposed per-source window features.
- UNSW-NB15 and TON_IoT contain endpoint/protocol/event or connection fields,
  but their row grain, timestamps, labels, and counters are not the same as
  Ryu/OVS observer events. Similar names do not establish equivalent event
  semantics.

These datasets may support separate exploratory re-aggregation studies if
their row unit and temporal semantics are documented, but must not be pooled
with live observations or used to claim semantic parity without a separate
protocol. Primary model training should use controlled, metadata-only
observations from the exact proposed collector and feature-builder versions.

## Minimum future collection and split plan

Before detector work, first repair and validate the observation configuration
and collector boundary, including selected-port identity, IPv4/IPv6 behavior,
drop/cap counters, and forwarding preservation. Then preregister scenario
families, benign conditions, feature definitions, window width, run count
based on a power/precision rationale, and labeling rules.

For each controlled run, save the scenario journal separately and emit an
explicit run record containing run ID, scenario ID, start/end, topology/config
digest, intended source/destination/protocol/port scope, and collection quality.
This creates run-level context, not per-packet truth. Use scenario timestamps
and scope only to derive coarse run/window labels under a documented rule;
ambiguous windows remain unlabeled. Preserve independent benign-only runs for
false-positive calibration.

Split whole runs, and where feasible hold out scenario parameter combinations
or host/topology variants. Fit transformations and select action operating
points on training/validation runs only. Use a sealed set of complete held-out
runs for final reporting. Never randomly split windows from one run across
training and test. Report per-run metrics and uncertainty across runs; windows
from one run are correlated observations, not independent experimental units.

Stage 7's policy calibration uses disjoint validation data. Any live model
must first operate in observation-only mode; thresholds cannot be selected
from the sealed test runs or from the Mininet integration runs used to verify
the telemetry path.

## Stage 7I.1 disposition (addendum; original proposal retained)

This section records the resolution of the candidates above without
rewriting the original audit/proposal text. The precise, versioned contract is
now [`live-feature-contract-v1.md`](live-feature-contract-v1.md), and its
non-network validation plan is
[`live-feature-validation-plan.md`](live-feature-validation-plan.md).

Only the four existing OpenFlow rule-counter interval quantities
(`rule_packet_delta`, `rule_byte_delta`, `rule_packet_rate_per_second`, and
`rule_byte_rate_per_second`) enter the v1 candidate predictor schema. They
retain rule-level semantics and are eligible only for complete, same-rule,
same-datapath-epoch snapshot pairs with valid monotonic timing. Their presence
in a validated telemetry pipeline is not a claim of detector readiness.

All packet-event/cardinality/flag/ARP/DHCP/DNS candidates in the original
proposal remain deferred. In particular, B1 showed that the current mirror
path did not establish a universal 54-byte boundary or independently prove
the realized selected port. PacketIn also remains best-effort. Those fields
must not be consumed as complete-coverage predictors until a separately
approved validation resolves the observation boundary and loss/coverage
semantics. No change is made to the Stage 5 77-feature contract, dataset,
protocol, or result.

This addendum does not authorize feature-builder implementation, data
collection, model training/inference, threshold calibration, DetectionResult
creation, or mitigation.

## Stage 7I.2 implementation note (append-only)

The v1 rule-counter candidate now has an offline implementation in
`src/sdn_defense/live_features.py`, documented in
[`live-feature-builder.md`](live-feature-builder.md). It accepts explicitly
paired, collection-qualified FlowSnapshots and emits only the four v1
rule-counter values with separate validity and provenance. It does not
change any feature definitions in this proposal or enable packet-derived
features. Maximum pair gap remains a required caller input because no
research value is frozen. Synthetic unit tests do not establish live
observation validity or detector readiness.
