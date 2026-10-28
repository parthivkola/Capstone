# Stage 7I.1 — Live-Native Feature Contract v1

## Status and use boundary

**Design specification only.** This document does not implement a feature
builder or authorize live inference. Stage 5 remains the frozen offline
evaluation. Its 77 CICFlowMeter-derived predictors are not reproduced by this
contract. The Stage 7 packet-observation path remains **unfrozen** after B1
received IPv6 frames above the requested 54-byte boundary and the realized
mirror selection was not independently recorded. No packet-derived feature
below is currently eligible for training or inference.

The only v1 numeric candidates are OpenFlow **rule-counter interval** values
already represented by `ObservationWindow`. They describe one rule's
cumulative counter changes between two controller snapshots. They are not
packet-flow features, and they cannot be interpreted as a complete view of
traffic that did not match that rule.

**Telemetry is evidence collection, not attack classification.** A vector in
this contract contains no class, label, confidence, novelty, shift, risk, or
action field.

## 1. Semantic vocabulary

- **Observed event:** one accepted, typed telemetry record emitted by a
  collector for an observation it received. It is evidence that the collector
  received that record; absent a validated coverage denominator it is not a
  count of all packets on the network. Deduplication is by immutable
  `observation_id` only. Distinct IDs are retained even if header values match.
- **Unique endpoint:** for future packet-event aggregation, a canonical
  `(address_family, normalized_IP_address)` pair. MAC endpoints use a separate
  `(link_layer, normalized_MAC)` namespace. IPv4 and IPv4-mapped IPv6 are not
  merged.
- **Unique destination port:** for a future transport event aggregate, the
  cardinality of `(IP_version, IP_protocol_number, destination_port)` values
  within one declared source identity and window. TCP and UDP ports are never
  combined.
- **TCP flag observation:** one accepted event with a complete, validated TCP
  base header and parsed flags. It does not imply a handshake, a unique
  connection, or visibility of the other packets in that connection.
- **Complete counter window:** two complete flow-stat snapshots for the same
  canonical rule, datapath connection epoch, and active run; valid monotonic
  elapsed time; both counters present and within their declared unsigned
  width; no reset, rule disappearance/replacement, reconnect, incomplete
  multipart response, or disqualifying collection gap.
- **Complete packet-event window:** not currently available. It would require
  a validated observer scope and protocol parser, measured loss/drop behavior,
  bounded queue/cap status, and a defined statement of which traffic the
  observer can see. A zero event count is not valid evidence of zero network
  traffic when any part of that coverage is unknown.

## 2. Schema and field separation

The proposed serialized object is `LiveFeatureVectorV1`; this name is a
specification, not an existing runtime type. JSON field order is fixed by the
tables below. JSONL may use canonical UTF-8 JSON with sorted object keys, but
`predictor_order` is authoritative for model column order.

### Predictor block

| Order | Stable feature ID / field | Type, unit, exact definition | Source, scope, window | Status |
|---:|---|---|---|---|
| 1 | `sdn.rule.packet_delta.v1` / `rule_packet_delta` | nullable unsigned integer, packets. `packet_count(t1) - packet_count(t0)` for one canonical OpenFlow rule | `ObservationWindow`; exact rule identity (datapath, table, priority, cookie, normalized selectors); adjacent complete snapshot interval | **Implementable from currently validated telemetry** |
| 2 | `sdn.rule.byte_delta.v1` / `rule_byte_delta` | nullable unsigned integer, bytes. `byte_count(t1) - byte_count(t0)` for the same rule and interval | Same scope and source as above | **Implementable from currently validated telemetry** |
| 3 | `sdn.rule.packet_rate.v1` / `rule_packet_rate_per_second` | nullable finite float, packets/s. `rule_packet_delta / measured_elapsed_seconds` | Same rule interval; elapsed time must use collector monotonic timing | **Implementable from currently validated telemetry** |
| 4 | `sdn.rule.byte_rate.v1` / `rule_byte_rate_per_second` | nullable finite float, bytes/s. `rule_byte_delta / measured_elapsed_seconds` | Same rule interval; elapsed time must use collector monotonic timing | **Implementable from currently validated telemetry** |

“Implementable from currently validated telemetry” means the telemetry
pipeline has emitted and validated live rule snapshots/windows with these
semantics. It does **not** mean a detector schema, coverage-qualified
training set, or live model has been validated. The four columns are
mathematically dependent in pairs; experiments should compare counter and
rate representations rather than assume all four add independent signal.

### Required provenance and validity block — never predictors

Every vector must carry these fields separately from the predictor block:

| Field | Definition |
|---|---|
| `schema_version` | Integer `1`; incompatible semantic changes require a new major schema version. |
| `feature_schema_id` | `stage7-live-rule-window-v1`. |
| `feature_order` | Ordered list of the four stable feature IDs above. |
| `window_id` | Immutable ID of the source `ObservationWindow`. |
| `run_id` | Controlled-run identity, nullable outside a run; metadata only. |
| `datapath_id`, `datapath_epoch_id` | Switch identity and connection epoch; metadata only. Epoch identity must change after reconnect. |
| `rule_identity_id` | Canonical rule identity; metadata/grouping key only, never a predictor. |
| `start_at`, `end_at` | UTC timestamps of the paired snapshots. |
| `measured_elapsed_seconds`, `timing_source` | Measured interval and source. Training eligibility requires monotonic collector timing; wall-clock fallback is retained as provenance but the rate columns are missing for model use. |
| `source_flow_record_ids` | Exact ordered IDs of both records used to derive the values. |
| `window_validity`, `invalid_reason` | One of valid, partial, baseline-only, invalid, or closed, and a typed cause from the telemetry contract. |
| `coverage_state` | `COUNTER_WINDOW_COMPLETE`, `COUNTER_WINDOW_INCOMPLETE`, or `NOT_ASSESSED`; describes statistics collection only, not packet coverage. |
| `collector_version`, `telemetry_provenance_version`, `ovs_version`, `schema_builder_version` | Exact versions/configuration identifiers when known; unknown remains explicit. |
| `label_ref`, `scenario_id`, `split_group_id`, `evaluation_metadata` | Stored in a separately access-controlled label/context record keyed by window/run ID. These fields are never serialized into the predictor block. |

`datapath_id`, rule selectors, run IDs, timestamps, scenario IDs, source and
destination identities, labels, and post-action outcomes are not features in
v1. A future experiment that wants identity-based predictors requires an
explicit preregistered ablation and leakage review.

### Explicit missingness states

Each numeric predictor is either a measured number or missing with a reason.
The data contract does not encode a missing state as numeric zero.

| State | Representation/meaning |
|---|---|
| `MEASURED` | Numeric value is observed or derived under all feature-specific validity conditions. Zero is permitted only here. |
| `UNKNOWN` | Required state or denominator is unavailable; no claim about value. |
| `INCOMPLETE` | Collection has a known gap, loss, incomplete multipart response, run boundary, reconnect, or invalid pairing. |
| `INVALID` | Input violates the schema/range or has reset/wrap ambiguity. |
| `NOT_APPLICABLE` | Feature does not apply to the source/scope. For example, transport event metadata for a non-transport rule. |

For v1 counters, zero is a valid measured delta only when both complete
counter values are equal across a complete eligible interval. A first snapshot
is baseline-only, not zero. Missing counters, an absent rule, invalid timing,
an incomplete snapshot, a reconnect, or a run boundary makes the corresponding
feature unavailable. Equal timestamps are invalid because no positive
elapsed interval exists.

OpenFlow counters are treated as unsigned 64-bit values. Any decrease is
`INVALID` with reason `COUNTER_DECREASE_RESET_OR_WRAP`; v1 does not infer
modulo wraparound. A future version may implement wrap correction only after
counter width, rule continuity, and switch reset behavior are independently
verified. It must not change v1 records retrospectively.

## 3. Observation and aggregation rules

The v1 observation interval is exactly the interval between two consecutive,
complete statistics snapshots for the same rule identity and datapath epoch.
It is not a connection lifetime and does not have packet-flow first/last
packet semantics. A maximum admissible interval/gap and polling schedule must
be fixed in the future experiment protocol before training data collection;
there is no universal numeric interval selected here. If that frozen limit is
exceeded, mark the interval `INCOMPLETE` and emit no numeric counter features.

No aggregation across rules occurs in v1. If several rules match the same
packet, their counters may each include it; summing rules can double-count.
Rules can also aggregate multiple transport conversations. Rule identity is
for pairing and provenance, not a predictor. Rule creation/replacement under
the same visible selector set must be detected through cookie/epoch and
counter continuity; if continuity cannot be proved, start a new baseline.

The four counter features need no packet payload. They are independent of
IPv4/IPv6 decoding, but they do not provide source/destination endpoint or
transport-level evidence unless those selectors exist on the rule. A wildcard
rule's counter cannot be partitioned into its constituent hosts or flows.

## 4. Deferred packet-event feature candidates

The following are deliberately **not v1 predictors**. Their status reflects
the present evidence, not whether code could be written:

| Candidate | Intended definition | Status | Reason/before eligibility |
|---|---|---|---|
| `observed_ipv4_event_count`, `observed_ipv6_event_count` | Accepted, deduplicated-by-ID observations with a valid complete family header, per declared scope/window | **Requires unresolved packet-observation safety validation** | The mirror boundary and realized selection are unresolved; PacketIn is best effort. |
| `observed_tcp_event_count`, `observed_udp_event_count` | Accepted observations with complete transport header, by family/protocol/window | **Requires unresolved packet-observation safety validation** | Must establish bounded header delivery and coverage/loss behavior for both IP families. |
| `distinct_tcp_destination_ports_observed` | Cardinality of `(IP version, TCP protocol number, destination port)` by source identity/window | **Requires unresolved packet-observation safety validation** | Must observe the complete required headers and establish scope/coverage; incomplete headers yield unknown, not a smaller trusted set. |
| `distinct_tcp_destination_endpoints_observed` | Cardinality of canonical destination IP endpoints by source/window | **Requires unresolved packet-observation safety validation** | IPv4 and IPv6 parsing, fragmentation/extension-header behavior, scope, and loss must be qualified. |
| `tcp_syn_without_ack_observed_count`, `tcp_syn_ack_observed_count`, `tcp_rst_observed_count` | Count complete TCP header flag observations satisfying the named bit predicate | **Requires unresolved packet-observation safety validation** | A header event is not a handshake result; sampling and direction coverage must be explicit. |
| `arp_sender_claim_pair_count` | Unique `(sender IPv4/IPv6 protocol address, sender MAC)` pairs seen in complete ARP observations | **Requires a collector change** | The current envelope has ARP PacketIn parsing, but the proposed safe observer needs verified event provenance, dedup/loss and run-window aggregation. No validated complete ARP event stream exists. |
| `arp_binding_conflict_count` | New conflicting claims against a versioned trusted IP/MAC binding table | **Not currently feasible** | No authoritative, versioned binding source and mobility/reset policy are established. |
| `new_source_mac_port_pair_count` | New observed source-MAC/ingress-port pair relative to approved inventory snapshot | **Not currently feasible** | No approved device inventory/versioned membership baseline exists. |
| `dhcp_message_type_count`, `dns_rcode_count` | Counts by parsed DHCP/DNS message field | **Not currently feasible** | No validated protocol parser or payload-independent message evidence exists; application metadata requirements are unspecified. |
| `rule_packet_delta`, `rule_byte_delta`, and rates | As defined in the v1 predictor table | **Implementable from currently validated telemetry** | Rule-level snapshot/delta path exists and was validated; it is not packet-level feature parity. |

No current feature is assigned `APPROXIMATION_REQUIRED` and then admitted to
the schema. If a field would require a different meaning, it is excluded and
must be proposed under a new stable identifier.

## 5. Packet-family and coverage semantics for future versions

IPv4 and IPv6 are separate populations. A family-specific event feature is
valid only if the collector can identify the family and parse every required
header field. Ethernet-only evidence does not imply a parsed IP event. IPv4
fragmentation and IPv6 extension headers may hide transport headers; such
records are `INCOMPLETE` or `NOT_APPLICABLE` according to a preregistered
parser rule, never silently counted as a non-TCP event. Truncated headers are
invalid for dependent fields.

PacketIn is not total traffic visibility: learned OVS forwarding can avoid
PacketIn; controller rules and packet-copy configuration affect what is
delivered; observer selection, sampling/rate caps, queue loss, protocol
parsing, and collector downtime affect coverage. A zero event count can only
mean zero **observed eligible events**. It cannot mean zero packets on the
network unless an independent, validated denominator establishes that claim.
The current mirror's requested 54-byte snaplen is not accepted as a universal
bound after B1.

If a later event schema becomes eligible, each window must report its eligible
scope and family coverage, observer-active interval, accepted count, known
sample/drop counts, queue overflow, cap status, parser failures, and unknown
loss state. When loss cannot be measured, coverage is `UNKNOWN`; absence-based
features are missing/incomplete. Do not infer complete capture from the
absence of reported drops.

## 6. Leakage-safe record layout

Keep three logical tables/records keyed with immutable identifiers:

1. **Predictor record:** schema ID/version, ordered v1 numeric values, per-
   value validity, and no labels or scenario names.
2. **Run/context record:** `run_id`, `scenario_id`, topology/config digest,
   scope, start/end, and scenario journal reference. Context is not a
   predictor.
3. **Label/evaluation record:** ground-truth source, label, labeling rule,
   scope/time interval, ambiguity status, and evaluation-only outcomes.
   Post-action observations and enforcement result are evaluation metadata,
   not predictors.

`split_group_id` is derived from the whole controlled run (or a stricter
   topology/scenario group) and is retained outside predictors. Before
   splitting, all windows from a run are assigned to one partition. If windows
   overlap in time, they must not cross partitions; the simpler v1 rule is
   disjoint runs per partition. Scenario names, attack labels, generated probe
   IDs, target-port list, run ID, absolute time, and post-action outcomes are
   prohibited predictors. Source/destination identities and rule IDs are
   grouping/provenance only in v1.

Training and inference must call the same versioned pure transform over the
same typed source semantics. Record its source revision, schema ID, ordered
feature IDs, numeric dtypes/units, validity handling, parser/collector version,
and a deterministic fixture-set digest. Reject reordered, missing, extra, or
semantically changed inputs; do not impute from training statistics unless a
separate protocol explicitly specifies a fitted transformation and stores its
training-only provenance. The present contract specifies no fitting or
imputation.

## 7. Compatibility with the 77-column offline model

None of these v1 features is a substitute for a CICFlowMeter feature. Rule
counter deltas/rates have different observation unit and aggregation scope.
The current Stage 5 RF remains an offline evaluation detector and is not
authorized for live autonomous mitigation. A future model trained on v1 is a
new model with new training data, validation, thresholds, and evaluation
protocol. Existing datasets have not been shown to reconstruct the v1 rule
counter observation distribution faithfully.

## 8. Implementation and freeze blockers

Before implementation or training, freeze the eligible gap/interval policy,
counter validity requirements, split and label protocols, and source version.
Before any packet-event feature enters a model, resolve B1's realized mirror
configuration ambiguity and universal byte-bound concern, then validate
IPv4/IPv6, selection, coverage/loss, forwarding preservation, isolation, and
cleanup. The current configuration-only auditor cannot independently read
the live Mirror row without an authorized running environment; this document
does not treat its unit tests as live evidence.

This contract is implementable as a specification, but not yet a validated
live detector input. No live feature collection, training, inference, attack
classification, policy decision, or mitigation is authorized by this
document.
