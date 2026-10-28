# Stage 7 Live Observation Telemetry Foundation

## Purpose and boundary

This addition records live SDN observations for future detector research. It does not
classify traffic or connect to the Stage 7 decision/enforcement path.

**Telemetry is evidence collection, not attack classification.** No observation created
here contains an attack label, confidence, anomaly score, risk decision, or mitigation
recommendation. The telemetry package has no dependency on `DetectionResult`, risk
policy, orchestrator, mitigation adapter, or OVS mitigation verification.

## Why `FlowRecord` remains unchanged

Stage 4 `FlowRecord` is retained as its existing versioned snapshot of an OpenFlow rule
and its cumulative switch counters. Its `packet_count` and `byte_count` are counters
associated with one rule at an observation time. They are not CICFlowMeter packet-flow
features, bidirectional flow measurements, or packet-level event counts. In particular,
the Stage 4 `tcp_flags` value describes a rule match selector when present; it is not a
count of TCP flag-bearing packets.

`ObservationWindow` is a separate contract for a measured change between two such rule
snapshots. Its output names are deliberately rule-scoped:

- `rule_packet_delta`: later cumulative rule packet counter minus earlier counter.
- `rule_byte_delta`: later cumulative rule byte counter minus earlier counter.
- `rule_packet_rate_per_second`: packet delta divided by measured observation interval.
- `rule_byte_rate_per_second`: byte delta divided by measured observation interval.

These are not `Flow Pkts/s`, `Flow Byts/s`, or `Flow Duration`. An OpenFlow rule may
cover multiple packet flows, and its counter interval does not provide individual
packet timing or bidirectional flow semantics.

## Contract and provenance

`src/sdn_defense/telemetry.py` defines three additive contracts:

- `ObservationWindow`: schema version, deterministic window ID, source, datapath,
  canonical rule identity, interval endpoints, measured elapsed duration, source record
  IDs, validity/reason, optional deltas/rates, provenance version, and optional run ID.
- `TelemetryObservation`: typed raw event envelope with observation ID/type, aware
  observation timestamp, source, optional scope, immutable scalar payload, provenance,
  collector monotonic time, and optional run ID.
- `ScenarioRunMetadata`: run/scenario ID, start/end, topology/config digest, source and
  destination scope, and protocol/port scope. It associates observations with a
  controlled run; it does **not** create per-flow ground truth.

Payload keys representing attack labels, classification, confidence, anomaly/risk
scores, or mitigation are rejected. DHCP, DNS, and inventory observation type names
are reserved in the generic envelope; no such parsers or inventory source are
implemented here.

## Canonical rule identity

The identity hashes normalized datapath ID, table ID, priority, cookie, and match
selectors. Known Ryu OXM keys are normalized to stable names; IP addresses and MAC
addresses are canonicalized; selector mappings are sorted before hashing. The parser
does not depend on field ordering or whitespace in Ryu's textual match representation.

Identity construction is deliberately conservative. If a raw match is not a recognized
literal OXM mapping, contains unknown selectors, conflicting aliases, or unsupported
values, identity construction fails rather than silently omitting information. This is
not a universal OpenFlow match parser; adding selector support requires an explicit
contract and tests.

## Counter pairing, timing, gaps, and resets

`CounterDeltaEngine` pairs only successive records with the same canonical rule
identity and same run ID. The first observation is `BASELINE_ONLY`; it has missing
deltas, never zero deltas. A repeated record ID, missing counter, invalid interval,
observation gap beyond a configured maximum, counter decrease, run boundary, rule
disappearance, or datapath disconnect is represented with explicit validity/reason
metadata. Counter decreases are treated as reset/invalid evidence, not negative traffic.

When both snapshots carry collector monotonic nanoseconds, elapsed time uses their
difference. Otherwise the engine can use the difference between timezone-aware UTC
collector observation timestamps, explicitly marked as wall-clock fallback. The Ryu
flow-stat handler now records collector monotonic time at receipt; the additive
`flow_snapshot_from_observation` adapter carries it beside (not inside) the unchanged
FlowRecord. It is not a switch packet timestamp and does not imply the exact instant
each counter was sampled.

The engine only closes a missing rule when its caller explicitly confirms a complete
snapshot. Partial replies must not be passed as complete. Disconnect clears the
datapath baseline; reconnect observations begin with a new baseline and are never
paired across a connection boundary. Ryu flow-stat replies are now assembled by
datapath ID and OpenFlow XID. The reply `OFPMPF_REPLY_MORE` flag determines whether a
part is followed by another; only the final part makes a complete collection. A
request-specific timeout or datapath disconnect emits an `incomplete_collection`
record and discards partial flow rows from snapshot/delta processing. Interleaved
requests remain separate. An empty final reply is a complete empty snapshot and may
close prior rules. Identical repeated part payloads are rejected as duplicate parts.

Each complete collection uses the final-reply receipt timestamp and monotonic collector
time for all its flow records. This marks when the collector completed the snapshot; it
does not claim the switch sampled every counter at that instant. The response XID is
registered before send and paired only with the matching datapath/XID. A run boundary
between request start and response completion makes the collection incomplete for
run-correlated data; it is not assigned to either run.

## Current Ryu observations

The Stage 2 controller emits telemetry envelopes for:

| Observation | Source | What it means | Important limitation |
|---|---|---|---|
| Ethernet PacketIn | Ryu `EventOFPPacketIn` | Ethernet type and observed source/destination MAC from one packet delivered to the controller | PacketIn is only traffic selected by switch rules; it is not total network visibility |
| ARP PacketIn | Ryu packet parser on a PacketIn | ARP opcode and sender/target protocol/hardware addresses in that delivered frame | Does not prove a host's authoritative binding or observe ARP frames not sent to Ryu |
| IPv4 PacketIn | Ryu packet parser on a PacketIn | IPv4 source/destination, protocol number, and TTL in that delivered frame | Does not provide complete flow behavior or packet timing distributions |
| TCP PacketIn | Ryu packet parser on a PacketIn | TCP ports and header bits in that delivered frame | One packet's bits are not SYN counts, handshake completion, or connection state |
| UDP PacketIn | Ryu packet parser on a PacketIn | UDP source/destination ports in that delivered frame | Does not parse DHCP or DNS messages |
| Port description | OpenFlow port description reply | Switch-reported port number, name, state, and config | Does not identify a physical device beyond the controlled switch's report |
| Flow-stat snapshot | OpenFlow flow-stat reply | Rule selectors and cumulative rule counters/duration at controller receipt | Rule counters are not per-flow CICFlowMeter semantics |

PacketIn telemetry is best-effort and its failure does not alter forwarding. Existing
table-miss/learning behavior remains unchanged. Once learned rules forward packets in
the switch, those packets may no longer produce PacketIn events. No packet mirroring,
broader controller punt, or traffic-generating rule was added.

## Stage 3 run correlation

Stage 3 accepts an explicit `--run-id`. When omitted, journal records keep `run_id`
absent; the controller never invents one. The telemetry collection runner generates
one unique ID per run and supplies it explicitly. With an ID, the `scenario_started`
record includes an additive `scenario_run` object with the
scenario ID, run ID, start time, topology/config digest, fixed source/destination scope,
and applicable protocol/port scope. `run_completed` records the end time, including
cleanup paths. Existing event names and scenario event meanings remain unchanged.

The metadata describes the intended controlled scenario scope and timing. It does not
prove every observed packet came from that scenario, and does not label individual
flows. Correlation quality, clock alignment, and concurrent-run handling require later
validation.

When `SDN_OBSERVATION_CONTEXT_FILE` is configured, Stage 3 atomically writes its
explicit active run context before starting Mininet and updates it to inactive at
scenario end, before Mininet teardown. Ryu reads that configured file at
collection-request and PacketIn boundaries;
the ID is attached only when context explicitly says that run is active. Without the
file or without an active context, `run_id` remains null. A context transition emits a
separate run-boundary record. Connection reconnects, counter resets, collection gaps,
and rule replacement retain their distinct representations.

Propagation is therefore:

```text
Stage 3 --run-id / generated per-run ID
  -> atomic scenario context JSON (SDN_OBSERVATION_CONTEXT_FILE)
  -> Ryu reads active context at observation/request time
  -> flow snapshot and PacketIn telemetry JSONL carry that run_id
```

No ID is derived from packet fields. The scenario journal and telemetry JSONL remain
separate artifacts and can be correlated by run ID and time/scope. Scenario metadata
states intent and bounded scope; it is not per-flow ground truth.

## Recorder and read-only replay

Set `SDN_TELEMETRY_JSONL` to enable the append-only recorder. Every line has a
`record_type` and schema version. Record types distinguish recorder metadata, run
metadata/boundaries, connection boundaries, requested/completed collections,
incomplete collections, raw Stage 4 `FlowRecord` snapshots, `ObservationWindow`
records, and raw `TelemetryObservation` records. JSON uses stable key ordering, UTC
timestamps, compact encoding, and a flush after each complete line. A crash may leave a
partial last line; replay reports the malformed line instead of accepting it. Missing
run-end boundaries are counted as incomplete runs.

The read-only validator is `validate_telemetry_jsonl(path)`. It checks record and
nested schema versions, FlowRecord fields, duplicate observation IDs, run consistency,
source-record references for windows, and timestamp order within each run. It does not
replay packets or classify traffic.

## Controlled telemetry collection

**PLANNED procedure:** Use the opt-in, root-gated runner:

```bash
sudo env PYTHONPATH="$PWD" /usr/bin/python3 \
  scripts/run_stage7_telemetry_collection.py \
  --output-dir experiments/stage7-telemetry/<run-directory>
```

The runner refuses an existing `s1` bridge, starts only the Stage 2 Ryu application,
keeps the Stage 7 gateway/policy/mitigation disabled, checks local h1-to-h3 reachability
for a bounded connectivity run, and invokes the existing bounded Stage 3 `port-scan`
scenario (8 seconds, 1 event per second, fixed h3 target and fixed allowlist). It checks
that Mininet removes `s1`, terminates Ryu, and validates the resulting telemetry JSONL.
Artifacts are separate: `telemetry.jsonl`, `ryu.log`, `benign-run.jsonl`,
`port-scan-run.jsonl`, and `collection-summary.json`. Collection output is generated
locally by execution; no measurements are embedded in this document.

### Observed collection — 2026-10-08

**OBSERVED:** The third controlled collection used the documented runner without
changing its scenario parameters. The output directory is
[`live-2026-10-08-03`](../../experiments/stage7-telemetry/live-2026-10-08-03/), with
separate `telemetry.jsonl`, `benign-run.jsonl`, and `port-scan-run.jsonl` files. The
recorder validator passed the telemetry file with these record counts: 1 recorder
metadata, 2 run metadata, 4 run boundaries, 7 connection boundaries, 20 flow-collection
records, 53 packet/port observations, 34 FlowRecord snapshots, and 42 ObservationWindows;
`incomplete_runs` was 0.

| Observation | Benign connectivity | Bounded port scan |
|---|---:|---:|
| Run ID | `a359f79b-ee50-4f24-bab5-2eaa996cee18` | `7ab81dd2-3d58-41f2-a222-924fbcbaa88d` |
| Scenario | h1 → h3 connectivity | h2 → h3 fixed TCP probes |
| Run interval (UTC) | 17:19:11.304413–17:19:19.922240 | 17:19:20.097308–17:19:27.335787 |
| Elapsed run interval | 8.617827 s | 7.238479 s; configured scenario duration was 8 s |
| Scenario parameters | 6 `ping -c 1 -W 1` operations | 8 s, 1 event/s, 8-event cap; ports 22, 53, 67, 80, 443, 8080, 18080, 5353 |
| Flow-stat requests / complete collections | 5 / 5 | 5 / 5 |
| Flow snapshots | 13 | 21 |
| ObservationWindows | 16 (10 valid, 3 baseline-only, 3 closed at disconnect) | 26 (16 valid, 5 baseline-only, 5 closed at disconnect) |
| PacketIn observations | 21 | 24 |
| ARP / IPv4 / TCP / UDP / other Ethernet | 2 / 1 / 0 / 0 / 18 | 4 / 1 / 1 / 0 / 18 |
| Port-description observations | 4 | 4 |

Both journals contain the corresponding run ID. Run IDs, scenario IDs, scope, and
timestamps provide correlation; the journal events are scenario-level records, not
per-flow ground truth. The context is explicitly deactivated before each topology is
stopped. The final context file is inactive. The known datapath ID was
`0000000000000001` for both runs, and Ryu logged OpenFlow 1.3. Early connection-close
events before datapath discovery were retained with a null datapath ID; they were not
assigned a fabricated identifier. Post-run disconnect boundaries had no active run ID.

Each run issued five stats requests and received five complete single-part replies. All
10 complete collections had at least one flow record. No incomplete, unmatched,
duplicate, timed-out, disconnect-incomplete, or empty-complete collection was recorded.
Requests completed before the next poll, so concurrent/interleaved XIDs were not
observed in this live run; request separation and incomplete multipart handling remain
covered by unit tests. A run-boundary crossing did not produce a partial snapshot.

The benign run produced 13 snapshots and 16 windows: 3 first-observation baselines,
10 valid paired windows, and 3 disconnect closures. The port-scan run produced 21
snapshots and 26 windows: 5 baselines, 16 valid paired windows, and 5 disconnect
closures. Valid windows include source FlowRecord IDs, canonical rule identity, UTC
start/end times, collector-measured elapsed time, and rule packet/byte deltas and rates.
For example, one port-scan window for the L2 rule selectors `in_port=2` and
`dst_mac=02:00:00:00:00:03` measured 2 packets and 148 bytes over 2.001630 seconds
(about 0.999 rule packets/s and 73.940 rule bytes/s). First observations and datapath
disconnect closures had null deltas/rates; they were not converted to zero. Zero deltas
in valid windows represented equal counters in paired snapshots. No reset, rule
disappearance, or observation-gap reason occurred. These are SDN rule-counter
observations, not CICFlowMeter flow features.

The scan journal records eight fixed probes, one for each configured destination port.
Ryu PacketIn telemetry recorded only one `TCP_PACKET_IN`, with destination port 22;
it did not expose the other seven destination ports. OVS flow statistics showed
aggregate L2 counters for h2 ingress to h3's MAC, without transport-port selectors.
Thus the scenario generated eight probes, the switch forwarded traffic and counted
rule matches, and Ryu directly observed only the PacketIn subset. PacketIn is not total
traffic visibility. The four port-description observations per run recorded the same
switch/local and three Mininet port entries; these generic port observations did not
distinguish the scenarios.

**INFERRED from these observations:** the current telemetry makes this particular
controlled scan partially observable, but does not provide sufficient structured
destination-port coverage for a defensible port-scan detector. Rule-level counters
show aggregate traffic changes and one PacketIn exposes port 22, but they do not
establish the full set of scanned ports. No detector, threshold, or effectiveness
metric was evaluated.

Two preliminary collection outputs are preserved in `live-2026-10-08-01` and
`live-2026-10-08-02` as diagnostic artifacts, not as validated datasets. Their
validator rejected line 4 for event-time ordering; the first attempt also logged a
flow-stat handler exception before snapshots/windows were emitted. The final run
`live-2026-10-08-03` passed validation after narrow telemetry logging and run-boundary
ordering fixes. The earlier files were not edited or represented as successful.

SHA-256 digests for the final run's principal artifacts:

| Artifact | SHA-256 |
|---|---|
| `telemetry.jsonl` | `d9cd24fbac1cc86d757f10e3c0ef8fb4ea71bdb7179dedc85f1446b89757371f` |
| `benign-run.jsonl` | `45a22e835d0cf4d669d38b45bf31cfe77c1c78da17d1e21df517730a79e2a086` |
| `port-scan-run.jsonl` | `4a34019fe6794c464bfdef087f3e9d666116a408c192a125d6662ccb835d333b` |
| `collection-summary.json` | `ab26b3421fc4c75f2a31ad21dbe4384abea21c83d08677d081a540d6ebaf4abf` |
| `ryu.log` | `0c6b004bc22c3622f726c8b976c9ccb70917e7170d8c2b90017076a084a0329f` |

## Protocol scope and limits

This increment implements only generic Ethernet, ARP, IPv4, TCP-header, UDP-header,
port-description, and flow-stat observations. It does not implement attack detection,
DHCP parsing, DNS parsing, device inventory, host/IP-MAC binding validation, scan
aggregation, SYN-rate aggregation, or any other attack-specific logic.

Potential future use is narrow and evidence-based:

- ARP observations can preserve claims seen in PacketIn; authoritative binding checks
  need a trusted inventory and sufficient visibility.
- TCP observations preserve a packet's flags and ports; SYN aggregation requires a
  deliberate observation coverage and windowing design.
- Port-scan evidence requires distinct destination aggregation over a declared window;
  a single flow rule or PacketIn is insufficient.
- Rogue-device evidence requires a versioned expected device/port inventory. Current
  Stage 3 behavior is a controlled simulation, not proof of unauthorized-device
  detection.
- DHCP and DNS require protocol-specific observation and parsing not implemented here.

## Explicit exclusions

- No detector or `DetectionResult` construction.
- No BENIGN/ATTACK/UNKNOWN state, confidence, novelty, PSI, or score.
- No policy evaluation, mitigation action, adapter call, OVS verification, or live
  mitigation.
- No Stage 5 RF inference, preprocessing, dataset access, or retraining.
- No CICFlowMeter feature mapping or fabricated/imputed feature values.
- No GraphSAGE or other graph model.

Stage 5 remains an offline research plane. Stage 4 records remain unchanged. The Stage 7
policy/enforcement protocol and its thresholds/lifecycle remain unchanged.

## Work required before detector research

1. Repeat the benign and selected scenario collections across separate run IDs and
   quantify run-to-run and benign-condition variation before considering detector
   features or thresholds.
2. Decide whether additional, explicitly bounded packet observation is required for a
   selected protocol question. The current scan run exposed one destination port via
   PacketIn, so the existing coverage cannot support complete scanned-port evidence.
3. Define only the attack-specific observers needed for a selected scenario, with
   observation coverage, aggregation windows, and benign confounders documented.
4. Establish scenario/run-level labels and disjoint run-level train/validation/sealed
   test splits before fitting or calibrating any detector. Scenario journals remain
   run-level context, not per-flow ground truth.
5. Assess timestamp alignment and feature stability on additional controlled runs
   without enabling mitigation.

Until those steps are complete, these contracts are a telemetry foundation, not a
live detector or evidence of security effectiveness.

## Six-scenario observability audit

The read-only audit in
[`stage7-attack-observability-audit.md`](../research/stage7-attack-observability-audit.md)
compares the current Ryu/OVS evidence with all six bounded Stage 3 scenarios. It
confirms that the existing `TelemetryObservation` envelope is sufficient for raw
label-free packet/port records, while the current observation path does not provide
complete protocol coverage. In the validated port-scan run, only one of eight TCP
destination ports appeared in PacketIn; the flow-stat selectors were aggregate L2
rules. The audit therefore recommends a bounded, observe-only packet-copy path for
selected protocol headers as the next telemetry engineering question. No such path,
new contract, protocol parser, detector, or mitigation was implemented by that audit.

The initial audit documents the Eventlet warning in the Ryu log: one RLock was not
greened during Eventlet thread patching. The later bounded packet-evidence run also
logged the warning, while producing complete stats collections and validator-clean
telemetry without handler exceptions. Its behavior under concurrency or load remains
unverified. See the [packet-evidence instrumentation report](../research/stage7-packet-evidence-instrumentation.md)
for measured coverage, byte-retention caveats, and cleanup details. No runtime or
dependency change was made; a focused concurrency/startup diagnostic is recommended
before higher-rate or concurrent telemetry work.
