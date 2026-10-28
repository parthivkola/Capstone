# Stage 7 Attack Observability Audit

## Scope and evidence basis

This is a read-only audit of the existing Stage 3 generators, Stage 7 telemetry contracts and Ryu controller, and the validator-clean live collection at `experiments/stage7-telemetry/live-2026-10-08-03`. It does not add a detector, label, threshold, score, risk decision, or mitigation action.

**OBSERVED FROM REPOSITORY:** Stage 3 scenarios are bounded Mininet traffic generators. The journal records scenario-level intent, parameters, and sender or fixture events. It is not a per-packet controller capture or per-flow ground truth. The Ryu controller receives PacketIn messages for packets delivered by OVS, parses Ethernet/ARP/IPv4/TCP/UDP headers, emits port-description observations, and requests OpenFlow flow statistics. It uses table-miss forwarding and then learns L2 rules.

**OBSERVED IN LIVE ARTIFACTS:** The two runs have run IDs `a359f79b-ee50-4f24-bab5-2eaa996cee18` (bounded h1-to-h3 connectivity) and `7ab81dd2-3d58-41f2-a222-924fbcbaa88d` (bounded h2-to-h3 TCP probes). In the scan run, the scenario journal records eight probes to the fixed allowlist. Ryu recorded one TCP PacketIn, to destination port 22. Flow statistics showed aggregate L2 rule counters rather than all eight transport destinations. This run supports partial observability, not complete scan evidence.

**DESIGN INFERENCE:** PacketIn fields are direct evidence only for the particular packet delivered to Ryu. They do not imply that all traffic was observed. Rule counters are direct cumulative counters for a switch rule; deltas/rates are derived rule-level observations and cannot be treated as per-flow or packet-level protocol semantics.

## Current telemetry boundary

`FlowRecord` remains an OpenFlow rule-stat snapshot. `ObservationWindow` remains a derived interval between two rule-counter snapshots. Its `rule_packet_delta`, `rule_byte_delta`, `rule_packet_rate_per_second`, and `rule_byte_rate_per_second` names retain their rule-counter meanings. They are not CICFlowMeter features such as `Flow Pkts/s`, `Flow Byts/s`, or `Flow Duration`.

`TelemetryObservation` is the existing typed, provenance-bearing envelope for raw PacketIn and port-description observations. It has no attack label or detector output. ARP, IPv4, TCP, and UDP header metadata are included only when those headers are present in a PacketIn. DHCP and DNS observation type values are reserved, but their message parsers are not implemented. The controller requests OpenFlow port descriptions, not periodic port counters or port-status events. Port descriptions report switch state; they do not establish a trusted device inventory. The controller's in-memory MAC learning table is forwarding state, not an exported, authoritative inventory.

After a learned L2 rule is installed, matching traffic can be forwarded by OVS without PacketIn. In the validated scan, OVS's rule-stat counters reflected traffic that PacketIn did not fully expose, but their L2 selectors did not reveal the complete destination-port set. The successful transmission of a scenario packet and the fact that OVS forwarded or counted it are separate from whether Ryu observed its protocol fields.

## Six-scenario observability matrix

| Stage 3 scenario | What the generator actually does | Current Ryu/OVS evidence | Missing evidence and minimum additional evidence | Evidence source and future use |
|---|---|---|---|---|
| **ARP spoofing** | Sends at most five unicast ARP replies from existing h2. The Ethernet/ARP sender MAC is h2's MAC while the sender IP claims h3's IP; target is h1. | **Code capability:** Ryu parses opcode and ARP sender/target IP/MAC from a delivered PacketIn. The ordinary L2 learning behavior can install a rule after initial traffic. No ARP-spoof collection is in the cited live artifact. | Repeated, sufficiently covered ARP claims with ingress port, datapath, observed time, and run ID; plus a separately versioned trusted IP-to-MAC/port inventory or independently observed competing claims. A conflict is evidence of inconsistent claims, not by itself attack classification. | PacketIn is direct for a delivered ARP frame; binding/conflict is derived controller state; expected inventory is contextual. Could support a future result only with coverage and trusted reference data. |
| **DHCP starvation** | Sends up to four DHCP client exchanges, one per second, using four declared client MACs to h3's local four-address in-memory DHCP fixture. The fixture tracks offers/leases and journals responses. This is a bounded fixture-pool pressure simulation. | Ryu can record generic UDP ports for delivered PacketIns. It does not parse DHCP payloads or observe fixture lease/pool state through the telemetry path. No DHCP live telemetry run is in the cited artifact. | For packet evidence: DHCP message type, BOOTP client hardware identity, transaction ID, source/destination, ingress, and time for delivered packets. To establish pool pressure, a fixture/server pool-capacity and allocation-state observation is also needed. | DHCP header/payload parse is direct only for delivered packets. Request counts/unique clients are derived. Fixture pool state is contextual server evidence, not generic OpenFlow telemetry. Would support a bounded fixture study, not general DHCP starvation claims. |
| **Port scan** | Opens sequential TCP connections from h2 to h3 on up to eight fixed allowlisted ports, one per second, bounded to eight seconds. | **Live observed:** eight journaled probes; one TCP PacketIn exposed destination port 22. Aggregate L2 flow counters changed, but no complete port set was visible. | A coverage-defined copy/observation path for the selected TCP headers, retaining source/destination IP and ports, TCP bits, ingress, datapath, timestamp, and run ID. A future evidence aggregator could count distinct observed destination ports per source over a bounded interval and preserve packet-observation IDs. | Packet fields are direct for each copied/delivered packet; distinct-port count is derived from the observed subset. A bounded OpenFlow packet-copy/mirror mechanism is a candidate, but must be checked for OVS behavior and controller load before use. Current evidence is insufficient for defensible scan detection. |
| **SYN flood** | Generates at most 50 bare TCP SYN frames over five seconds, at no more than ten per second, from h2 to one fixed h3 port (18080), varying source port and sequence number. | Ryu records TCP ports/bits for delivered PacketIns. Rule counters may aggregate traffic at L2. The cited live artifact contains no SYN-flood run, so live coverage has not been measured. | Coverage-bounded TCP header observations sufficient to count observed SYN-bearing packets by source/destination tuple and interval. Handshake completion would require observing both directions and tracking tuple state; it remains a derived, incomplete indicator subject to packet loss/retransmissions, not a fact from one SYN bit. | TCP bits/tuple are direct per delivered packet; rates/counts are derived over a declared window. Handshake state is partially observable only with two-direction coverage. Current forwarding may bypass Ryu after learning. |
| **Rogue-device simulation** | Toggles the existing h2-to-s1 link down/up, then sends bounded ARP requests from h2's preconfigured interface and existing MAC. It simulates link/device reappearance; it does not attach a new unauthorized device. | Ryu requests port descriptions when a datapath connects and observes source MAC/ingress on PacketIn. It does not handle OpenFlow port-status events in the current controller. No authoritative approved-device inventory is present. No rogue-device live collection is in the cited artifact. | A switch-port status/link event stream, observed MAC-to-ingress-port events with timestamps, and a separately maintained approved device/port inventory with version/provenance. A new MAC or changed port is an inventory mismatch observation, not a malicious label. | Port status and PacketIn MAC/port are direct when received; change relative to inventory is derived/contextual. Could support a future controlled inventory-mismatch result; existing simulation cannot validate unauthorized-device detection. |
| **DNS anomaly** | Sends at most ten UDP DNS queries at no more than one per second for fixed unusual names under `.test`; h3's local fixture returns NXDOMAIN without recursion or upstream forwarding. | Ryu sees UDP ports for delivered PacketIns but does not parse DNS names, query/response direction, flags, or RCODE. The fixture journals names/answers separately. No DNS live telemetry run is in the cited artifact. | For delivered DNS packets, parse QR, transaction ID, question name/type, response code, endpoints/ports, and time; preserve whether query or response was observed. A bounded packet-visibility path is needed where L2 learning otherwise bypasses Ryu. | DNS fields are direct only when parsed from a delivered packet. Query rates and response distributions are derived. Fixture journal events are scenario context, not controller observations or per-flow labels. |

The terms in the final column describe the evidentiary status of proposed fields: **direct** means present in the actual observed event; **derived** means computed from identified observed events or snapshots; **contextual** means supplied by a separate configuration, inventory, or scenario record; **unavailable** means not present in the current telemetry path. Scenario-generated values in journals must not be presented as controller-observed network evidence.

## Minimum defensible evidence design

### Keep the existing contracts; do not add attack fields

No new contract is justified by this audit. `TelemetryObservation` already represents one raw typed observation with timestamp, source, scope, scalar protocol metadata, provenance, collector timing, and optional run ID. Its payload deliberately rejects attack/detector labels. `ObservationWindow` has a different and still appropriate purpose: rule-counter changes between snapshots. A future protocol aggregator should not overload it or change `FlowRecord` semantics.

If later code needs to aggregate packet observations, design a separate typed protocol-evidence window that references the input observation IDs and records the actual collection policy/coverage, interval, gaps, and aggregation. That is future work; do not infer full traffic from a count of PacketIn events. No confidence, attack label, risk state, or mitigation recommendation belongs in telemetry.

### Minimum additions by scenario

1. **Port scan:** first establish a narrowly scoped, rate-bounded way for selected TCP header packets to be copied to the controller while preserving ordinary forwarding. Validate that it covers all packets in the fixed isolated test and quantify controller load. Then derive unique observed destination ports per source over fixed windows, retaining observation IDs and explicit coverage gaps.
2. **ARP spoof:** retain the existing parsed ARP sender claims, but add enough repeated delivery coverage for the fixed test and compare them with a separately trusted, versioned IP/MAC/port inventory or a prior claim record. State only that claims conflict; do not assign maliciousness in the telemetry layer.
3. **SYN flood:** use the same bounded header-copy mechanism for the single TCP scope, including TCP bits and both directions if handshake evidence is studied. Count SYN observations in measured windows. Do not report handshake failures unless the required response/ACK evidence and missing-packet semantics are validated.
4. **Rogue-device simulation:** expose port-status/link changes and explicitly version the expected MAC-to-switch-port inventory. A Stage 3 link flap and known h2 traffic can validate event correlation only; the current simulation is not an unknown device.
5. **DHCP:** add a DHCP parser for delivered messages, but separately observe the fixture's allocation/pool state if pool exhaustion is the research target. These are distinct evidence sources and need distinct provenance.
6. **DNS:** add a DNS parser for delivered UDP messages and preserve query/response attributes. Establish packet-copy coverage first; a parser cannot recover packets that OVS did not send to Ryu.

These are designs, not implemented or live-validated telemetry. The packet-copy mechanism is the common missing capability for protocol completeness; it must be selected and bounded before adding protocol-specific aggregation.

## Correlation and visibility semantics

Use the existing explicit `run_id` for scenario/run association and preserve `datapath_id`, observed timestamp, scope, source, and provenance on each telemetry record. For any future aggregate, retain the IDs of contributing telemetry records; for rule-counter windows, continue retaining source `FlowRecord` IDs. Scenario journal and telemetry remain separate. Their shared run ID and time/scope permit controlled-run correlation, but do not establish that a particular packet or flow caused a particular scenario event.

Visibility labels for this design:

| Field/evidence | Current status | Boundary |
|---|---|---|
| Ethernet source/destination MAC, ethertype | **PARTIALLY OBSERVABLE** | Direct from PacketIn frames only. |
| ARP opcode and sender/target claims | **PARTIALLY OBSERVABLE** | Parser exists; no guarantee every ARP frame reaches Ryu and no trusted inventory exists. |
| IPv4 addresses/protocol/TTL | **PARTIALLY OBSERVABLE** | Direct from delivered PacketIn only. |
| TCP ports and bits | **PARTIALLY OBSERVABLE** | Direct for delivered TCP PacketIn; not a complete SYN count or handshake record. |
| UDP ports | **PARTIALLY OBSERVABLE** | Direct for delivered UDP PacketIn; no DHCP/DNS payload semantics. |
| OpenFlow rule packet/byte counters | **OBSERVABLE** | Cumulative counters for a specific switch rule when a complete stats collection is received. |
| Rule-counter deltas/rates | **DERIVABLE** | Only for safely paired complete snapshots with valid elapsed time; still rule-level aggregate evidence. |
| Complete scan destination-port set | **NOT OBSERVABLE** in the validated scan run | Only one of eight probe destination ports appeared in PacketIn; L2 rule counters do not recover the other ports. |
| DHCP message type/client ID and DNS question/rcode | **NOT OBSERVABLE** in current telemetry | No payload parser; fixture journals are separate context. |
| Authoritative IP/MAC/device inventory | **NOT OBSERVABLE** | No trusted inventory source is implemented. |
| Port description at request time | **OBSERVABLE** | Describes switch-reported port name/config/state, not attached-device identity; no port counters or port-status stream is collected. |

The run ID and scenario scope are contextual metadata. They are not packet-derived features. Absence of PacketIn evidence is not evidence that the packet/event did not occur.

## Sampling, performance, and safety

The controller currently performs best-effort telemetry on the PacketIn path; it does not mirror all learned traffic. Making every packet visible can turn Ryu into a packet-processing bottleneck and alter the experiment's forwarding path. Before adopting packet copies, constrain them to the isolated Mininet bridge and explicit protocol/scope, cap packet rate and payload size, retain headers rather than application payload where sufficient, measure drops/queueing/CPU/memory, and make coverage gaps explicit. Aggregation state must have bounded cardinality and a fixed expiration policy. Deduplication must be based on explicit event identity or packet metadata and must not accidentally discard retransmissions that matter to the question.

No tcpdump/pcap source is proposed as production detector input. A separately controlled packet-capture source could be considered for ground-truth/coverage verification, but would require an explicit independent provenance and experiment protocol.

## Future detector input and evaluation design

**DESIGNED, NOT IMPLEMENTED:** a future detector should consume evidence-only aggregates, each with schema version, run ID, datapath/scope, interval boundaries, contributing telemetry observation IDs, collection method/coverage, missing/gap indicators, and provenance versions. The detector may then produce the existing `DetectionResult` contract. The aggregation layer must not include scenario labels, attack names, or mitigation outputs in the feature payload.

Future evaluation should split by whole scenario run, never by rows/windows from the same run. Keep scenario journals separate and use them only to assign run-level experimental condition labels after feature extraction. Build separate training, validation, and sealed test run sets; do not fit thresholds or select features on test runs. Include multiple benign runs and repeated controlled runs per scenario, and vary only predeclared bounded rates/durations/targets within the fixed lab. Report run-level uncertainty and benign-condition variation. Engineering validation (telemetry coverage/correctness), detector research evaluation (held-out-run evidence-to-label performance), and later closed-loop system evaluation (mitigation disruption/rollback) are separate experiments.

No detector metrics are reported here. The single validated benign run and single validated port-scan run are not a detector dataset and cannot establish effectiveness.

## Eventlet RLock warning

**OBSERVED:** the final run's Ryu log begins with Eventlet's deprecation warning and `1 RLock(s) were not greened, to fix this error make sure you run eventlet.monkey_patch() before importing any other modules.` The warning is emitted by the installed Eventlet `patcher._green_existing_locks` path. Pinned Ryu manager code first imports `ryu.lib.hub`, calls `hub.patch(thread=False)`, and later calls `hub.patch(thread=True)` during manager startup. The warning therefore concerns a lock created before Eventlet's thread patching; the log does not identify that lock or prove a specific telemetry operation was affected.

**OBSERVED:** despite the warning, this run logged controller startup, OpenFlow 1.3 datapath connections, complete flow-stat collections, PacketIn/port observations, and the telemetry JSONL validator passed. No telemetry handler failure appears in the final Ryu log.

**UNRESOLVED:** these facts do not prove that every Ryu concurrency path is safe or that the warning has no effect under load. It is a compatibility warning, not enough evidence to invalidate the bounded sequential artifact, and not enough evidence to call it harmless generally. No Eventlet/Ryu dependency or runtime was changed. Before higher-rate, concurrent, or long-duration protocol experiments, capture a focused Ryu concurrency/startup diagnostic and resolve or explicitly bound the warning's impact.

## Decision

**B. Minimal additional telemetry is required.** The initial generic-observation port scan exposed the coverage gap: eight probes were generated, but only one destination port was present in PacketIn and the rule counters were L2 aggregates. The subsequent bounded packet-evidence experiment is documented in [Stage 7 packet-evidence instrumentation](stage7-packet-evidence-instrumentation.md). In that single controlled run, eight of eight generated destination ports appeared in selected OpenFlow packet-copy observations. This improves observability for that exact run and scope; it does not establish general coverage or detection performance. DHCP/DNS parsing, ARP binding comparison, inventory, or SYN aggregation should be added only for a chosen research question and with the required independent state.

This is not a detector recommendation or evidence of attack detection. The later packet-evidence task added an opt-in, bounded OpenFlow observer; it did not change FlowRecord semantics or the TelemetryObservation envelope and did not implement detection.
