# Stage 7 Bounded Packet-Evidence Instrumentation

## Scope and status

This is an observe-only instrumentation validation. It does not implement a
detector, assign labels to telemetry, calculate detection metrics, call the
risk policy, or invoke mitigation. Scenario journals and telemetry remain
separate artifacts and are joined only by their explicit `run_id`.

**DESIGNED:** use temporary OpenFlow 1.3 rules in the isolated Mininet bridge
to copy narrowly selected TCP traffic to Ryu while sending the original packet
to h3. The observer is opt-in (`--packet-evidence`) and requires explicit run
context. Each rule is limited to h2 ingress port 2, source `10.0.0.2`,
destination `10.0.0.3`, one of the eight fixed scan destination ports, and a
30-second hard timeout. The action outputs to the controller and directly to
the original h3 port. This avoids changing the intended forwarding path.

The match deliberately does not include TCP flags. The earlier diagnostic run
showed that putting an OpenFlow TCP-flags mask in the rule match caused the
existing Stage 4 FlowRecord parser to reject the corresponding stats record.
The corrected experiment leaves FlowRecord semantics unchanged and records
TCP header bits from the copied PacketIn instead.

**IMPLEMENTED:** only parsed header metadata is serialized: Ethernet and IP
addresses, protocol, TCP ports and bits, ingress port/datapath provenance,
run ID, observation time, sampling sequence, byte-length metadata, and source
provenance. Raw bytes and application data are not written to JSONL. The
controller's deterministic acceptance budget is four accepted observations
per rolling second and 16 per run; there is no in-memory event queue. Offers,
accepted events, rate drops, and run-cap drops are reported in a
`packet_evidence_coverage` record. Observer rules are checked in the scenario
journal's before/after OVS flow dumps, then the isolated Mininet bridge is
removed and Ryu exits.

## Controlled collection

Final artifact directory:
[`experiments/stage7-telemetry/packet-evidence-2026-10-08-03`](../../experiments/stage7-telemetry/packet-evidence-2026-10-08-03)

| Run | Run ID | Scope and measured boundary | Flow collections / snapshots | ObservationWindows | Packet observations | Port observations |
|---|---|---|---:|---:|---:|---:|
| Controlled connectivity | `052feb3a-e9dd-48c5-b5a4-be5678554bfc` | h1 → h3, six bounded pings; 17:53:06.614705–17:53:15.366738 UTC (8.752 s) | 5 complete single-part / 45 | 56 | 25 ordinary Ryu observations; 0 selected packet copies | 4 PORT_DESCRIPTION |
| Bounded port scan | `bc959a85-2c8d-4cd3-8d52-d5f43c688942` | h2 → h3, 8 s configured, 1 probe/s, fixed eight-port list; 17:53:15.433236–17:53:22.798671 UTC (7.365 s) | 5 complete single-part / 50 | 63 | 24 ordinary Ryu observations plus 8 selected copies | 4 PORT_DESCRIPTION |

Each run had zero incomplete or empty collections, zero incomplete-collection
records, and five complete statistics collections with one part each. The
collections produced 45 and 50 rule-stat FlowRecords, respectively. There were
no multipart replies to assemble in this run. The combined JSONL contains 95
FlowRecord snapshots, 119 ObservationWindows, 20 flow-collection lifecycle
records, 61 ordinary TelemetryObservation records, two packet-evidence
coverage records, two run metadata records, and zero incomplete runs. The
windows remain rule-counter intervals, not packet-flow features.

Run metadata carried the same run ID as the separate scenario journal. Run
start/end boundaries are recorded, and packet-evidence context was ended before
Mininet teardown. The scenario journal describes the controlled procedure; it
does not provide per-flow ground truth.

## Generated versus observed scan probes

The Stage 3 journal records eight generated `fixed_tcp_probe` events to h3 on
ports `22, 53, 67, 80, 443, 8080, 18080, 5353`. The telemetry contains eight
`ryu_openflow_bounded_packet_copy` records with the same destination-port set,
eight distinct source/destination/port tuples, and `tcp_bits=2` for all eight
records. Thus observed destination-port coverage for this one bounded run was
8/8 (100%); no generated port was missing. The instrumentation summary reports
8 offers, 8 accepted records, 0 rate drops, and 0 run-cap drops. This is a
coverage measurement against the controlled scenario journal, not a detector
label or effectiveness result.

The benign run had 18 Ethernet, 2 ARP, 1 IPv4, and 4 port-description
observations, with no selected-copy offers or drops. The scan run had 18
Ethernet, 5 ARP, 1 IPv4, 8 TCP packet-evidence copies, and 4 port-description
observations. `PORT_DESCRIPTION` records report switch port state/configuration;
they do not identify an attached device or establish attack evidence.

In the scan OVS dump, all eight temporary observer rules were present before
and after the probes with cookie `0x534445560001`, the fixed h2→h3 selectors,
controller-copy action, and `output:3`. The sum of their matched packet counts
after the run was eight. The Stage 3 journal separately reports successful
h1→h3 baseline reachability. These observations verify the configured copy and
forward outputs for this test; they do not prove a detector can identify a
scan.

## Bounds and byte-retention caveat

**OBSERVED:** the installed host runs Open vSwitch 3.6.2. The installed OVS
action documentation states that, starting with OVS 2.7, the `max_len` option
on the `controller` action has no effect because packet-in messages are sent
without packet buffering; the full packet is sent to controllers. This is
documented in the [official OVS actions reference](https://docs.openvswitch.org/en/stable/ref/ovs-actions.7/).
The OpenFlow 1.3 action parser in the installed Ryu source represents
`OFPActionOutput.max_len` as the requested maximum, while the installed Ryu
`OFPPacketIn` parser defines `total_len` as the full Ethernet frame length and
`data` as the Ethernet frame bytes (it trims only alignment padding). Thus
`copied_byte_count=74` and `original_byte_count=74` are frame bytes, not
OpenFlow-message framing. The OVS flow dump's `CONTROLLER:54` records the
requested action field; it does not prove that OVS applied that cap.

An additional local capability probe using `ovs-ofctl -O OpenFlow13 parse-flow`
rejected `output(port=CONTROLLER,max_len=54)` with `unsupported truncate port
CONTROLLER`. OVS supports per-output truncation for eligible physical output
ports, but not this direct controller output form. The selected action therefore
does deliver more packet bytes to Ryu than the configured 54-byte request. For
the observed fixed TCP connection probes, the scenario invokes
`socket.create_connection`, sends SYNs (`tcp_bits=2`), and intentionally sends no
application data. That does not make the current mechanism safe for arbitrary
payload-bearing traffic, and it does not establish the requested controller
byte cap.

**OBSERVED:** the packet-evidence code passes `message.data` to Ryu's in-memory
packet parser, then serializes only explicitly selected header metadata and
length/provenance fields. The final JSONL has no packet-byte arrays, raw packet
field, or application payload field. No packet dump or pcap was generated.
This establishes non-persistence for this code path and artifact, not that the
switch-to-controller transport omitted the packet body.

**DECISION:** do not expand or freeze this mechanism as a detector-input
foundation. The repeatability collection was not run because the controller
copy is not byte-capped on this OVS version. A future safe implementation needs
a separate truncated physical-port mirror/collector or another mechanism that
demonstrably bounds bytes before they reach a packet parser. That is a separate
telemetry architecture change; until verified, leave packet evidence disabled
by default and restricted to the controlled test scenario.

## Resource and runtime observations

The runner sampled Ryu `/proc` process counters after each run. Cumulative CPU
time was 0.41 seconds after benign and 0.45 seconds after scan (0.45 seconds
overall in the runner's sampled interval); observed process high-water RSS was
64,392 KiB. This is coarse process-level measurement, not an isolated estimate
of instrumentation overhead. The Eventlet startup warning `1 RLock(s) were not
greened` appeared. The installed Ryu manager calls `hub.patch(thread=False)`
early during manager import, then `hub.patch(thread=True)` later in `main()`.
Eventlet's `_green_existing_locks` scan reports an RLock it could not convert
during that later thread patch. The warning does not name the lock's owner, so
the specific lock cannot be identified from this run. No dependency/runtime
change was made. The final Ryu log contains no packet handler or flow-stat
handler traceback, and the sequential telemetry records validate in timestamp
order. This is evidence against an observed correctness failure in this run,
not a concurrency-safety proof. Classify the warning as a concern whose effect
was not demonstrated; higher-rate or concurrent use remains unvalidated.

## Recorder validation and cleanup

The read-only telemetry validator accepted the final `telemetry.jsonl`:

| Record type | Count |
|---|---:|
| recorder metadata | 1 |
| run metadata / boundaries | 2 / 4 |
| flow collections | 20 lifecycle records |
| flow snapshots | 95 |
| ObservationWindows | 119 |
| TelemetryObservations | 61 |
| packet-evidence coverage | 2 |
| incomplete runs | 0 |

The runner's final summary reports `controller_output_and_h3_output_verified`
and `clean_shutdown=true` for both topologies. Its readiness/cleanup checks
refused pre-existing bridges/listeners; after the run no Ryu listener on 6653
remained and the `s1` bridge was absent. The result artifacts are the JSONL
telemetry, two scenario journals, Ryu log, active-context record, and collection
summary in the directory above.

An earlier diagnostic run is preserved at
`experiments/stage7-telemetry/packet-evidence-2026-10-08-02`. Its rules matched
TCP flags in OpenFlow and caused FlowRecord parsing exceptions. It is not the
final result and is excluded from the counts here. Removing the TCP-flags match
fixed that interoperability issue without changing FlowRecord.

## Hardening follow-up and repeatability decision

The final one-benign/one-scan artifact above is the only packet-evidence
collection accepted for this assessment. **No additional runs were made** after
the Open vSwitch `max_len` semantics were established, so there are no three-run
per-condition repeatability statistics. The two earlier diagnostic directories
remain preserved and are not pooled with the final run.

The corrected rule no longer includes a TCP-flags selector. It produced 95
FlowRecord snapshots and 119 ObservationWindows with zero Ryu handler
tracebacks; FlowRecord semantics were not changed. The previous diagnostic's
FlowRecord exceptions came from the earlier TCP-flags selector, not from the
Eventlet warning.

## Interpretation and remaining limits

**OBSERVED:** in one bounded scan run, the selected copy path exposed every
generated destination port that the earlier generic PacketIn path had largely
missed. Original forwarding succeeded, the OVS observer rules were visible in
the flow dump, and the recorder preserved run IDs and coverage counters.

**NOT ESTABLISHED:** this is one benign and one scan run. It does not establish
repeatability, detector performance, false-positive behavior, or general
packet visibility. The generic PacketIn stream remains partial; absence of a
PacketIn is not evidence that traffic did not exist. Rule counters remain
cumulative rule-level counters. OVS 3.6.2 sends the entire packet for controller
actions despite `CONTROLLER:54`, so the present PacketIn-copy path can deliver
payload bytes for other eligible traffic. The mechanism is not safe to expand
until the copy is truncated before it reaches the observer. DHCP/DNS parsing,
ARP binding state, and trusted device inventory remain unimplemented.

The final hardening decision is **C. Packet-evidence instrumentation is not
sufficiently trustworthy to freeze as a detector-input foundation**. The
per-run event bounds and metadata-only recorder are verified, but OVS's
controller action sends full packet data, so the intended byte bound is not
enforced. Telemetry is evidence collection, not attack classification. No
detection metric or security-effectiveness claim is made.
