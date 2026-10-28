# Stage 7 OVS Packet-Truncation Validation

## 1. Objective

This single, bounded, benign validation tested whether OVS 3.6.2 can send a
truncated observation copy to a separate collector before the frame reaches
that observer. It did not test a detector, attack scenario, packet coverage
across scenarios, production safety, or performance under load.

No Stage 5 data, model, or evaluation code was used. The Ryu packet-evidence
copy feature was disabled. No packet capture was created, and no raw frame or
payload bytes were written to disk.

## 2. Exact OVS mechanism tested

The experiment used OVSDB `Mirror.snaplen`, not an OpenFlow
`CONTROLLER:max_len` action:

- OVS 3.6.2 / OpenFlow 1.3.
- Mirror selected ingress traffic on `s1-eth1` (h1) only.
- Mirror output was `s7obs0`, a veth endpoint added as an OVS bridge port.
- The peer `s7rcv0` was moved into a separate network namespace named
  `s7collector`.
- Configured `Mirror.snaplen`: **128 bytes**.
- An exact, temporary UDP forwarding entry sent only `in_port=1, UDP,
  destination port 39000` to h3's port. It prevented the measured probe from
  being sent to Ryu through the table-miss path. It was an isolated forwarding
  rule, not mitigation.

The observed OVSDB row reported `snaplen=128`, the selected ingress port, and
the dedicated output port. Configuration output was treated as setup evidence
only; the acceptance decision used independently measured frame lengths at h1
and at the collector.

## 3. Test topology and packet

The existing isolated Stage 2 Mininet star was used: h1, h2, and h3 connected
to OVS bridge `s1`, with the local Stage 2 Ryu controller on loopback TCP 6653.
Datapath ID was `0000000000000001`. No external interface or production switch
was involved.

One UDP datagram was sent from h1 (`10.0.0.1`) to h3 (`10.0.0.3:39000`). Its
application payload was 400 repeated test bytes, generated in memory. An
AF_PACKET socket on h1 measured the outgoing Ethernet frame length without
writing frame bytes. The h3 test receiver returned a short response, confirming
a UDP round trip; that response carried only the received payload length.

| Measurement | Value |
|---|---:|
| Original h1 egress frame | **442 bytes** |
| Configured OVS mirror snaplen | **128 bytes** |
| Collector-received frame | **128 bytes** |
| Collector result | **exactly snaplen** |
| Truncated relative to original | **Yes, by 314 bytes** |
| Packet count accepted by the matching collector | **1** |

The single observed frame was IPv4/UDP from `10.0.0.1` to `10.0.0.3`,
destination port 39000. The original and copied lengths were measured at
different interfaces/processes. The received copy met both acceptance
conditions: `128 <= 128` and `128 < 442`.

The first 42 bytes of this frame were Ethernet, IPv4, and UDP headers. Thus the
128-byte observation also contained **86 bytes of UDP application payload in
collector memory**. The collector did not inspect or persist those bytes. This
is a successful byte cap, but it is larger than needed for this test's
Ethernet/IPv4/UDP metadata.

## 4. Ryu and collector isolation

Ryu did **not** receive the mirrored test UDP tuple. The Ryu packet-evidence
feature remained disabled. The temporary OpenFlow rule handled the measured
UDP request directly, and no Ryu `TelemetryObservation` contained the test
tuple. The OVS mirror output pointed to the dedicated observation port, not
`CONTROLLER`.

Ryu continued to handle ordinary controller events for the Stage 2 forwarding
topology. Its aggregate `packet_in_forwarded` count changed from 19 before the
probe to 20 in the later summary, but inspection found no observation of the
test UDP tuple; the added event was unrelated IPv6 multicast/control traffic
outside the measured UDP exchange. Therefore the evidence supports “the copied
test UDP packet was not sent to Ryu,” not “Ryu received no PacketIn events.”

The collector namespace had no IPv4 route and the collector veth had no IPv4
address. It had the namespace loopback addresses and an automatically assigned
IPv6 link-local address. The Ryu listener was bound on the host's loopback;
from the separate namespace, a connection attempt to `127.0.0.1:6653` failed,
as that address referred to the namespace's own loopback. OVS reserves a
Mirror output port for mirror traffic and discards frames received on it, so
the collector endpoint was not used as an ordinary forwarding link.

**Isolation limit:** this verifies separation from Ryu's loopback listener and
from the Mininet forwarding path for this experiment. It does not establish a
general-purpose security boundary against a compromised host/kernel, and IPv6
routes were not separately enumerated. The collector namespace and veth were
temporary and removed after the run.

## 5. Forwarding result

The same bounded `ping -c 3 -W 1` reachability check from h1 to h3 passed at all
three points:

| Condition | Result |
|---|---|
| Before mirror setup | 3 sent, 3 received, 0% loss |
| Mirror/copy active | 3 sent, 3 received, 0% loss |
| After mirror removal | 3 sent, 3 received, 0% loss |

The single UDP test request also traversed the exact OVS forwarding rule; OVS
flow statistics recorded one packet and 442 bytes. The receiver responded, so
the bounded request/response completed while the mirror was active. This is a
small functional check, not evidence of zero performance impact under load.

## 6. Payload persistence and artifacts

The collector read each candidate frame into process memory to inspect its
length and fixed Ethernet/IPv4/UDP headers. It wrote only timestamp, received
length, configured snaplen, protocol, addresses, ports, sequence, and a
packet-type value to `collector-metadata.json`. The sender wrote only its
measured frame length and UDP metadata into the parent process's result object.
The Ryu log contains controller/flow events and parsed telemetry metadata; it
does not contain packet data or application payload bytes.

Persisted outputs in the accepted run directory:

- `collector-metadata.json`
- `validation-summary.json`
- `ryu.log`

No pcap/pcapng, raw packet field, payload field containing packet bytes, or
packet dump was created. A file listing and content scan found no pcap and no
test payload marker. The metadata JSON parsed successfully. There was no
telemetry JSONL artifact, so the telemetry JSONL validator did not apply.

Accepted run ID: `94e1e37a-41b6-4f13-b00d-3789e8de4482`.

Artifacts:

- [Accepted validation summary](../../experiments/stage7-telemetry/truncation-validation-2026-10-08-02/validation-summary.json)
- [Collector metadata](../../experiments/stage7-telemetry/truncation-validation-2026-10-08-02/collector-metadata.json)
- [Ryu log](../../experiments/stage7-telemetry/truncation-validation-2026-10-08-02/ryu.log)
- [Validation runner](../../scripts/run_stage7_packet_truncation_validation.py)

An initial diagnostic invocation is preserved under
`truncation-validation-2026-10-08-01`. It measured a 128-byte collector frame,
but its first harness guard compared aggregate PacketIn counts across the
whole interval and rejected an unrelated control PacketIn. That guard was
narrowed to inspect the actual UDP tuple. The diagnostic invocation cleaned up
the topology and is not counted as a separate validation result or a
repeatability run.

## 7. Cleanup and runtime observations

Independent post-run checks confirmed:

- bridge `s1` absent;
- mirror configuration absent;
- `s7collector` namespace absent;
- `s7obs0` observation interface absent;
- Ryu listener on 127.0.0.1:6653 absent.

The Eventlet warning `1 RLock(s) were not greened` appeared in the Ryu startup
log. This experiment does not resolve that warning or establish that it is
benign under concurrent/high-rate controller operation. The collector itself
was a separate namespace process and was not an Eventlet task.

The collector did not expose packet/drop statistics: it accepted one
matching frame and did not measure aggregate frames filtered by its local
tuple selector or kernel socket drops. No packet-loss rate or coverage claim
is made. The test does not establish long-run queue bounds or CPU/memory cost.

## 8. Exact command and implementation

The accepted run used:

```bash
sudo env PYTHONPATH="$PWD" python3 \
  scripts/run_stage7_packet_truncation_validation.py \
  --output-dir experiments/stage7-telemetry/truncation-validation-2026-10-08-02
```

The runner started the existing `networking.ryu.stage2_controller` with
`SDN_STAGE2_PACKET_EVIDENCE_ENABLED=false` and
`SDN_STAGE2_INSTALL_TEST_RULE=false`, then created the existing Stage 2
Mininet topology. Its observation-specific operations were:

```bash
ip netns add s7collector
ip link add s7obs0 type veth peer name s7rcv0
ip link set s7rcv0 netns s7collector
ovs-vsctl add-port s1 s7obs0
ovs-vsctl -- --id=@src get Port s1-eth1 \
  -- --id=@out get Port s7obs0 \
  -- --id=@mirror create Mirror name=stage7-truncation-validation \
  select_src_port=@src output_port=@out snaplen=128 \
  -- set Bridge s1 mirrors=@mirror
ovs-ofctl -O OpenFlow13 add-flow s1 \
  'cookie=0x573700000001,priority=200,in_port=1,udp,tp_dst=39000,actions=output:3'
```

The collector used a Python AF_PACKET socket bound only to `s7rcv0`, filtered
in memory for the single expected UDP tuple, and serialized metadata only. The
sender used a second AF_PACKET socket on h1 to measure the outgoing frame,
then sent one UDP datagram. All mirror, link, namespace, Mininet, and Ryu
resources were removed in cleanup. The user-space experiment code did not
call `RiskPolicy`, `MitigationOrchestrator`, the mitigation adapter, or an ML
detector.

## 9. Validation and integrity

- The output JSON files parsed successfully.
- No new telemetry JSONL was produced; the telemetry JSONL validator was not
  applicable.
- Ruff, pytest, and mypy results are reported with the implementation report.
- The Stage 5A raw-file hashes are defined by the frozen audit artifact;
  Stage 5D prepared hashes are defined by the frozen preparation artifact.
  They were checked after this run. Stage 5 experiment outputs and Stage 5F
  protocol hashes were also checked.
- Stage 7 policy protocol files and the prior packet-evidence result artifact
  were checked by SHA-256 after this run.

## 10. Limitations

- One packet and one OVS 3.6.2 mirror configuration were measured; there is no
  repeatability evidence yet.
- The test proves exact 128-byte truncation for one IPv4/UDP frame on this
  topology. It does not establish behavior for VLANs, IPv6 extension headers,
  fragments, other datapaths, different frame sizes, or other protocols.
- The mirror selection was one ingress port and one destination; all-traffic
  coverage was not tested.
- Collector drops and OS receive-queue overflow were not measured.
- The Eventlet RLock warning remains unresolved.
- No attack scenario, detector, threshold, model, classification metric,
  policy decision, or mitigation was evaluated.

## 11. Freeze decision

**B — partially works but requires a specific fix before repeatability.** The
OVS 3.6.2 mirror did enforce the configured 128-byte boundary at the isolated
collector, but that boundary passed 86 bytes of UDP application payload into
collector memory even though those bytes were unnecessary for this packet's
Ethernet/IPv4/UDP header evidence. Before a repeatability campaign, choose and
validate a header-only snaplen for the specific evidence scope. For
Ethernet/IPv4/TCP tuple and flag evidence, validate a 54-byte boundary; for
Ethernet/IPv4/UDP headers alone, 42 bytes is sufficient. Protocols needing
application-level fields such as DHCP/DNS require a separately declared
minimal parse length and must not inherit a larger cap silently.

The tested mechanism otherwise met this experiment's byte-boundary condition:
it delivered a 128-byte mirror frame for an independently measured 442-byte
original, the collector stayed outside the forwarding path, and Ryu did not
receive the test UDP tuple. Forwarding worked before, during, and after
cleanup; no raw bytes or payload were persisted; temporary resources were
removed. This result verifies OVS mirror truncation, but does not yet validate
the smaller header-only boundary needed to minimize payload exposure in the
next collection campaign.

This decision does **not** authorize the 3+3 repeatability campaign yet. The
next step is one minimal header-only truncation check at the selected TCP
boundary, followed by review. It does not freeze the overall packet-observation
system, prove general isolation or coverage, resolve the Eventlet warning, or
authorize detector implementation or autonomous mitigation.

## TCP 54-byte header-boundary validation

### Objective and method

This is a separate, single-packet validation of the proposed 54-byte boundary.
It preserves the UDP experiment above as its own result. The test used the same
isolated Stage 2 Mininet topology and OVS 3.6.2 `Mirror.snaplen` mechanism, with
an OVS mirror from h1's ingress (`s1-eth1`) to `s7obs0`; the veth peer
`s7rcv0` remained in the dedicated `s7collector` network namespace. Ryu used
OpenFlow 1.3 on loopback port 6653, and its packet-evidence feature was off.
One narrowly matched temporary forwarding flow sent the test tuple to h3.

The sender generated one checksummed IPv4/TCP Ethernet frame in memory. It
contained a 256-byte test payload so the original frame was larger than the
configured boundary. The packet used source `10.0.0.1:40123`, destination
`10.0.0.3:39001`, and PSH+ACK flags. This was a bounded synthetic TCP packet,
not an attack scenario or a completed TCP handshake. An AF_PACKET sender socket
measured its outgoing frame; the separate collector parsed the mirrored copy
in memory and wrote metadata only.

### Measured header boundary

| Measurement | Sender/original | Collector copy |
|---|---:|---:|
| OVS `Mirror.snaplen` | — | **54 bytes** |
| Ethernet frame length | **310 bytes** | **54 bytes** |
| Ethernet header | 14 bytes | 14 bytes |
| IPv4 IHL | 5 words | 5 words / 20 bytes |
| IPv4 options | 0 bytes | 0 bytes |
| IPv4 total length | 296 bytes | 296 bytes declared in header |
| TCP data offset | 5 words | 5 words / 20 bytes |
| TCP options | 0 bytes | 0 bytes |
| TCP source/destination ports | 40123 → 39001 | 40123 → 39001 |
| TCP flags | PSH+ACK (`0x18`) | PSH+ACK (`0x18`) |
| Application payload bytes visible at collector | 256 in original | **0 bytes** |

The collector received exactly the configured 54-byte boundary. Independently
measured header lengths sum to 14 + 20 + 20 = 54 bytes. The collector confirmed
the TCP header was complete and that the frame ended at the end of that header;
it did not receive application payload bytes. No IP or TCP options were
present in this test packet. Therefore this result does not test how a 54-byte
boundary presents option-bearing headers. For the required evidence fields in
this packet (Ethernet/IP endpoints, TCP ports, and flags), all bytes were
available without payload.

### Ryu, forwarding, isolation, and cleanup

No Ryu PacketIn matching the test TCP tuple was found in the Ryu log. Ryu did
emit unrelated PacketIn/telemetry events during the Mininet run; the result is
specifically that the mirrored test tuple was not observed by Ryu. The
collector received the copy through the dedicated observation veth and was not
part of the h1-to-h3 forwarding path. From its network namespace, a connection
to `127.0.0.1:6653` did not reach Ryu's host-loopback listener. IPv4 addresses
and routes and IPv6 addresses and routes were inspected. The namespace had an
IPv6 link-local address/route, so this test makes **no claim of complete IPv6
isolation**.

Bounded `ping -c 3 -W 1` reachability from h1 to h3 passed before mirroring,
while the mirror was active, and after cleanup (3/3 replies in each check).
Cleanup checks reported the Mininet bridge, collector namespace, observation
interface, mirror row, and Ryu listener absent. The test did not invoke policy,
mitigation, or the Stage 7 gateway.

### Persisted data and runtime observations

The run ID is `e94601f0-88d1-453e-aff3-0a57729c65f2`. The experiment directory
contains `collector-metadata.json`, `validation-summary.json`, and `ryu.log`.
The collector metadata contains the frame length, configured snaplen, parsed
header lengths/options lengths, addresses, ports, flags, timestamp, and an
explicit zero for visible application-payload bytes. The sender summary stores
the measured original length and intended payload length, but no payload
content. Inspection found no raw packet byte field, payload bytes, packet dump,
or pcap/pcapng file. The Eventlet startup warning `1 RLock(s) were not greened`
appeared again. No associated handler exception or test-tuple PacketIn was
observed; this one run does not resolve the warning or establish concurrency
correctness.

### Commands and validation

The isolated test was run as:

```bash
sudo env PYTHONPATH="$PWD" python3 \
  scripts/run_stage7_tcp_truncation_validation.py \
  --output-dir experiments/stage7-telemetry/tcp-truncation-validation-2026-10-08-01
```

The temporary runner is
[run_stage7_tcp_truncation_validation.py](../../scripts/run_stage7_tcp_truncation_validation.py).
The result files are [validation summary](../../experiments/stage7-telemetry/tcp-truncation-validation-2026-10-08-01/validation-summary.json),
[collector metadata](../../experiments/stage7-telemetry/tcp-truncation-validation-2026-10-08-01/collector-metadata.json),
and [Ryu log](../../experiments/stage7-telemetry/tcp-truncation-validation-2026-10-08-01/ryu.log).
The result JSON is metadata, not a telemetry JSONL file, so the telemetry
replay validator does not apply. Validation after this experiment: Ruff passed;
pytest passed with 203 tests and 2 privileged tests skipped; the temporary
runner passed targeted mypy. Repository-wide mypy reports the known existing
`networking/ryu/stage2_controller.py:373` optional-budget issue. Frozen Stage
5/Stage 7 hashes and the prior UDP result artifact were rechecked after the
experiment.

### TCP boundary decision

**A — for the measured no-options Ethernet/IPv4/TCP evidence boundary, the
54-byte copy was experimentally verified.** It delivered exactly 54 bytes,
contained the complete measured Ethernet, IPv4, and TCP headers including
addresses, ports, and flags, and exposed zero application payload bytes to the
collector. This is sufficient to proceed to the separately planned bounded
repeatability campaign for evidence fields contained in these headers. The
result does not prove behavior for option-bearing TCP/IP headers, VLAN tags,
IPv6, other packet shapes, general traffic coverage, or production safety. It
does not supersede the earlier **B** decision for the 128-byte UDP experiment,
freeze the overall observation system, resolve Eventlet, or authorize a
detector or mitigation.
