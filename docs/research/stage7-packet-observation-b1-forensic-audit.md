# Stage 7 B1 Packet-Observation Forensic Configuration Audit

## 1. Incident summary

B1 was the first benign run of the planned packet-observation repeatability
campaign. The runner stopped after collecting metadata because 33 of 37
collector frames exceeded the requested 54-byte boundary. All 37 observed
frames were IPv6 Ethernet frames, which the collector did not decode beyond
the Ethernet header. Their payload visibility is therefore unknown. The
campaign was stopped; B1 was not retried and no later run was performed.

This audit uses only the preserved B1 files, runner/topology source, the prior
TCP-boundary report, local OVS documentation, and read-only commands. The
preserved B1 files do **not** contain an OVSDB Mirror-row dump, a complete
bridge/port/interface dump, mirror counters, or a collector namespace
interface/route snapshot. The OVSDB socket was not readable by the current
unprivileged audit process. Consequently, this report separates the
configuration requested by the runner from the configuration independently
observed during B1.

## 2. Exact B1 evidence

Run ID: `1ff8c915-4daf-4494-a8a1-940e0180b115`.

| Evidence | Preserved result |
|---|---|
| Scenario journal | 6/6 h1→h3 one-ping operations reported successful |
| Sender-side monitor | 5 IPv4 ICMP echo-request frames, each 98 bytes |
| Collector | 37 frames seen and accepted; 0 rate-cap drops; 0 run-cap drops |
| Configured boundary in runner/artifact | 54 bytes |
| Collector lengths | 4 exactly 54 B; 33 above 54 B; none below; maximum 372 B |
| Ethertype | 37/37 `0x86dd` (IPv6) |
| Kernel socket drop counter | Unsupported; drops unknown |
| Payload interpretation | Unknown for the oversized IPv6 frames; IPv6/L4 was not parsed |
| Persistence | Metadata only; no packet bytes, payload, or pcap in the B1 artifact directory |
| Ryu | Ordinary PacketIn events; Eventlet RLock warning; no traceback found |
| Cleanup | Partial summary reports bridge, mirror, namespace, veth, and Ryu listener absent |

The length histogram is 54×4, 70×9, 86×2, 90×5, 110×2, 119×1, 128×1,
130×1, 143×1, 166×3, 314×2, 354×3, and 372×3. B1 timestamps span
2026-10-08 18:34:54 through 18:35:04 UTC in collector metadata. The B1 run
summary is incomplete because the runner aborted on the overlength check;
the separate cleanup status was written during `finally`.

## 3. OVS Mirror configuration

### Requested by the B1 runner

The runner executes the following OVSDB transaction (with `54` substituted
for `SNAPLEN`):

```text
ovs-vsctl -- --id=@src get Port s1-eth2
  -- --id=@out get Port s7obs0
  -- --id=@m create Mirror name=repeat-B1
    select_src_port=@src output_port=@out snaplen=54
  -- set Bridge s1 mirrors=@m
```

Thus the **requested** row is:

| Mirror field | Requested B1 value |
|---|---|
| `name` | `repeat-B1` |
| `select_src_port` | Port row `s1-eth2` |
| `select_dst_port` | Not specified by the command; actual row value not saved |
| `select_vlan` | Not specified by the command; actual row value not saved |
| `select_all` | Not specified by the command; actual row value not saved |
| `filter` | Not specified by the command; actual row value not saved |
| `output_port` | Port row `s7obs0` |
| `output_vlan` | Not specified by the command; actual row value not saved |
| `snaplen` | `54` |
| Mirror statistics | Not captured |

The runner did not save the output of `ovs-vsctl list Mirror`, a Mirror UUID,
or the row's realized values. The cleanup check later confirmed that the row
was absent after teardown, which does not recover its state during B1.
Accordingly, the table above is the requested transaction, **not an
independent observation of the live B1 row**. Defaults for omitted columns
were not treated as measured values.

The installed local `ovs-vswitchd.conf.db(5)` documentation describes
`select_src_port` as selecting packets arriving on listed ports and
`select_dst_port` as selecting packets departing on listed ports. It says an
empty VLAN selection selects all VLANs. It describes `output_port` as an
exclusive mirror destination: non-selected frames are not forwarded to it and
frames received on it are discarded. It documents `snaplen` as the maximum
per-packet number of bytes mirrored and says larger mirrored packets are
truncated in the datapath before the mirror output. The documentation states
no IPv6-specific exception.

## 4. OVS topology

### Topology defined by repository code

`networking/mininet/stage2_topology.py` creates bridge `s1` with three host
links in order: h1, h2, h3. Mininet conventionally assigns `s1-eth1` to h1,
`s1-eth2` to h2, and `s1-eth3` to h3. The B1 runner checked that all three
names were present, read the `ofport` of `s1-eth2` and `s1-eth3`, and stopped
unless they were 2 and 3 respectively. It did not persist the live Bridge,
Port, or Interface rows. The mapping below is therefore the topology/code
mapping expected by the runner, not a saved B1 OVSDB snapshot.

| Expected bridge port | Expected attachment | B1 runner evidence |
|---|---|---|
| `s1-eth1` / OpenFlow port 1 | h1 (`10.0.0.1`, `02:00:00:00:00:01`) | Port name presence checked; Ryu log records h1-source PacketIns at ingress 1 |
| `s1-eth2` / OpenFlow port 2 | h2 (`10.0.0.2`, `02:00:00:00:00:02`) | Port name presence and `ofport=2` checked; requested mirror source |
| `s1-eth3` / OpenFlow port 3 | h3 (`10.0.0.3`, `02:00:00:00:00:03`) | Port name presence and `ofport=3` checked |
| `s7obs0` | host-side veth added to `s1`, requested mirror output | Runner creates/adds it; cleanup summary says absent afterward |
| `s7rcv0` | peer veth moved to namespace `s7collector`; AF_PACKET collector binds here | Runner creates/moves/binds it; cleanup summary says namespace/interface absent afterward |
| Ryu controller | host loopback TCP 6653; OpenFlow 1.3 | Runner starts Ryu; Ryu log reports datapath ID `0000000000000001` |

The controller was not configured as a mirror output. The Ryu app was the
Stage 2 controller, with packet-evidence disabled by the runner. B1 did not
run the Stage 7 gateway or mitigation path.

## 5. Mirror-selection analysis and h1-source frames

The runner requested `select_src_port=s1-eth2`; according to the installed OVS
documentation, that should select packets **arriving on h2's port**. The
topology code and checked OpenFlow port number support the intended h2 mapping.
The command did not request `select_dst_port`, nor `select_all`, and it
replaced the bridge's mirror set with `@m`. But because no live OVSDB row was
saved, these are facts about the command, not proof of every realized Mirror
column or of the port-to-interface bindings during B1.

The collector metadata contains two frames with h1's configured source MAC.
Both are IPv6 multicast Ethernet frames to `33:33:00:00:00:02`, each 70 bytes.
The Ryu log has corresponding h1-source IPv6 PacketIn observations at
OpenFlow ingress port 1 at nearly the same times:

| Collector timestamp | Collector frame | Ryu timestamp / ingress |
|---|---|---|
| `18:34:56.742832Z` | h1 MAC → `33:33:00:00:00:02`, 70 B | `18:34:56.742326Z`, source h1 MAC, `in_port=1` |
| `18:35:04.358967Z` | h1 MAC → `33:33:00:00:00:02`, 70 B | `18:35:04.358610Z`, source h1 MAC, `in_port=1` |

This is strong temporal/address correlation that h1-origin IPv6 multicast
traffic was visible at both the Ryu ingress-1 observation point and collector.
The logs do not provide a packet identifier, so exact packet identity is not
proven. The first pair occurred during the mirror-active setup/reachability
period before the six-ping scenario journal began; the second pair occurred
after the journal's run-end timestamp while the collector was still active.
They are not the IPv4 ICMP ping frames counted by the sender monitor.

Under the documented `select_src_port` semantics and intended topology, h1
ingress traffic should not be selected by a sole h2 ingress selector. The
collector observations are therefore inconsistent with the runner's intended
selection. Potential classes of explanation include a different realized
Mirror row/port reference, a runtime port mapping/configuration discrepancy,
or a packet arriving at the collector by a path other than the intended
selected mirror copy. The saved evidence cannot choose among these. The
collector socket's packet-type values and matching Ryu timestamps do not
identify the OVSDB row that delivered the frame.

The only defensible answer to “which ports were selected by the live B1
Mirror?” is: **not recoverable from the B1 artifacts**. The runner requested
the `s1-eth2` source port; the observed h1-origin frames mean that intended
scope was not independently established.

## 6. IPv6 frames larger than 54 bytes

The collector received each frame through an AF_PACKET socket on `s7rcv0` and
recorded `len(frame)` before parsing. All 37 records identify Ethernet
ethertype `0x86dd`; 33 recorded frame lengths exceed the runner's requested
54-byte snaplen, up to 372 bytes. The collector code does not parse IPv6
headers or transport headers. Its `payload_visibility_assessable` field is
false for those overlength frames, so the metadata's
`application_payload_bytes_visible: 0` is **not evidence that IPv6 payload was
absent**.

The local OVS manual says `Mirror.snaplen` is a maximum per-packet mirror size
and describes datapath truncation before output. It does not document an IPv6
exception. Thus the observed lengths are not explained by documented
protocol-specific snaplen behavior. They show that the bytes reaching the
collector in B1 did not satisfy the requested universal 54-byte boundary.

The evidence does not establish whether the long frames were emitted by the
configured Mirror row without truncation, came from an unexpected/different
Mirror selection or output configuration, or reached the collector through
another source/path. No B1 Mirror row, mirror packet/byte counters, OVS flow
dump, capture at `s7obs0`, namespace interface inventory, or IPv6 route/state
snapshot was retained. Do not infer that IPv6 is exempt from snaplen, nor that
the frames were safe because the JSON contains no bytes.

## 7. Could the IPv6 frames contain payload?

Yes, they **could** contain bytes beyond link/network headers, including
transport or application data. Their exact IPv6 payload composition is
unknown because the collector did not parse IPv6, extension headers, transport
headers, or payload. The artifact stores only lengths and Ethernet metadata.
It is impossible to infer payload absence from the stored
`application_payload_bytes_visible=0`; for IPv6 this is the collector's
default, paired with `payload_visibility_assessable=false`.

No raw bytes, payloads, or packet captures are present in the B1 artifact
directory. That establishes non-persistence, not non-delivery to collector
memory.

## 8. Collector-path and forwarding isolation

### What is supported

- The runner created a new `s7collector` network namespace, created a veth
  pair, moved `s7rcv0` into that namespace, and bound the collector socket to
  `s7rcv0`.
- It added host-side `s7obs0` to bridge `s1` and requested it as the mirror
  `output_port`.
- The OVS documentation says an `output_port` mirror destination is reserved:
  ordinary frames are not forwarded to it and frames received on it are
  discarded.
- The runner probed IPv4 addresses/routes in the collector namespace and
  checked that its own `127.0.0.1:6653` was not reachable. Those outputs were
  not saved in B1.
- Ryu's log contains ordinary stage 2 PacketIns, including the two h1 IPv6
  multicast records correlated above. No Ryu event identifies the mirror
  output port or proves the collector's entire input set.
- Before-observation and mirror-active reachability checks must have passed
  for the runner to reach the collector validation stage; the runner aborts
  if either check fails. The scenario journal independently records all six
  h1→h3 ping operations successful.
- The after-cleanup reachability call ran in `finally`, but its result was
  not retained in the partial B1 `run-summary.json`. It must be reported as
  **unknown**, not passed.
- Cleanup summary records bridge, mirror, namespace, observation interface,
  and Ryu listener absent after teardown.

### What is not established

The namespace topology code makes the dedicated-veth collector design
credible, but B1 did not preserve a namespace `ip link` inventory, IPv6
addresses/routes, bridge/port/interface dump, or OVSDB state. Therefore it is
not possible to prove from B1 artifacts that the collector could receive
frames only from the intended Mirror output. The live collector's two
h1-correlated records are a further reason not to claim the intended source
selection was isolated. The collected evidence supports that the collector
was outside the ordinary Mininet host-to-host link path by design; it does not
prove that every frame on its socket came from the one intended mirror
selection.

## 9. Comparison with the prior 54-byte TCP validation

The earlier single TCP experiment is recorded separately in
`docs/research/stage7-packet-truncation-validation.md` and its own artifact
directory. That experiment recorded an OVSDB row and used:

- bridge `s1`;
- source selector `s1-eth1` (h1 ingress), not B1's requested `s1-eth2`;
- output port `s7obs0` and collector peer `s7rcv0` in `s7collector`;
- `Mirror.snaplen=54`;
- a single crafted IPv4/TCP tuple from h1 to h3, with a temporary exact
  forwarding rule;
- a measured 310-byte sender frame and 54-byte collector frame.

The B1 runner requested the same bridge, output veth names/namespace design,
and snaplen, but selected h2 ingress and ran six h1→h3 ping operations plus
reachability checks. B1's exact live Mirror row was not recorded, so the
actual B1 settings cannot be equated to the earlier OVSDB row. The earlier
test proves truncation for its one measured no-options IPv4/TCP packet under
its recorded configuration. It does not establish B1's selected-port state,
IPv6 behavior, or a universal cap.

Thus the prior TCP result did **not** test the same complete mirror selection
and traffic conditions as B1. It did test the same intended OVS snaplen
primitive and collector-veth architecture, but with a different selected
source port and different packet.

## 10. Sender count discrepancy

The scenario journal records six successful pings at approximately one-second
intervals, beginning `18:34:57.983330Z`. The sender metadata has five IPv4
ICMP echo-request records, beginning `18:34:58.985886Z` and continuing at
roughly one-second intervals through `18:35:02.994746Z`. The five sender
records line up with journal operations 2–6; no sender record is present at
the timestamp of operation 1.

The runner starts the sender monitor subprocess and immediately begins the
first ping. There is no readiness handshake confirming that the monitor has
bound its AF_PACKET socket before ping 1. A startup race is therefore a
plausible explanation for the missing first sender observation. However, no
per-ping sender correlation or monitor-start timestamp was saved, so the
precise reason is **not proven**. The journal's “success” means the ping
received a reply; it is not a sender-side packet capture count.

## 11. Root-cause classification

**Root cause is not determinable from the preserved evidence.**

Two independent inconsistencies need explanation before packet observation
can be trusted:

1. OVS documentation and the B1 command describe a 54-byte mirror cap, while
   33 of 37 collector frames were longer. The actual B1 Mirror row and a
   second observation point at `s7obs0` were not saved, so the discrepancy
   cannot be assigned to snaplen behavior versus configuration/path mismatch.
2. The runner requested only h2 ingress selection, but two h1-origin IPv6
   multicast frames reached the collector and have near-simultaneous Ryu
   ingress-1 observations. The actual Mirror row and runtime port binding
   snapshot were not saved, so the selector leak's cause cannot be identified.

The local OVS documentation does not explain either result as a normal
IPv6-specific behavior. It would be speculation to declare a protocol
exception, an OVS snaplen defect, a port-index bug, or a second traffic source
as the cause.

## 12. B1 answers and evidentiary status

### Proven

- The runner requested `snaplen=54`, source selector port `s1-eth2`, and
  output port `s7obs0` under Mirror name `repeat-B1`.
- B1 collector metadata contains 37 IPv6 frames; 33 lengths exceed 54 bytes;
  maximum length 372 bytes.
- Two 70-byte IPv6 multicast collector records carry h1's source MAC and are
  closely time-correlated with Ryu ingress-1 observations of the same source
  and destination MAC.
- Scenario journal records six successful pings; sender metadata records
  five ICMP request frames.
- Runner source defines a dedicated collector namespace/veth and an OVS
  mirror output port; cleanup status says those temporary resources were
  absent afterward.
- No raw packet data/payload was persisted in B1 artifacts.
- No B2/B3 or scan run was performed.

### Not proven

- The exact live B1 Mirror row values, beyond the command's requested values.
- Which ports were actually selected by the live B1 row.
- That every collector frame came exclusively from the intended OVS mirror.
- Why the overlength IPv6 frames reached the collector or their payload
  contents.
- Why the first ICMP sender observation was absent.
- The outcome of after-cleanup reachability.
- IPv6 route/address isolation in B1.

### Disproved or unsafe to assume

- It is unsafe to assume every collector frame is at most 54 bytes under the
  current configuration.
- It is unsafe to assume the requested h2-only selector was the realized
  collector scope.
- It is unsafe to claim payload safety for the overlength IPv6 frames.
- It is unsafe to pool B1 with the prior single-packet TCP result; they are
  separate experiments with different selected source ports and traffic.

## 13. Minimal next investigation required

Before any future packet experiment is considered, make the configuration
auditable without changing it as part of this report: preserve a read-only
snapshot of the live `Bridge`, `Port`, `Interface`, and `Mirror` rows during
setup; preserve the `s1-eth1/2/3` interface-to-port/ofport mapping; preserve
mirror `statistics` before/after; and preserve the collector namespace's
interface/address/IPv4 and IPv6 route state. Also collect a metadata-only
source-side interface and mirror-output accounting view sufficient to
correlate packet lengths/directions without storing bytes. Any future test
must remain separately authorized; this report did not run one.

For the five-versus-six sender count, the minimum diagnostic is a monitor
readiness handshake and per-ping timestamp/correlation metadata. This is a
runner diagnosis recommendation only; no code was changed here.

## 14. Freeze decision

**Packet observation remains UNFROZEN. Detector implementation remains
BLOCKED.** B1 disproves the assumption that the current setup always delivers
frames no longer than 54 bytes, and the selected-port scope was not
independently established. The earlier single TCP test remains valid only for
its measured packet and recorded configuration; it does not override B1.

Stage 5 remains frozen. Stage 6 GraphSAGE remains deferred. FlowRecord,
mitigation, and protocol contracts are unchanged.

## 15. Read-only audit record

Inspected repository source: `scripts/run_stage7_packet_observation_repeatability.py`,
`scripts/run_stage7_tcp_truncation_validation.py`,
`networking/mininet/stage2_topology.py`,
`docs/research/stage7-packet-observation-repeatability.md`, and
`docs/research/stage7-packet-truncation-validation.md`.

Inspected B1 files:

- `run-summary.json`
- `scenario-journal.jsonl`
- `sender-metadata.json`
- `collector-metadata.json`
- `ryu.log`

Read-only commands used:

```text
ovs-vsctl --version
ovs-vswitchd --version
ovs-vsctl list-columns Mirror
ovs-vsctl show
ovs-vsctl list Mirror
ovs-vsctl list Bridge
ip netns list
ip -brief link show
ip -n s7collector -brief address show
ip -n s7collector -6 route show
ip link show s1-eth1
man -P cat ovs-vswitchd.conf.db
python read-only JSON/JSONL inspection of the preserved B1 artifacts
```

OVS version commands succeeded and identified OVS 3.6.2-1.fc44. OVSDB
inspection commands failed with `database connection failed (Permission
denied)` for `/var/run/openvswitch/db.sock`; this was not escalated. The
`ovs-vsctl list-columns Mirror` command is not supported by this ovs-vsctl
CLI and returned `unknown command`; it did not access or modify the database. The
namespace and `s1-eth1` lookups reported they did not exist at audit time,
consistent with prior cleanup, and do not describe B1's live state. The local
`ovs-vswitchd.conf.db(5)` manual was read for Mirror selection, output-port,
and snaplen semantics.

No tests were run because this was a read-only forensic audit and no
implementation changed. No network state was changed, no packets were
generated, no captures were created, and no raw packet data was created. This
document is the only file added by this audit.
