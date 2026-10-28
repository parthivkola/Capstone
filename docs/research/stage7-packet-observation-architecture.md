# Stage 7 Packet-Observation Architecture Investigation

## 1. Problem statement

The live SDN telemetry path needs protocol evidence for future, separately
designed detection research. It does not need application payloads. The current
bounded OpenFlow packet-copy experiment observed all eight generated port-scan
destination ports in one run, but its controller action requested
`CONTROLLER:54` while OVS 3.6.2 delivered the full packet to Ryu. The mechanism
is therefore not frozen and must not be expanded as though the requested value
were a byte-exposure limit.

This investigation is read-only. It changes no network configuration, installs
no packages, runs no packet-evidence experiment, and creates no packet capture.
The goal is to choose a conservative architecture for a later, isolated
validation. **Telemetry is evidence collection, not attack classification.**

### Evidence labels used here

- **VERIFIED FROM REPOSITORY / LOCAL DOCUMENTATION** means directly present in
  inspected code, artifacts, installed versions, or local man pages.
- **DESIGN INFERENCE** means an architectural implication of those facts, not
  an experimentally demonstrated property.
- **REQUIRES FUTURE VALIDATION** means the property must be demonstrated on the
  exact Fedora/OVS/Mininet/Ryu setup before the mechanism is trusted.

## 2. Why the current PacketIn packet-copy approach was rejected

**VERIFIED FROM LOCAL DOCUMENTATION:** the installed host has OVS 3.6.2. Its
`ovs-actions(7)` states that the `max_len` argument to a `controller` action has
no effect on OVS 2.7 and later: the full packet is sent to the controller. The
prior run observed 74 bytes in Ryu after asking for 54. Ryu's PacketIn `data`
is the delivered Ethernet frame, not an application-level, safely truncated
header view. The prior artifact did not persist the raw bytes or payload, but
that does not prevent full packet bytes from reaching the controller process.

The existing Ryu table-miss path also uses `OFPCML_NO_BUFFER`, which is not a
payload-truncation policy. PacketIn is selected by switch behavior and is not a
complete view of packets that OVS forwards after learning. In the earlier
validated generic-telemetry scan, only one of eight probe destination ports
appeared in PacketIn. The separate bounded-copy experiment saw all eight in a
single run, but the byte-exposure caveat prevents treating that mechanism as a
safe, frozen detector-input source.

**CONCLUSION:** do not rely on `CONTROLLER:max_len` as a truncation guarantee on
this OVS release. Continue to keep the current packet-evidence feature disabled
by default. Do not send selected packet copies directly to Ryu unless a future
mechanism independently demonstrates a strict pre-parser byte bound.

## 3. Candidate architectures

### A. OVS port mirroring / SPAN to a dedicated observation interface

OVS can mirror selected ingress/egress traffic to a mirror destination. Local
`ovs-vswitchd.conf.db(5)` documents `Mirror.snaplen` as the maximum number of
bytes per packet to mirror, with a schema range of 14–65,535 bytes. OVS's
`ovs-actions(7)` separately documents `output(port=..., max_len=...)` as
truncating a packet for that single output action, while later pipeline actions
continue to see the complete packet. These mechanisms target an output port,
not the OpenFlow controller port.

- **VERIFIED:** this installed OVS schema has a `snaplen` column; local docs
  describe its maximum-per-mirrored-packet meaning. OVS supports port mirroring.
- **DESIGN INFERENCE:** a dedicated mirror destination separates observation
  traffic from the OpenFlow control channel and can preserve ordinary forwarding
  while adding mirror-copy load.
- **REQUIRES FUTURE VALIDATION:** whether `snaplen` is honored by the exact
  userspace/datapath configuration used by Mininet, the exact delivered frame
  length at a receiving endpoint, packet transformation/order, and forwarding
  behavior under mirror load. A schema entry alone does not prove datapath
  behavior.

### B. Dedicated collector interface/namespace receiving mirrored traffic

This is candidate A with a stronger host boundary. A dedicated OVS mirror
destination connects to a veth/interface whose receiving end is placed in a
collector network namespace. The collector would have no IP address, route, or
connection to the control network; it would parse a bounded set of headers and
emit only typed metadata to the experiment recorder.

- **VERIFIED:** Linux network namespaces and veth interfaces are available as
  standard kernel/networking mechanisms; the current Mininet topology is a
  local isolated three-host star. The existing `/usr/bin/ip` utility is
  present. OVS's mirror schema can reserve an output port exclusively for
  mirrored traffic; frames received on that port are discarded.
- **DESIGN INFERENCE:** a namespace with no route and a receive-only mirror
  port reduces accidental access to the SDN control interface and makes
  payload persistence independently avoidable. It does not by itself prevent
  the collector from receiving full frames.
- **REQUIRES FUTURE VALIDATION:** exact OVS mirror/veth attachment semantics,
  namespace isolation, truncation before bytes reach the collector, receive
  behavior, cleanup, bounded queue/drop accounting, and end-to-end forwarding.

### C. Kernel/eBPF packet-metadata observation

A TC/eBPF or XDP program could observe packets at an explicitly selected
interface and emit only fixed-size metadata to a bounded ring buffer. Packets
would ordinarily continue through the kernel/OVS path; Ryu would not receive
PacketIn copies from this observer.

- **DESIGN INFERENCE:** a program that parses fixed headers and exports only
  fixed-size records can avoid sending packet payloads to Ryu and can make
  event-buffer capacity/drop counters explicit.
- **VERIFIED LOCAL LIMITATION:** `bpftool`, `clang`, and `tc` were not found in
  the inspected PATH. Kernel version alone does not establish usable eBPF
  tooling, privileges, verifier support, or attachment semantics.
- **REQUIRES FUTURE VALIDATION:** toolchain/runtime availability without
  installing packages, OVS/veth hook placement, packet visibility relative to
  OVS processing, verifier safety, ring-buffer overflow accounting, kernel
  compatibility, and cleanup. This is a higher maintenance option than an OVS
  mirror and should not be selected before the simple mirror path is tested.

### D. OpenFlow PacketIn only

Packets travel through OVS and selected packets are encapsulated in
`OFPPacketIn` messages to Ryu. The current parser can decode Ethernet, ARP,
IPv4, TCP, and UDP headers from delivered `message.data`.

- **VERIFIED:** the current Ryu code serializes selected metadata rather than
  raw bytes, but packet bytes are present in memory. OVS 3.6.2 does not honor
  controller-action `max_len` as a truncation limit. Table-miss PacketIn is not
  total traffic visibility.
- **DESIGN INFERENCE:** this is not an acceptable general packet-evidence
  transport when minimizing payload exposure is a requirement. It remains
  useful for ordinary controller events when the control-plane behavior itself
  requires PacketIn, but not as a replacement for bounded packet observation.

### E. Another mechanism: OVS physical-output truncation

An explicit OpenFlow output action to an eligible physical mirror interface
with `max_len=N` is a potentially narrower alternative to controller output.
The OVS man page says truncation is scoped to that output action and later
actions process the complete packet. It also says this output truncation does
not support patch ports. This may permit an experiment without configuring a
general all-traffic mirror, but exact output-port and mirror topology choices
must be reviewed against the isolated testbed.

- **VERIFIED FROM LOCAL DOCUMENTATION:** documented truncation behavior and
  patch-port limitation.
- **DESIGN INFERENCE:** output-port truncation before a dedicated collector
  could bound bytes delivered to the observation endpoint without truncating
  the original forwarding copy.
- **REQUIRES FUTURE VALIDATION:** parsing the OpenFlow 1.3 rule on OVS 3.6.2,
  exact truncation at the collector, interaction with mirror configuration,
  forwarding preservation, rule scope, and cleanup. Do not substitute
  `output:CONTROLLER` for a physical output; the local OVS parser previously
  rejected controller-port truncation.

## 4. Comparison table

| Candidate | Packet path and payload exposure | Isolation and forwarding | Scenario evidence / metadata-only potential | Bounds, failures, realism, validation |
|---|---|---|---|---|
| **A. OVS SPAN/mirror to interface** | Selected copies leave OVS through a mirror destination. Without effective snap length, full frames including payload may reach that interface; Ryu need not receive them. | Separate from control socket, but not isolated from host by interface alone. OVS docs say mirrored copies are additional to normal delivery; mirror resource pressure can still affect the datapath. | Can expose Ethernet/IP/TCP/UDP/ARP and, for selected DHCP/DNS traffic, protocol headers and selected application-protocol fields if a parser receives enough bytes. Metadata-only retention is an observer property, not an OVS property. | Bound selectors to ports/VLAN/filter, mirror snaplen if verified, collector rate/window/storage. Failures: mirror misselection, truncation not applied, overload/drop, stale mirror. Realistic on OVS 3.6.2; exact path needs experiment. |
| **B. Mirror to isolated namespace collector** | Same mirrored copy, received on dedicated veth/interface in namespace. Payload can still reach collector unless truncation is verified before receipt. | Strongest candidate separation: no IP/routes and no Ryu control socket in collector namespace. Original switch forwarding is expected to continue, with added mirror work. | Same potential header evidence as A; parser emits only fixed metadata. DNS/DHCP application headers require bounded protocol parsing and adequate snap length. | Can bound OVS scope, snaplen/output truncation, collector rate, ring/queue, run duration, record count/storage. Drops must be counted and coverage marked incomplete. Failures include namespace escape/misconfiguration, full-frame delivery, collector loss, OVS overload, cleanup leak. Realistic but unvalidated. |
| **C. eBPF/TC/XDP metadata observer** | Kernel hook sees packets at chosen interface; fixed metadata records go to userspace; no packet copy need reach Ryu. Depending on hook, packet remains on normal path. | Can isolate reader process and collector socket; forwarding likely preserved but verifier/program errors and hook placement can affect observations. | Protocol-header fields directly parseable where headers are present; DNS/DHCP fields need bounded parsing. | Scope by interface/filter, event rate, ring-buffer capacity, run duration/storage. Ring loss must be explicit. Toolchain absent in PATH; highest operational/maintenance cost and hook semantics unverified. |
| **D. PacketIn only** | Selected frame bytes travel on the OpenFlow control channel to Ryu. On OVS 3.6.2 controller `max_len` does not cap them. | No separate collector isolation; PacketIn processing shares Ryu control plane. Forwarding/coverage depends on rules and learning; PacketIn can miss learned traffic. | Existing parser sees common L2/L3/L4 headers for delivered packets, but not all traffic; application-level DHCP/DNS fields are not currently parsed. | Scope/rate can be constrained by rules and code, but there is no trustworthy max_len byte bound here. Controller load and coverage are coupled. Not recommended for selected packet evidence. |
| **E. Physical output with `max_len`** | Explicit additional output to a physical collector port; local OVS docs state only that output copy is truncated and later actions retain full packet. Payload after the cap should not travel to that port if the local implementation matches docs. | Can preserve the full original packet's later output action; separate collector interface/namespace still needed. | Header subset depends on cap and encapsulation; can support fixed headers and selected protocol metadata if the cap includes them. | Bound by exact match, port, max_len, rate/window/storage. Failures: parser/port unsupported, wrong action ordering, output type not eligible, implementation differs. Best initial byte-bound mechanism to validate. |

The candidates are not mutually exclusive: the recommended design uses a
dedicated namespace collector (B) and validates OVS's physical mirror/output
truncation (A/E) before relying on it.

## 5. Six-scenario evidence matrix

Status terms: **AVAILABLE** means the named information is present in the
current implementation for the specific event source; **PARTIAL** means it is
available only for selected PacketIns or controlled fixtures; **UNAVAILABLE**
means the live telemetry contract/path does not currently expose it. Scenario
journal data is context, not packet-derived evidence.

| Scenario | Scenario actually generates (verified) | Current controller/telemetry evidence | Minimum useful future evidence | Source and evidence class | Could support future result? |
|---|---|---|---|---|---|
| **ARP spoofing** | Bounded crafted ARP replies claiming h3's IP from h2 toward h1. | Ethernet/ARP sender and target fields are **PARTIAL**: parser can expose them only when the packet reaches Ryu. Authoritative IP→MAC binding/inventory is **UNAVAILABLE**. | Source MAC, ARP sender IP/MAC, target context, ingress port, timestamp; separately versioned trusted binding context. | Header fields direct when received; binding conflict derived from observations plus trusted inventory; scenario ID contextual. | Potentially, for a controlled binding-conflict question. A conflict is evidence, not itself an attack label. |
| **DHCP starvation** | Bounded DISCOVER/REQUEST activity using declared client MAC identities against a local DHCP fixture; fixture sees its own messages. | Ethernet/IP/UDP headers are **PARTIAL** on PacketIn. DHCP message type, client identifier, transaction ID, lease/pool pressure are **UNAVAILABLE** in the telemetry parser. Fixture state is separate. | Bounded DHCP header/options parser for message type, client MAC/identifier and xid; separate pool/lease fixture state if the question requires exhaustion. | Packet fields direct when received; unique-client/rate/lease pressure derived; run metadata contextual. | Potentially for the controlled fixture only if packet visibility and pool state are independently recorded. |
| **Port scan** | Eight bounded TCP connection probes from h2 to h3 on a fixed port set. | TCP tuple is **PARTIAL** in ordinary PacketIn. Prior generic collection showed only one of eight destination ports. Rule counters are aggregate rule-level counters. The prior copy experiment observed 8/8 once, but was unfrozen due full packet delivery risk. | Source identity, destination IP/port, protocol, per-observation time, explicit coverage/drop counters over a bounded window. | Tuple/timestamp direct for observed frames; unique-port count derived; scenario port list contextual. | Yes, as evidence of destination diversity if observation coverage is measured. No claim of detection follows. |
| **SYN flooding** | Up to 50 bare TCP SYN frames at bounded rate to h3:18080. | TCP tuple/bits are **PARTIAL** for delivered PacketIns. Complete packet visibility, bidirectional handshake, and per-packet counts are **UNAVAILABLE**. | Tuple, SYN/ACK/RST bits, timestamp, bounded counts/rates, coverage/drop accounting; handshake state only if both directions are visible and explicitly tracked. | Header bits direct per received frame; rates/state derived and incomplete under loss. | Potentially for a controlled SYN-rate evidence question; one SYN bit is not a flood or handshake claim. |
| **Rogue-device simulation** | h2's existing link is toggled and its existing preconfigured MAC sends ARP requests. It is not a newly attached unauthorized device. | Source MAC/ingress port are **PARTIAL** on PacketIn; port descriptions/status are **AVAILABLE** as switch state snapshots, but port status events are not currently a complete inventory feed. Approved MAC/device inventory is **UNAVAILABLE**. | Timestamped MAC→ingress-port observation, port/link event, separately versioned approved device/port inventory. | MAC/port direct when observed; mismatch derived against inventory; scenario journal contextual. | Could support inventory mismatch experiments; current scenario cannot establish rogue-device detection validity. |
| **DNS anomaly** | Up to ten bounded UDP/53 queries to local `.test` names; local fixture returns NXDOMAIN without external recursion. | IP/UDP endpoints are **PARTIAL**. DNS direction, transaction/query metadata and response code are **UNAVAILABLE** in current telemetry. Fixture journal separately records test behavior. | Bounded DNS header/question parser: query/response bit, transaction ID, question name/type, RCODE, endpoint/port and timestamp; payload discarded immediately after parsing. | DNS fields direct only when the relevant frame reaches observer; rates/distributions derived; fixture context separate. | Potentially for controlled DNS-query behavior if coverage and fixture context are recorded; no claim about general DNS anomalies. |

Across all scenarios, absence of a PacketIn is not evidence that a packet did
not exist. A future observation contract must report visibility policy and
drops/coverage alongside observations.

## 6. Payload-exposure analysis

| Candidate | Can payload reach Ryu? | Can payload reach some collector? | Safe metadata-only outcome |
|---|---|---|---|
| PacketIn | **Yes.** OVS 3.6.2 controller `max_len` does not reliably truncate. | Not applicable; Ryu is the recipient. | Ryu can choose not to persist bytes, as the current serializer does, but this is not transport minimization. |
| SPAN/mirror without verified snaplen | No, unless also sent to controller by another rule. | **Yes, full frame may reach mirror endpoint.** | Collector parser can discard payload, but exposure already occurred at its interface. |
| Mirror/output truncation plus isolated collector | No packet copy needs to go to Ryu. | Intended to receive only capped bytes; **must be empirically verified** on OVS 3.6.2. | Parse only required fixed headers/options, emit explicit metadata fields, immediately discard frame bytes; persist no raw packet or payload. |
| eBPF metadata export | No packet copy needs to go to Ryu. | Kernel hook necessarily accesses packet memory; exported event can contain only metadata. | Fixed-size event schema and bounded ring; code review and tests must ensure no packet buffer is exported or serialized. |

No architecture can claim “payload never existed in memory”: packet forwarding
and parsing inherently process bytes. The relevant proposed guarantee is narrower:
payload bytes do not traverse the Ryu control channel and are not delivered to
or persisted by the observation collector beyond a verified header cap.

For DNS/DHCP, some protocol fields are carried after transport headers. A
future design must declare the exact maximum parse depth needed and retain only
the resulting fields; it must not retain the whole application payload merely
because parsing is convenient. If the header cap cannot contain the required
metadata for a particular packet, record the observation as incomplete rather
than increasing the cap silently.

## 7. Isolation analysis

**Recommended boundary (design inference):** OVS mirror/physical output →
dedicated veth → collector network namespace → metadata-only parser/recorder.
The collector namespace should have no address, default route, or control-plane
socket; only the receive interface is present. Ryu remains on the existing
loopback OpenFlow control connection and receives no selected packet copies.

This separates the collector process from the Ryu control-plane network path,
but does not by itself constrain which frames reach the collector. The OVS
mirror selection and pre-delivery truncation are essential. The namespace does
not protect against a full packet being delivered to it, collector compromise,
host-kernel defects, or an overly broad OVS mirror rule.

**REQUIRES FUTURE VALIDATION:** verify namespace addresses/routes, interface
membership, OVS port role, no path from collector namespace to Ryu control
socket, exact mirrored bytes, and full cleanup. Do not attach a physical
production NIC or external bridge; use only the isolated Mininet bridge.

## 8. Coverage and boundedness

The future experiment should apply bounds at independent layers:

1. **Scope:** explicit isolated bridge and selected Mininet ingress/egress
   ports; protocol and tuple selectors only where required by the declared
   experiment. Avoid `select_all` for the first validation.
2. **Bytes:** set an explicit mirror snap length or per-output maximum, then
   verify received frame lengths at the collector. The configured value alone
   is not evidence of a cap.
3. **Time:** activate only inside explicit run boundaries; remove mirror/rules
   and deactivate context before Mininet teardown.
4. **Rate:** deterministic per-source or global event budget with accepted,
   rate-dropped, malformed, and overflow counters. A drop makes coverage
   incomplete; it must not be interpreted as no traffic.
5. **Memory:** fixed-size event records and bounded queue/ring, with explicit
   overflow count and no unbounded per-flow state.
6. **Storage:** metadata-only JSONL, maximum records/file size per run, append
   errors surfaced as run failure, and no pcap/raw-frame fallback.
7. **Coverage accounting:** compare controlled generated event identifiers or
   probe tuples with observed tuples only for instrumentation coverage. Keep
   scenario journal and telemetry separate; do not feed scenario truth into a
   later detector feature set.

For SPAN, OVS mirror counters can help establish packets/bytes transmitted to
the mirror, but are not a substitute for collector receive counts or packet
identity. For eBPF, ring-buffer lost-event counters are required. For every
candidate, distinguish “not selected,” “selected but dropped,” “malformed,”
and “observed and parsed” where the implementation can establish those states.

## 9. Forwarding and control-plane impact

OVS's local documentation describes mirror traffic as an additional mirrored
copy, and describes per-output `max_len` truncation as scoped to that one
output while later actions retain the full packet. These are documented
semantics, not a test result for this project topology. Mirroring consumes
datapath and host resources; a slow collector can drop observations or affect
resource pressure even when forwarding rules remain logically intact.

The proposed collector avoids sending evidence over Ryu's OpenFlow TCP channel
and avoids per-packet controller parsing. It does not prove zero forwarding
impact. A future validation must compare target and unrelated connectivity
with the observer disabled/enabled, inspect exact OVS rules and counters, bound
traffic, record collector loss, and clean up mirror configuration. No attack
scenario or packet-copy experiment was run as part of this design audit.

## 10. Failure modes

- OVS accepts a `snaplen`/output cap in configuration but the active datapath
  delivers more bytes than expected.
- Mirror selectors are broader than intended or select both ingress and
  egress, duplicating observations.
- A mirror output port is misconfigured, receives ordinary traffic, or is
  inadvertently connected to an external network.
- Collector namespace has an address/route or can reach the Ryu listener.
- Mirror/collector overload silently drops packets or blocks the reader; the
  pipeline fails to report loss.
- Collector parser reads beyond the declared cap, accepts malformed/truncated
  headers as complete, or accidentally serializes raw bytes.
- DNS/DHCP metadata requires more bytes than the configured safe cap.
- Rule/mirror state survives teardown and affects subsequent runs.
- Eventlet/Ryu concurrency warning remains unresolved; this proposal reduces
  selected packet processing in Ryu but does not establish Eventlet safety.
- eBPF hook is attached at the wrong side of OVS, sees a different packet set,
  or loses events through ring-buffer pressure.

Fail closed for the research collector: if truncation, scope, loss accounting,
or cleanup cannot be verified, stop collection and mark the artifact
incomplete. Do not fall back to Ryu PacketIn with full frames.

## 11. Recommended architecture

**DESIGN RECOMMENDATION:** validate **B + E** first: a dedicated observation
interface in an isolated collector namespace, receiving only narrowly selected
OVS mirror/physical-output copies with a documented truncation mechanism. Use
OVS `Mirror.snaplen` only if the controlled experiment proves it is effective
for this exact datapath; otherwise evaluate the documented physical-port
`output(port=..., max_len=...)` action in an isolated test bridge. Neither is
trusted based solely on configuration or man-page semantics.

The collector should parse only the minimum per-scenario metadata, produce the
existing `TelemetryObservation`-compatible evidence records with source,
timestamp, datapath/port, and run ID, and expose coverage/loss counts. It should
not emit labels, confidence, `DetectionResult`, risk, or actions. It should not
invoke Ryu mitigation code. FlowRecord and ObservationWindow retain their
existing OpenFlow rule-stat semantics.

This recommendation is conservative because it separates packet bytes from
the SDN control channel and permits an independently verified byte boundary.
It is not a declaration that the proposed truncation is already effective.

### Why the alternatives are not selected as the first path

- **A alone (SPAN to a host interface):** plausible, but does not isolate the
  receiver or prove truncation. A dedicated namespace improves the boundary.
- **C (eBPF):** potentially strong metadata-only architecture, but the local
  toolchain is absent from PATH and attachment/coverage semantics are
  unverified. It adds kernel-program and operational complexity before a
  simpler OVS-native path has been tested.
- **D (PacketIn only):** rejected for selected packet evidence because OVS
  3.6.2 ignores controller-action `max_len`, full packet bytes can reach Ryu,
  and PacketIn is incomplete traffic visibility.
- **OpenFlow output truncation without namespace:** the byte cap may be useful,
  but a dedicated namespace provides clearer receiver isolation and explicit
  cleanup boundaries.
- **No justified candidate:** not necessary yet because installed OVS
  documentation/schema expose a plausible mirror/output truncation path. Its
  critical property remains unverified, so the decision is a testable design,
  not a freeze.

## 12. Minimal future experiment required

Before any repeatability or detector-input collection, run one bounded,
non-production validation in the isolated Mininet topology, with no Ryu
PacketIn-copy action and no mitigation:

1. Record OVS/Ryu/Mininet/kernel versions and baseline bridge/flow state.
2. Create a dedicated veth mirror destination and receive endpoint in a new
   collector namespace with no IP address or routes; verify it cannot connect
   to the Ryu OpenFlow listener.
3. Select only a fixed h2→h3 test tuple on the isolated bridge. Test either
   `Mirror.snaplen` or physical `output(..., max_len=N)` as a single declared
   mechanism; do not combine mechanisms in a way that obscures which one
   truncates.
4. Send a small, bounded set of test frames whose header/payload boundary is
   known. A temporary in-memory sentinel may verify that bytes beyond the
   declared cap do not arrive, but do not write packet bytes or pcaps to disk.
5. At the collector, record only received length and parsed metadata; verify
   actual length never exceeds the declared bound and that no raw bytes enter
   JSONL.
6. Verify target and unrelated forwarding before/during/after observation,
   compare OVS mirror/output counters with collector receive/drop counters, and
   ensure truncation does not alter the original forwarding copy.
7. Exercise malformed/truncated headers and queue/rate limits at the planned
   bounded level; verify all loss is surfaced and record provenance is intact.
8. Remove mirror/rules/interfaces and namespace in `finally`; independently
   inspect OVS state, connectivity, controller listeners, and namespace state.
9. Only after that passes, collect repeated benign and port-scan telemetry
   runs, keeping scenario journals separate and comparing generated/observed
   tuples solely for coverage.

This is a future validation plan, not an experiment performed in this task.
The Eventlet warning also remains a concern without a demonstrated correctness
failure; this experiment should record whether it appears and keep the
controller out of the packet-copy path.

## 13. Freeze/unfreeze decision

**DECISION: KEEP PACKET-EVIDENCE INSTRUMENTATION UNFROZEN.** The direct
controller-copy mechanism is unsuitable as a bounded-byte path on OVS 3.6.2.
The local OVS schema and documentation make a separate, truncated mirror/output
collector plausible, but this project's actual delivery boundary, isolation,
forwarding preservation, and loss accounting have not been tested. The
recommendation is therefore B+E as the next narrowly scoped engineering
validation, not authorization to collect new research data or to implement a
detector.

### What remains unverified

- OVS 3.6.2 datapath actually enforces `Mirror.snaplen` or physical-output
  `max_len` as documented in this Mininet topology.
- Collector receives no bytes beyond the configured maximum.
- Namespace isolation and no-route/no-control-plane properties hold at
  runtime.
- Forwarding is preserved and mirror load is acceptable.
- Collector/parser bounds, queue loss, JSONL behavior, and cleanup are reliable.
- The Eventlet RLock warning has no effect under relevant concurrency; current
  evidence neither demonstrates a correctness failure nor proves safety.
- Repeated benign/scan coverage is consistent across runs.

## 14. Read-only inspection record

Inspected repository sources and artifacts included:

- `src/sdn_defense/telemetry.py`
- `src/sdn_defense/flow_records.py`
- `networking/ryu/stage2_controller.py`
- `networking/ryu/structured_events.py`
- `networking/ryu/config.py`
- `networking/mininet/stage2_topology.py`
- `networking/mininet/config.py`
- `networking/mininet/stage3_config.py`
- `networking/mininet/stage3_agents.py`
- `networking/mininet/stage3_scenarios.py`
- `docs/research/stage7-attack-observability-audit.md`
- `docs/research/stage7-packet-evidence-instrumentation.md`
- `docs/architecture/stage7-live-observation-telemetry.md`
- `experiments/stage7-telemetry/packet-evidence-2026-10-08-03/`
- local `/usr/share/openvswitch/vswitch.ovsschema`
- local `ovs-actions(7)` and `ovs-vswitchd.conf.db(5)` documentation

Read-only commands included `sed`, `rg`, `command -v`, `ovs-vsctl --version`,
`ovs-ofctl --version`, `uname -r`, and `man ... | col -b`. No network
configuration was changed, no package was installed, no packet capture was
created, and no traffic or attack scenario was run. Tests were not run: this
task changed only a design document and made no implementation change.

External primary references:

- [Open vSwitch actions reference](https://docs.openvswitch.org/en/stable/ref/ovs-actions.7/)
- [Open vSwitch database configuration reference](https://docs.openvswitch.org/en/stable/ref/ovs-vswitchd.conf.db.5/)
- [Open vSwitch `ovs-tcpdump` reference](https://docs.openvswitch.org/en/stable/ref/ovs-tcpdump.8/) (considered, but the utility is not installed and is not needed for the proposed isolated collector)
