# Stage 7 Packet-Observation Repeatability Campaign

## 1. Objective and stopping rule

This campaign was intended to run three bounded benign connectivity runs and
three bounded Stage 3 port scans through the isolated OVS mirror collector,
using `Mirror.snaplen=54`. It was observation validation only; it did not
implement a detector, use RF/ML, invoke policy or mitigation, or calculate
detection metrics.

The campaign **stopped during B1**. The first collector received IPv6 frames
larger than the configured 54-byte boundary. Because this violates the required
byte bound and the IPv6 payload was not parsed, no further run was started.
There are no B2, B3, S1, S2, or S3 artifacts. The incomplete campaign is
preserved as evidence; it was not retried.

## 2. Setup

The one attempted run used Fedora, OVS 3.6.2, the isolated Stage 2 Mininet
topology, and Ryu with OpenFlow 1.3 on loopback TCP 6653. Ryu's packet-evidence
feature was disabled. A dedicated `s7collector` namespace received the OVS
mirror copy through a veth. The mirror was configured with snaplen 54 and
selected h2's switch port. That same selection was held constant for the
campaign so the required h1-to-h3 ICMP workload would not be copied to the
collector; a 54-byte copy of default ping traffic would include part of its
ICMP data. The scan workload, if reached, would originate on selected h2.

Benign B1 used the established workload: six bounded one-ping
`h1 → h3` operations, one per second. The harness also ran bounded three-ping
reachability checks before observation and with the mirror active. The run
journal records all six workload operations as successful. The harness invoked
the after-cleanup reachability check, but a runner bookkeeping defect did not
retain its return value, so that result is **not available**.

The collector's configured acceptance bounds were 32 observations per second
and 256 observations per run. It wrote parsed metadata only to JSON; the sender
monitor and scenario journal were separate metadata records. No raw frame or
payload content was serialized.

## 3. B1 observed results

Run ID: `1ff8c915-4daf-4494-a8a1-940e0180b115`.

| Measurement | B1 result |
|---|---:|
| Workload generated | 6 h1-to-h3 ping operations |
| Sender-side workload frames measured | 5; each measured 98 bytes |
| Configured mirror snaplen | 54 bytes |
| Collector frames seen / metadata accepted | 37 / 37 |
| Collector rate-limit drops | 0 |
| Collector per-run-cap drops | 0 |
| Kernel socket-drop counter | Unsupported by this collector socket; value unavailable |
| Exactly 54-byte frames | 4 |
| Frames shorter than 54 bytes | 0 |
| Frames larger than 54 bytes | **33** |
| Largest collector frame | **372 bytes** |
| Collector ethertype observations | 37 IPv6 (`0x86dd`) |
| Generated/observed scan ports | Not applicable; no scan ran |

Collector lengths ranged from 54 to 372 bytes (histogram: 54×4, 70×9, 86×2,
90×5, 110×2, 119×1, 128×1, 130×1, 143×1, 166×3, 314×2, 354×3, and 372×3).
Every copied frame in this B1 collection exceeded the requested boundary except
four. The collector did not parse IPv6 headers or transport data, so payload
visibility for these full-length IPv6 frames is **unknown**. Some destination
MACs map to IPv6 multicast groups, including the mDNS multicast MAC; identifying
the application protocol or payload from those addresses alone would be an
inference, not an observation. The oversized copies alone are sufficient to
fail the boundary requirement.

Two collector records had source MAC `02:00:00:00:00:01` (the configured h1
MAC) even though the mirror was configured to select `s1-eth2`/h2. IPv6 source
addresses were not parsed, and this run does not establish why the h1 MAC
appeared. The intended selected-port scope was therefore not independently
confirmed. There was no scan tuple in B1, so scan-tuple isolation at Ryu is not
applicable; Ryu logged ordinary PacketIn events from the testbed.

The sender monitor measured only five of the six generated ICMP request frames.
This is an additional instrumentation completeness gap; it was not retried.
Because the run stopped at the first collector-boundary failure, no scan-port
coverage or scan repeatability result exists.

## 4. Payload safety, Ryu, and forwarding

The collector artifact contains lengths, Ethernet addresses, ethertypes,
timestamps, and other parsed metadata fields. It contains no raw bytes or
payload content. No pcap/pcapng or packet dump exists. However, 33 full frames
larger than 54 bytes reached collector memory, and their IPv6 application-data
content was not decoded. Therefore payload exposure cannot be ruled out. The
campaign stopped immediately after the oversized-frame check; no later run was
started.

The only workload in B1 was h1-to-h3 ping traffic; the configuration intended
to select h2 ingress only, but the collector records included h1-source MACs,
so that scope was not confirmed. The Ryu log contains ordinary PacketIn events
from the testbed. There was no scan tuple in B1 to test against Ryu, and this run does
not establish that the oversized IPv6 mirror copies were absent from every
other controller path.

The before-observation and mirror-active reachability checks passed; otherwise
the runner would have stopped before collecting B1. The after-cleanup check was
executed but not recorded. Cleanup verification passed: bridge, mirror,
collector namespace, observation interface, and Ryu listener were absent. The
Eventlet warning `1 RLock(s) were not greened` appeared; no traceback was found.
This does not resolve the warning.

## 5. Artifacts and validation

The attempted run is preserved under
[`experiments/stage7-telemetry/packet-observation-repeatability-2026-10-09/B1`](../../experiments/stage7-telemetry/packet-observation-repeatability-2026-10-09/B1):

- `run-summary.json` (partial; cleanup verification)
- `scenario-journal.jsonl`
- `sender-metadata.json`
- `collector-metadata.json`
- `ryu.log`

There is no campaign summary because the run failed its boundary check. The
exact invocation was:

```bash
sudo env PYTHONPATH="$PWD" python3 \
  scripts/run_stage7_packet_observation_repeatability.py \
  --output-dir experiments/stage7-telemetry/packet-observation-repeatability-2026-10-09 \
  --ryu-manager .venv-ryu/bin/ryu-manager
```

The campaign runner stopped after B1 with `collector frame exceeded snaplen`;
it did not retry. Validation results are reported with the task response. The
Stage 5 raw/prepared hashes and frozen Stage 5/Stage 7 protocol hashes were
rechecked; no mismatch was found.

Post-run validation: Ruff passed; pytest passed with 203 tests and 2
privileged tests skipped; targeted mypy for this runner passed. Repository-wide
mypy still reports the previously known optional-budget error at
`networking/ryu/stage2_controller.py:373`. Integrity checks matched 24/24 raw
dataset files, 7/7 prepared files, and 6/6 frozen Stage 5/Stage 7 protocol or
reference artifacts. B1's JSON and JSONL files parsed; all eight scenario
journal records carried the same run ID. No pcap file or test payload marker
was found. Process CPU/RSS deltas and OVS mirror/drop counters were not captured
for B1, so no resource-overhead result is available.

## 6. Limitations and decision

This is one failed benign run, not a repeatability sample. It does not establish
port-scan coverage, TCP-header repeatability, statistical reliability, or
detector effectiveness. The collector did not decode IPv6, so the type and
content of oversized IPv6 frames remain unknown. Sender-side measurement missed
one generated ping. The post-cleanup reachability outcome was not retained.

**Decision C — repeatability and payload safety cannot be trusted with the
current mirror configuration.** Although the prior single TCP test received
exactly 54 bytes, this run received 33 of 37 frames above 54 bytes, including
frames up to 372 bytes. Do not proceed to the repeatability campaign or a
detector-input freeze until the reason OVS delivered oversized mirror copies is
understood and the collector-boundary limit is independently revalidated. No
scan runs were performed in this campaign.
