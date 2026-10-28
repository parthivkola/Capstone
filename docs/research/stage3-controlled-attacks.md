# Stage 3: Controlled Attack Scenarios

## Implementation status and boundary

The six planned scenarios are implemented by `networking/mininet/stage3_scenarios.py` and namespace-local agents in `networking/mininet/stage3_agents.py`. The packet encoders and bounds are in `networking/mininet/stage3_packets.py` and `networking/mininet/stage3_config.py`. No scenario traffic was run while implementing this stage. Before executing a scenario, its configuration, target, and cleanup procedure still require project supervisor review. All generated traffic is confined to the fixed local Mininet network.

The intended observation path remains:

```text
Mininet → OVS → Ryu → traffic observations
```

Stage 3 is limited to creating bounded traffic scenarios and checking that the existing network foundation observes them. It does not add ML, GraphSAGE, Random Forest, XGBoost, Isolation Forest, SHAP, GNNExplainer, FastAPI, React, PostgreSQL, JWT, hardware, or automatic mitigation. It does not evaluate research hypotheses.

## Common safety and reproducibility requirements

- Use only the documented local Mininet topology and explicitly named Mininet hosts. Never attach the topology to a physical or Internet-facing interface.
- Pin the scenario's source, destination, protocol/target, rate, duration, seed where applicable, and configuration before each run. No arbitrary target selection or unrestricted flooding.
- Use the smallest scenario-specific traffic rate and duration below. Stop at the bound or earlier if the topology/controller becomes unstable.
- Record scenario configuration and Ryu observations; do not interpret observations as attack detection or mitigation results.
- Stop the traffic process on normal completion, timeout, or error. Restore host/link state, address tables, leases, and fixture state. Verify the Mininet topology can be stopped cleanly.
- No persistence, external targets, automatic mitigation, or traffic that escapes the isolated Mininet network.
- The fixed Stage 2 topology remains h1 (client), h2 (test host), h3 (server), and s1. DHCP and DNS use transient, scenario-only fixtures bound to h3's fixed Mininet address; the Stage 2 topology/controller behavior is unchanged.

## Scenario plans

The numerical limits below are conservative hard caps in the runner and host agents. Lower `--duration` and `--rate` values may be selected. Configurable target names are restricted to each scenario's one documented Mininet target; arbitrary addresses and hosts are rejected. There is no target discovery or host/port range input.

### S3-1 — SYN flood

- **Purpose:** Produce a small, bounded burst of TCP SYN traffic to check packet/flow observation under elevated connection attempts.
- **Attacker:** h2.
- **Victim/target:** h3, TCP port 18080 only (the explicit Stage 2 test service/flow endpoint).
- **Expected traffic behavior:** Repeated connection-start packets from h2 to the one fixed destination and port; no spoofed source and no payload/application action.
- **Topology assumptions:** Existing h2–s1–h3 local path; port 18080 is reserved for this experiment and does not forward beyond Mininet.
- **Duration/rate bound:** At most 5 seconds and 10 SYN packets/second; stop at the first bound reached.
- **Observables:** Ryu flow/packet counters and timestamps, OVS flow counters, and target reachability before/after. No security classification is inferred.
- **Cleanup:** Stop sender; remove only scenario-created process/state; verify h1↔h3 baseline reachability and shut down Mininet.
- **Successful scenario:** The predeclared bounded traffic is emitted only on the h2→h3:18080 path, corresponding counters change, and all processes/topology stop cleanly.
- **Must not happen:** No spoofing, source fan-out, unbounded packet generation, service exhaustion objective, external traffic, blocking, or automatic mitigation.

### S3-2 — Port scan

- **Purpose:** Generate a fixed small set of connection probes to characterize how Ryu observes sequential destination-port activity.
- **Attacker:** h2.
- **Victim/target:** h3 only; a version-controlled allowlist of no more than 8 TCP ports must be declared before a run.
- **Expected traffic behavior:** Sequential low-rate probes from h2 to the listed h3 ports only.
- **Topology assumptions:** Existing local topology; probes remain within Mininet and no target discovery is performed.
- **Duration/rate bound:** At most 10 seconds and 1 probe/second, with no more than 8 total probes.
- **Observables:** Per-flow and per-port records/counters from OVS/Ryu and the fixed probe outcome log.
- **Cleanup:** Stop the probe process; restore any temporary listener/service configuration; verify topology shutdown.
- **Successful scenario:** Only the predeclared h3 ports are probed within the cap and the local observation records correspond to those probes.
- **Must not happen:** No subnet/range scan, host discovery, arbitrary target input, UDP/other protocols, external scanning, or automated response.

### S3-3 — ARP spoofing

- **Purpose:** Check whether bounded changes to local ARP observations are visible in the controlled topology.
- **Attacker:** h2, with a fixed Mininet MAC address.
- **Victim/target:** h1's ARP view of h3's fixed IP address `10.0.0.3` only.
- **Expected traffic behavior:** A small number of local ARP advertisements from h2 associating the fixed h3 IP with h2's Mininet MAC; no forwarding outside Mininet.
- **Topology assumptions:** Existing shared L2 broadcast domain. The run must record expected h3 IP/MAC and h2 MAC before starting.
- **Duration/rate bound:** At most 5 advertisements over at most 5 seconds.
- **Observables:** Ryu packet-in/port observations where available, OVS counters, and h1's ARP table before/during/after.
- **Cleanup:** Stop sender; flush or restore h1's affected neighbor entry; verify h1 resolves the correct h3 MAC and ping; restart affected Mininet hosts if restoration is uncertain.
- **Successful scenario:** Only the declared local ARP identity is exercised within the cap, observations are recorded, and the correct mapping is restored before the run is considered complete.
- **Must not happen:** No ARP activity on the physical LAN, no arbitrary IP/MAC claims, no persistence, no gateway impersonation, and no automatic mitigation.

### S3-4 — DHCP starvation

- **Purpose:** Observe a bounded sequence of DHCP client identity requests against a deliberately tiny isolated address pool.
- **Attacker:** h2 only.
- **Victim/target:** A scenario-specific DHCP fixture attached to h3; the fixture must bind only to the Mininet-side interface and use a pool of at most 4 addresses.
- **Expected traffic behavior:** A small number of client discovery/request exchanges to the local fixture, using at most 4 declared temporary client identities.
- **Topology assumptions:** The Stage 2 baseline has no DHCP service. The Stage 3 runner starts a transient fixture bound only to h3's `10.0.0.3` Mininet address; review the fixture and binding before executing the scenario.
- **Duration/rate bound:** At most 4 client identities, 1 discover/second, and 4 seconds total.
- **Observables:** Fixture lease/offer log, OVS counters, and Ryu flow/packet observations for DHCP traffic.
- **Cleanup:** Stop client and fixture; release leases and reset the fixture pool; verify no DHCP service is listening beyond the Mininet interface and baseline hosts remain reachable.
- **Successful scenario:** At most the fixed number of requests reach only the isolated fixture, observations are recorded, and the pool is reset.
- **Must not happen:** No real network DHCP server interaction, no broadcast beyond Mininet, no arbitrary MAC generation, no pool depletion beyond the tiny fixture, no persistence, or automatic mitigation.

### S3-5 — DNS anomaly

- **Purpose:** Produce a bounded set of unusual but valid local DNS queries to test whether DNS traffic is observable.
- **Attacker/client:** h2; h1 may be used as a fixed comparison client in a separately labeled run.
- **Victim/target:** A local DNS fixture on h3, queried by fixed address and port for names under the reserved `.test` domain.
- **Expected traffic behavior:** One syntactically valid query per second using a predeclared list of no more than 10 unusual names; the fixture must not recurse or forward upstream.
- **Topology assumptions:** The Stage 2 baseline has no DNS fixture. The Stage 3 runner starts a transient fixture bound only to h3's `10.0.0.3:53` Mininet endpoint; it has no upstream forwarding.
- **Duration/rate bound:** At most 10 seconds, 1 query/second, and 10 names total.
- **Observables:** Fixture query log, Ryu/OVS flow and packet counters, client response status, and timestamps.
- **Cleanup:** Stop fixture/client; clear scenario-local fixture logs/cache if any; verify no upstream resolver traffic and normal topology cleanup.
- **Successful scenario:** Only predeclared `.test` names reach the local fixture within bounds, observations are recorded, and no query is forwarded upstream.
- **Must not happen:** No public DNS queries, recursive forwarding, arbitrary domain list, high-rate query generation, external resolver use, persistence, or automatic mitigation.

### S3-6 — Rogue device

- **Purpose:** Observe a known, newly activated Mininet host/port as an unapproved-device scenario without connecting physical equipment.
- **Attacker/device:** Existing h2, using its fixed topology interface and MAC.
- **Victim/target:** The local s1 segment; any observation target is limited to h1/h3 and the Ryu event log.
- **Expected traffic behavior:** Bring the preconfigured h2 Mininet interface/link up and emit only a small, fixed amount of local ARP or DHCP discovery traffic. No host creation outside Mininet.
- **Topology assumptions:** The runner records the existing h2/s1 link, toggles it down then up inside Mininet, and records h2's fixed MAC and s1 port. No physical interface is involved.
- **Duration/rate bound:** Link active for at most 30 seconds; at most 1 discovery packet/second, and no more than 10 packets total.
- **Observables:** Ryu switch/port/packet observations, OVS port state, and the explicit link-up/link-down timestamps.
- **Cleanup:** Stop sender; set h2 link down, restore original state, and verify OVS port state and clean Mininet shutdown.
- **Successful scenario:** The fixed h2 port activation and bounded local packets are visible, then the port returns to its recorded initial state.
- **Must not happen:** No host attachment to the host OS/physical network, arbitrary MAC/IP configuration, persistence, scanning, flooding, or automatic quarantine/mitigation.

## Stage 3 exit evidence (to be defined before execution)

For each scenario execution, retain its reviewed configuration, a bounded-run record, observation logs, cleanup confirmation, and any deviations. Passing means only that the controlled scenario ran within its declared limits and the existing network foundation recorded the expected local observations. It does not establish detection accuracy, novelty detection, drift adaptation, explainability, mitigation safety, or Internet-scale performance.

## Exact usage

### Prerequisites and startup

Use the Fedora host with Mininet and Open vSwitch installed and active. The Ryu controller remains a separately started Stage 2 process. In terminal 1, start it with its default test rule disabled:

```bash
EVENTLET_NO_GREENDNS=yes .venv-ryu/bin/ryu-manager \
  --ofp-tcp-listen-port 6653 networking/ryu/stage2_controller.py
```

From the repository root, first inspect the selected bounded configuration without root or traffic:

```bash
.venv/bin/python -m networking.mininet.stage3_scenarios syn-flood --dry-run
```

Then run exactly one reviewed scenario in terminal 2. Mininet startup requires root; `PYTHONPATH` is set explicitly so the system Python and its Mininet package can import this repository:

```bash
sudo env PYTHONPATH="$PWD" /usr/bin/python3 \
  -m networking.mininet.stage3_scenarios syn-flood
```

Replace `syn-flood` with one of `arp-spoof`, `dhcp-starvation`, `port-scan`, `syn-flood`, `rogue-device`, or `dns-anomaly`. The runner creates only h1/h2/h3 and s1 through `networking/mininet/stage2_topology.py`; it rejects non-loopback controller settings. It starts no external interface, service, or host. The runner stops Mininet on success or failure. Stop the separately started Ryu process with Ctrl+C.

### Fixed targets and caps

| Scenario | `--target` value | Default duration/rate | Maximum duration/rate/events |
| --- | --- | --- | --- |
| `arp-spoof` | `h1` (ARP view for h3 only) | 5 s / 1 claim/s | 5 s / 1/s / 5 claims |
| `dhcp-starvation` | `h3` local fixture | 4 s / 1 identity/s | 4 s / 1/s / 4 identities |
| `port-scan` | `h3` | 8 s / 1 TCP probe/s | 10 s / 1/s / 8 ports |
| `syn-flood` | `h3:18080` | 5 s / 10 SYN/s | 5 s / 10/s / 50 SYNs |
| `rogue-device` | existing `h2` port on `s1` | 10 s / 1 ARP/s | 30 s link-up / 1/s / 10 packets |
| `dns-anomaly` | `h3` local fixture | 10 s / 1 query/s | 10 s / 1/s / 10 names |

Targets are fixed by scenario. `--target` can only explicitly repeat the matching fixed target identifier (`h1`, `h3`, or `s1`); a different host/address fails validation. For example, a smaller SYN scenario is:

```bash
sudo env PYTHONPATH="$PWD" /usr/bin/python3 \
  -m networking.mininet.stage3_scenarios syn-flood \
  --target h3 --duration 2 --rate 4
```

The port scan has a version-controlled allowlist of TCP ports `22,53,67,80,443,8080,18080,5353`. Select a subset with `--ports`; up to eight unique allowlisted ports are accepted. No UDP or range scan is available:

```bash
sudo env PYTHONPATH="$PWD" /usr/bin/python3 \
  -m networking.mininet.stage3_scenarios port-scan \
  --target h3 --duration 4 --rate 1 --ports 22,80,18080
```

All numeric settings must be positive and within the per-scenario caps. DHCP uses only four declared temporary BOOTP client identifiers and a four-address in-memory pool. DNS names are the fixed `unusual-1.test` through `unusual-10.test`; the h3 fixture binds only to `10.0.0.3:53`, returns local negative answers, and never recurses or forwards upstream. SYN uses raw bare SYN frames with fixed h2/h3 MAC/IP addresses, fixed h3 TCP port 18080, and no payload. ARP uses only h2's fixed MAC to claim h3's fixed IP to h1. Rogue-device simulation toggles the existing h2 Mininet link and sends fixed ARP discovery frames; it creates no host or physical interface.

### Logs, observations, and cleanup

Each run writes timestamped JSONL configuration, agent events, before/after OVS flow dumps and port lists, and cleanup outcomes to `experiments/stage3/runs/<timestamp>-<scenario>.jsonl`. Set `--log-file PATH` to choose another local log path. Ryu's structured observations remain in the separately managed Ryu process log; Stage 3 does not parse them into a detection result. These records describe traffic and observations only.

The runner terminates its bounded sender and fixtures in `finally` paths. DHCP leases live only in the fixture process and reset when it stops. The ARP scenario flushes h1's h3 neighbor entry and verifies h1 relearns the expected h3 MAC and can ping h3. The rogue-device scenario restores h2's link to `up`. Every scenario checks baseline h1-to-h3 reachability after the run, captures switch state, and stops the Mininet network. Failure or timeout also tears down active senders, fixtures, and topology. No OpenFlow rule is installed or modified by Stage 3.

Ordinary unit tests cover bounds, fixed targets, packet encodings, and dry-run behavior without root or Mininet. This documentation does not claim that a live scenario has been executed, that the scenarios have security effectiveness, or that any research hypothesis is supported.
