# Networking and safety

## Existing controlled environment

The networking code uses Mininet, Open vSwitch, and Ryu with OpenFlow 1.3. The documented local Ryu listener port is TCP `6653`; port `16653` was previously blocked by SELinux. Historical documentation records `pingall` with no loss. This run did not start or alter Mininet, OVS, Ryu, bridges, host interfaces, or firewall state.

Use the pinned, isolated testbed described in [Stage 2 control-plane setup](architecture/stage2-sdn-control-plane.md) and [Ryu runtime setup](architecture/ryu-runtime-setup.md). Never connect the topology to external networks. Do not run attack scenarios from a host shell or against non-test targets.

The current administrator action list is [the isolated-lab checklist](lab-admin-preflight-checklist.md).

Run the read-only host gate before considering a lab operation:

```bash
./scripts/preflight_stage7_lab.py
./scripts/preflight_stage7_lab.py --json
```

The report checks effective UID, Mininet/OVS/Ryu tool versions, OVS service status and read access,
current bridge/port inventory, host interfaces, and loopback TCP 6653 availability. A pass also
requires an explicit `--ack-isolated-lab` acknowledgment and an empty inspectable OVS bridge
inventory. That acknowledgment cannot override a failed check. The preflight is read-only: it does
not stop services, change bridges/interfaces/firewall state, or terminate processes. If OVS access
is denied, an administrator must inspect it with `sudo ovs-vsctl show`; do not start Mininet until
bridge ownership and scope are reviewed.

## Telemetry

FlowRecord v1 describes Ryu OpenFlow rule-counter snapshots. PacketIn may support ordinary L2 forwarding, but PacketIn records are not accepted as telemetry evidence for the validated rule-counter feature builder. No packet mirror/capture is enabled by the demo.

The builder rejects incomplete collection, mismatched run/epoch, resets/decreases, invalid intervals and excessive gaps. Ryu receives `SDN_STAGE2_MAX_FEATURE_GAP_SECONDS` (default `30.0` seconds) as an explicit engineering default, not a research-derived threshold; set it according to an approved collection protocol. The live source-to-feature integration has known provenance questions; review `docs/research/remaining-stages-and-gates.md` before any collection.

## Mitigation lifecycle

The existing adapter/policy/lifecycle code includes scoped actions, TTL, protected-target checks, rate limits, cookies, independent OVS verification, expiry, and rollback. `SUBMITTED` records local submission only. `CONFIRMED` requires independent observation of the expected action and selectors. A successful API/request write is not proof of enforcement. The dashboard demo exposes no mitigation operation and never changes network state.

## Runner deadlines and cleanup

`scripts/run_stage7_rule_counter_validation.py` now runs the synchronous Mininet worker in a fresh child process group. The parent enforces a configurable wall deadline (default 120 seconds), then escalates SIGINT (5 seconds), SIGTERM (3 seconds), and SIGKILL (3 seconds), each bounded. Parent SIGINT/SIGTERM is routed through that cleanup path; repeated signals are ignored during bounded cleanup. The worker's benign host command also uses an in-namespace `timeout` (5 seconds, with one-second kill-after); controller readiness is 20 seconds. Explicit subprocess calls for prerequisites, version capture, and OVS checks have finite 5-second timeouts. Cleanup verification treats `ovs-vsctl br-exists s1` exit code 2 as “bridge absent” per the [Open vSwitch command manual](https://www.openvswitch.org/support/dist-docs/ovs-vsctl.8.pdf); other nonzero results are unverifiable and fail closed. Telemetry collection and synchronous topology startup/teardown remain inside the worker and therefore cannot exceed the parent's wall deadline without escalation.

The parent rejects an existing output path and reserves a fresh directory before creating the child. Every completed or failed worker path checks process-group exit and independently checks that bridge `s1` and the controller listener on 6653 are absent. Verification failures are reported as cleanup failures, not success. The worker's `finally` attempts topology and controller cleanup; the parent watchdog handles a blocked worker. Cleanup after a SIGKILL cannot be guaranteed: if the OVS bridge remains or its absence cannot be checked, the run is reported failed and requires manual inspection. Offline supervisor tests cover the deadline/escalation and reported-cleanup paths. No live run was performed, so OS/Mininet behavior remains unverified.

The runner remains benign-only: bounded ICMP pings from h1 to h3. It does not invoke the older port-scan runner, record PacketIn as detection telemetry, enable packet mirroring, or capture packets. Ryu uses explicit port 6653. Do not treat its offline-tested watchdog as permission to collect live evidence; the research protocol and isolated testbed gates still apply.

## Live telemetry and bounded scenario collection (2026-10-28)

The CSE-CICFlowMeter offline model (77 features) remains strictly separate from the four-feature live schema. The live scorer `stage7-live-robust-anomaly` v0.1.0 uses only `stage7-live-rule-window-v1`; it is a benign-calibrated deviation scorer, not a classifier or probability model. Its threshold 4.0 is a fixed engineering setting, not selected or validated on attack data.

Read-only preflight passed with authorized inspection: Mininet 2.3.1b4, OVS 3.6.2, Ryu 4.34, OpenFlow 1.3, loopback TCP 6653 available, and an empty OVS bridge inventory. The declared fixed topology has h1/h2/h3 behind s1 and no host uplink. No host firewall, bridge, interface, or service configuration was changed.

The mixed collector now uses the actual host Python installation that imports Mininet (`/usr/bin/python3`) after bounded interpreter checks; it does not shim the missing venv dependency. It runs preflight before spawning the worker, rejects existing output directories, supervises the worker process group with a 180-second wall deadline, bounds the port-scan subprocess to 25 seconds, and verifies bridge/listener cleanup. Ryu writes both an untouched combined stream and append-only run-scoped streams so the API poller can audit and score windows while the datapath is active. The API uses actual Ryu datapath/epoch heartbeats and persists each window once by ID.

The first three verified paired collections are `experiments/stage7-telemetry/live-2026-10-28-bounded-scan-07/` through `-09/`: each includes six successful bounded benign ICMP probes and eight fixed TCP connect probes at one per second from h2 to isolated h3/10.0.0.3. Per-scenario audits passed; across these runs there were 30 benign and 43 port-scan eligible windows, with 0 rejected snapshot pairs and independently verified cleanup. An earlier `-03` raw combined stream remains audit-incomplete as originally collected because it mixes run IDs; it was not edited or relabeled. Its exact records were used only to verify the run partitioner in a temporary directory.

Dataset `experiments/stage7-live-evaluation/live-2026-10-28-initial-run-split-02/` preserves the four-feature order, per-window source IDs and hashes, scenario journal hashes, and whole-run train/validation/test assignments. The preliminary logistic candidate is `var/models/stage7-live-logistic-preliminary-03/`, SHA-256 `c9aa0edaaddaba4e89f566b2c0e430b4a183459d6ad5fe54aea335ae8e2a8669`. It was trained on two runs, threshold-selected on two validation runs with a 10% benign-FPR cap, and tested on one independent run per class. Test confusion matrix is `[[9, 1], [3, 8]]`, macro F1 0.8091, benign FPR 0.10, and port-scan FNR 0.2727. Artifact reload reproduced a held-out score. This is too few independent runs for approval; the registry marks it `TRAINED_UNAPPROVED_PRELIMINARY` and disables inference.

With the API running during collection `live-2026-10-28-integrated-score-10`, 10 benign and 10 port-scan windows were scored and persisted. One port-scan window scored 6.3022 (>4.0) and one benign window also exceeded the threshold, demonstrating a false alert. The port-scan outlier's strongest evidence was packet rate 8.451 packets/s versus benign median 1.491, robust deviation +6.3022; byte and packet deltas also exceeded their respective medians. These are observed feature deviations, not proof of attack identity. The API was restarted and the same stored window IDs remained present.

No SYN scenario, other attack family, model approval, live mitigation, or browser walkthrough was performed. The main next evidence needed is additional independent benign variation and port-scan runs, followed by a predeclared held-out protocol with enough independent test runs to assess false alerts and missed scans. Mitigation remains disabled.

## Safe validation workflow

1. Review the current protocol and run-plan gate; current live evidence collection is not cleared.
2. Confirm an isolated authorized testbed, no pre-existing bridge/listener/output path, bounded workload, and cleanup ownership.
3. Use only the benign rule-counter runner for benign collection. Keep it separate from the mixed scenario runner.
4. Preserve raw logs and manifests; audit provenance before considering feature construction.
5. Keep detector training and mitigation disabled until their independent gates pass.
6. Verify exact action and selector state and rollback absence independently if a later approved enforcement test is run.
