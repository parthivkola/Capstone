# Stage 7I.3 — Proposed Rule-Counter-Only Live Lineage Validation

**Current status (2026-10-21): offline prerequisites implemented; live
validation remains unexecuted and requires separate approval.** The original
status below is retained as the historical plan baseline and is superseded by
the dated offline implementation update near the end of this document.

**Historical baseline:** implementation audit required before approval; not
executed or authorized. At that point the repository did not provide a safe,
executable rule-counter-only command path. The existing telemetry
runner always executes a port-scan run, does not explicitly pass Ryu's
OpenFlow listen-port argument, and records ordinary PacketIn metadata even
when packet-copy mode is disabled. It must not be used for this proposed
scope. There is also no command-line source-pair audit or cadence/gap
analyzer. This plan defines the minimum gaps to close; it does not authorize
feature training, inference, detection, policy, or mitigation.

## Review basis

The source review covered `networking/ryu/stage2_controller.py`,
`src/sdn_defense/telemetry_io.py`, `src/sdn_defense/telemetry.py`,
`src/sdn_defense/live_provenance.py`, the live-feature and telemetry unit
tests, the frozen Stage 7 protocol/reference documents, and the Stage 7I
research documents. Tests use synthetic events; the controller has not been
started for this review.

Ryu observes connection state in `datapath_state_change_handler` and creates
an epoch from the datapath object identity, controller-instance nonce, and
controller-local sequence. `switch_features_handler` observes the same
connection again; the tracker treats the same object as idempotent. Each flow
statistics request receives an XID from the datapath, captures the current
run ID, starts multipart state before `send_msg`, and records a schema-2
request. Reply handling looks up the epoch using the reply's exact datapath
object, then joins by datapath ID, XID, and epoch. Only the final multipart
reply produces a completed collection and snapshots. Timeout, disconnect,
replacement, shutdown, and run-change paths emit incomplete/cancelled
records. An unidentified disconnect invalidates every active epoch and
pending collection.

These are source-code facts. Whether deployed Ryu emits these callbacks in
this order with stable datapath object identity, and whether the JSONL stream
contains the expected records under real collection timing, remains untested.

## Plan-to-implementation audit

| Plan step | Repository implementation / entry point | Status and limitation |
|---|---|---|
| Isolated three-host topology | `networking/mininet/stage2_topology.py`: `Stage2Topology.build()` creates `s1` with `OpenFlow13`, h1/h2/h3; `create_network()` starts it against loopback controller config. | **IMPLEMENTED BUT NOT VERIFIED LIVE for this task.** `create_network()` starts the network; it is not a read-only preflight. The module CLI starts an interactive Mininet CLI and is not a bounded telemetry runner. |
| Controller connection epochs | `networking/ryu/stage2_controller.py`: `datapath_state_change_handler()`, `switch_features_handler()`, `_observe_datapath_connection()`, `_write_connection_epoch_boundary()`. | **IMPLEMENTED BUT NOT VERIFIED LIVE.** Connection object identity and callbacks need a real Ryu event-lineage run. |
| Request/XID and multipart completion | `stage2_controller.py`: `_request_flow_statistics()`, `flow_statistics_reply_handler()`, `_monitor()`; assembler in `src/sdn_defense/telemetry_io.py`. | **IMPLEMENTED BUT NOT VERIFIED LIVE.** Assembler uses a 5-second default timeout and numerically increasing XIDs per epoch. XID wrap/reuse is not verified. `FlowStatsCollection` holds monotonic start/end values, but the request record omits start monotonic time and the completion record omits completion monotonic ns (it stores UTC and elapsed seconds). |
| Snapshot construction and counter windows | `stage2_controller.py`: completed reply path and `_process_complete_collection()`; `telemetry.py`: `flow_snapshot_from_observation()` and `CounterDeltaEngine`. | **IMPLEMENTED BUT NOT VERIFIED LIVE.** Ryu's counter engine has a 30-second runtime gap setting; this is not an approved live-feature maximum gap. |
| Run metadata/context | `networking/mininet/stage3_scenarios.py`: `_write_experiment_context()`; Stage 2 controller `_current_run_id()`. | **PARTIALLY IMPLEMENTED.** Context is read at controller boundaries/request/completion, not through atomic subscription. Existing telemetry runner brackets each workload, but has no benign-only mode. |
| Packet observation disabled | `SDN_STAGE2_PACKET_EVIDENCE_ENABLED=false` disables the optional packet-copy flow rules in `networking/ryu/config.py`. | **UNSAFE OR AMBIGUOUS FOR “RULE-COUNTER-ONLY”.** `switch_features_handler()` installs a table-miss rule that sends packets to Ryu, and `packet_in_handler()` parses and records ordinary PacketIn metadata even when packet-copy mode is false. Suppressing `telemetry_observation` writes would keep packet-derived records out of the dataset, but would not isolate packet bytes from Ryu. A later approval must explicitly decide whether ordinary control-plane PacketIns may occur but be excluded from evidence, or require a different forwarding setup. Do not assume either interpretation. |
| Safe benign-only orchestration | `scripts/run_stage7_telemetry_collection.py`: `run()` invokes `_run_benign()` and then unconditionally `_run_port_scan()`. | **UNSAFE OR AMBIGUOUS.** No benign-only CLI option exists. Do not run this script for the proposed validation. A narrowly scoped runner mode/script is required. |
| Ryu listen port | Existing Stage 2 validator `networking/ryu/validate_stage2.py` explicitly passes `--ofp-tcp-listen-port <port>`. `scripts/run_stage7_telemetry_collection.py` launches `ryu-manager networking.ryu.stage2_controller` without that argument, then probes port 6653. | **PARTIALLY IMPLEMENTED.** Future runner must pass the selected port explicitly (6653 only after current environment/config is confirmed); a readiness probe alone does not set the listener port. |
| JSONL schema validation | `validate_telemetry_jsonl()` in `src/sdn_defense/telemetry_io.py`; invoked by the existing runner after collection. | **IMPLEMENTED AND TRACEABLE.** It checks record schemas, timestamps, run boundaries, and source-record references. It accepts historical schema 1 for compatibility and is not a full multipart lifecycle audit. |
| Source-verified feature-pair audit | `audit_snapshot_pair_provenance()` in `src/sdn_defense/live_provenance.py`; builder method `RuleCounterFeatureBuilder.build_source_verified()`. | **PARTIALLY IMPLEMENTED.** Pure API only. No script reads telemetry JSONL into `SnapshotPair` objects and emits a provenance audit report. The general validator does not invoke this audit. |
| Cadence/gap analysis | No repository entry point found. Snapshot records contain `collector_monotonic_ns`; completion records contain UTC times and computed `elapsed_seconds`. | **PARTIALLY IMPLEMENTED.** Per-rule snapshot gaps can use snapshot monotonic times when both snapshots exist. Exact monotonic request/completion cadence and empty-complete-collection timing cannot be reconstructed because request and collection terminal records omit those monotonic values. Add them before claiming precise collection cadence/latency. |
| Disconnect/reconnect live test | Stage 2 event handlers and offline epoch/assembler tests. Existing live runner has no controlled reconnect scenario. | **MISSING for deterministic live execution.** Exclude from the initial run. Keep reconnect behavior covered by synthetic tests and plan a later, separately reviewed lifecycle test. |
| Incomplete-collection live test | Assembler timeout/disconnect branches and synthetic tests exist; normal runner does not inject or orchestrate an incomplete response. | **MISSING for deterministic live execution.** Exclude from the initial run; do not stop a controller mid-collection as part of the initial cadence run. |
| Cleanup | Existing telemetry runner has `finally` cleanup for Mininet/Ryu and checks `s1` and listener removal. | **IMPLEMENTED BUT NOT SUFFICIENT FOR THIS SCOPE.** It is attached to the unsuitable combined benign-plus-scan runner. Reuse only after a benign-only orchestration path is added and reviewed. |

### Initial executability decision before offline prerequisites (2026-10-21)

The intended initial benign-only collection is **not executable safely as
written**. The existing command is explicitly unsuitable because it always
invokes `Scenario.PORT_SCAN`. Manual assembly from the controller and topology
CLIs is also not an acceptable substitute: it lacks the existing runner's
run-context lifecycle, output ownership, and cleanup/validation orchestration.
The minimum prerequisites before a separate approval request are:

1. Add an explicit benign-only mode to a controlled runner (or a separate
   small runner) that cannot dispatch attack scenarios and that passes
   `--ofp-tcp-listen-port` explicitly.
2. Resolve the PacketIn boundary explicitly. If ordinary learning-switch
   PacketIns are approved as a forwarding detail, add a config gate to
   suppress `telemetry_observation` writes and verify packet-derived records
   do not enter the dataset; document that packets still reach Ryu. If zero
   packet visibility at Ryu is required, design and separately review a
   forwarding mode that can prove it. Record suppression is not packet-path
   isolation.
3. Add an offline command-line audit that validates the recorded schema-2
   lineage and source-verifies pairs from JSONL, and a cadence/gap report
   command. Until then the Python APIs require manual object construction
   and are not reproducible command-line validation.
4. Add exact monotonic request and terminal-completion timestamps to
   schema-2 collection records, including empty complete collections, with
   focused tests and a schema-compatible versioning decision. Do not infer
   them from UTC or float elapsed seconds.
5. Make the runner refuse an existing output directory because the recorder
   appends to `telemetry.jsonl` while run journals are overwritten. Verify
   output ownership and cleanup paths in tests.
6. Review the new path's focused tests and cleanup guarantees. Do not add
   live disconnect/reconnect or incomplete-response injection to the initial
   run.

The initial approved run should therefore be limited to one fresh controller,
one isolated Stage 2 topology, a finite benign h1-to-h3 workload, normal flow
statistics collection, and orderly run/controller/topology shutdown. No
attack scenario or forced failure branch is needed to measure normal cadence.
Execution remains blocked until the PacketIn scope is resolved.

The initial collection may produce ordinary `ObservationWindow` records
through Ryu's existing `CounterDeltaEngine(maximum_gap_seconds=30.0)`. Preserve
them as raw telemetry but do not treat 30 seconds as the approved live-feature
gap policy and do not feed these records to training. The initial pass should
measure source-linked collection and per-rule snapshot gaps; source provenance
can be checked without selecting a feature-gap threshold. Actual feature-vector
eligibility remains blocked until that threshold is separately reviewed.

## Actual output schemas and correlation fields

The recorder writes JSON objects per line with `record_type` and
`schema_version`. `src/sdn_defense/telemetry_io.py` defines these current
envelope versions:

| Record type | Schema | Lineage-relevant fields |
|---|---:|---|
| `recorder_metadata` | 2 | `recorded_at`, `source_version` |
| `run_metadata` | 1 | `run_id`, metadata object |
| `run_boundary` | 1 | `run_id`, `state`, `timestamp` |
| `connection_boundary` | 2 | DPID, epoch ID, epoch sequence, controller-instance ID, state, lifecycle source, optional affected epoch IDs, run ID |
| `flow_collection` | 2 | Request: collection ID, DPID, XID, epoch, run ID, `state=requested`, start time. Completion: `complete=true`, `terminal_state=COMPLETE`, part/record counts, completion time and elapsed seconds. |
| `incomplete_collection` | 2 | Collection ID when known, DPID/XID/epoch/run when known, `complete=false`, reason, terminal state |
| `flow_snapshot` | 2 | nested `flow_record`, collection ID, epoch, run ID, UTC time, collector monotonic completion time |
| `observation_window` | 1 | nested window, source record IDs, run, interval and feature validity/reason fields |
| `telemetry_observation` | 1 | nested PacketIn/port observation; currently emitted by ordinary PacketIn handling |

The existing telemetry runner writes `telemetry.jsonl`, `ryu.log`,
`active-run-context.json`, `benign-run.jsonl`, `port-scan-run.jsonl`, and
`collection-summary.json`. These are actual names, but that runner is
unsuitable because it always runs a port scan. A future benign-only run should
use a unique new output directory and keep its scenario journal separate.
Proposed environment manifest, validator output, provenance-audit summary,
cadence/gap summary, and cleanup report have no current writers or frozen
schemas.

The existing parent runner knows the controller PID as `controller.pid`, but
does not serialize it. The controller-instance UUID appears in connection
boundary records and is the lineage identity. Run ID comes from the context
file. Collection IDs encode epoch, DPID, and XID. No current artifact ties
the process PID to the controller-instance UUID.

The run recorder path is append mode. The runner uses `mkdir(...,
exist_ok=True)`, so reusing an output directory can append new recorder lines
to stale telemetry while overwriting the run journal. A new path is required
and the future runner should fail if it already exists; a unique-name
convention alone is not a programmatic safety check.

`validate_telemetry_jsonl()` checks record shape, timestamps, run boundaries,
and window references. It accepts historical schema 1 for compatibility;
it does not validate the full request/terminal/epoch lifecycle.
`audit_snapshot_pair_provenance()` is a Python API that takes already-created
`SnapshotPair` objects and source records. No CLI currently loads a JSONL
stream into pairs or produces the requested provenance report. No cadence/gap
analysis CLI exists either.

## Exact commands: current availability and blocked runtime sequence

The following are repository-backed offline checks; none starts a network
service or generates traffic:

```bash
cd /home/parthivkola/Workspace/Projects/Capstone
.venv/bin/pytest -q tests/unit/test_live_observation_telemetry.py tests/unit/test_live_feature_builder.py
.venv/bin/ruff check networking/ryu/stage2_controller.py networking/ryu/config.py networking/mininet/stage2_topology.py src/sdn_defense/telemetry.py src/sdn_defense/telemetry_io.py src/sdn_defense/live_provenance.py src/sdn_defense/live_features.py tests/unit/test_live_observation_telemetry.py tests/unit/test_live_feature_builder.py
.venv/bin/mypy networking/ryu/stage2_controller.py networking/ryu/config.py networking/mininet/stage2_topology.py src/sdn_defense/telemetry.py src/sdn_defense/telemetry_io.py src/sdn_defense/live_provenance.py src/sdn_defense/live_features.py
```

For a later run, environment inventory commands that do not start services
are known from the repository prerequisites and environment documentation:

```bash
python3.11 --version
ovs-vsctl --version
ovs-ofctl --version
mn --version
.venv-ryu/bin/ryu-manager --version
```

These version commands do not establish that the service is active, the
controller is listening on the intended port, or the topology is isolated.
The existing `scripts/setup_ryu_stage2.sh --check` is a runtime installation
check, but it requires the pinned local Ryu checkout/venv and invokes the
Ryu manager version command; it does not start a controller or validate live
lineage.

**No safe live command sequence currently exists.** In particular, do not
run the following existing command for this task: it always runs the bounded
port scan after benign traffic, so it violates the requested benign-only
scope:

```bash
sudo env PYTHONPATH="$PWD" /usr/bin/python3 scripts/run_stage7_telemetry_collection.py --output-dir experiments/stage7-telemetry/<new-run-directory> --ryu-manager .venv-ryu/bin/ryu-manager
```

The `<new-run-directory>` is illustrative only. The command is intentionally
shown as **DO NOT RUN**. It also does not explicitly pass Ryu's
`--ofp-tcp-listen-port` option and does not suppress ordinary PacketIn
telemetry. A future command cannot be truthfully specified until the
benign-only runner, PacketIn telemetry gate, source-audit CLI, and cadence
report tool exist. Do not substitute `networking/ryu/validate_stage2.py`:
it installs its explicit test rule and runs both ping and TCP reachability
checks. Do not substitute `python -m networking.mininet.stage2_topology`:
it enters an interactive CLI and has no telemetry run lifecycle.

### Required command sequence after those prerequisites (not executable yet)

1. Offline gates: run the three repository-backed commands above plus the
   focused tests for the new runner/auditors. **No network effect.**
2. Inventory: run the version commands above; record exact outputs. Confirm
   current root/Mininet/OVS authorization and current host state using the
   separately reviewed runner preflight. **The preflight must not start the
   topology.**
3. Integrity baseline: compare frozen files listed in the recorded Stage 5
   raw/prepared and Stage 5F/Stage 7 reference manifests with their recorded
   SHA-256 values. The repository has no single verified `verify-hashes`
   command; the future run package must include the exact manifest-driven
   command or generated `sha256sum --check` input and preserve its output.
   Do not invent a manifest path or list here.
4. Controller startup: the future runner must start a fresh
   `.venv-ryu/bin/ryu-manager --ofp-tcp-listen-port 6653
   networking/ryu/stage2_controller.py` with explicit telemetry/context paths,
   test-rule installation false, packet-copy false, and PacketIn telemetry
   recording false. It must record its PID, log path, and readiness result.
   **Not currently executable as a validated sequence:** existing runner
   omits the explicit listen-port option and PacketIn telemetry gate.
5. Topology startup: the future runner must call the existing
   `create_network(TopologyConfig("127.0.0.1", 6653))` only after controller
   readiness and its own isolated-state preflight. The implementation must
   set/verify OpenFlow13 and refuse an existing `s1`. **No standalone safe
   bounded command currently wraps these checks.**
6. Benign workload and collection: the new benign-only runner may reuse the
   current bounded six `ping -c 1 -W 1 10.0.0.3` operations with one-second
   spacing and 2.5 seconds for final polls, but only after exact parameters
   are separately approved. The current `_run_benign()` writes run context
   before topology creation and sets it inactive before `network.stop()`;
   it is private to the combined unsafe runner and cannot be invoked from a
   safe CLI today.
7. Shutdown: close run context, allow pending statistics to reach terminal
   completion or timeout, stop Mininet, then gracefully stop Ryu and verify
   no test bridge and no listener remain. Use the new runner's `finally`
   path; do not manually kill processes or run the combined runner.
8. Offline validation: first run `validate_telemetry_jsonl(path)`, then the
   future source-lineage CLI and cadence/gap report command. The latter two
   commands are **missing**. Keep malformed/incomplete output and report
   failure; never repair or overwrite it.
9. Post-run integrity: rerun the exact manifest-driven hash comparison from
   step 3 and compare the source/configuration hash inventory. Command awaits
   the same hash-check packaging prerequisite.

This sequence is a requirements list, not a shell recipe: steps marked
missing/blocked are intentionally not given invented executable commands.

## Preconditions

Before a separately approved run:

1. Review and approve this exact plan and the selected run duration.
2. Confirm the repository's rule-counter-only runner and config are the
   intended versions; record source hashes or a commit when available.
3. Confirm an isolated Mininet topology, no pre-existing conflicting bridge,
   OpenFlow 1.3, and the established controller endpoint. Confirm cleanup
   ownership and that only approved local interfaces are in scope.
4. Confirm packet-evidence copy/mirror is disabled, and that detector,
   Stage 7 gateway, RiskPolicy, MitigationOrchestrator, and mitigation adapter
   are not started or imported by the collection path.
5. Confirm recorder schema 2 and the source-verification audit are enabled.
   Preserve the JSONL and controller logs as separate, append-ordered
   artifacts.
6. Record Ryu, OVS, Mininet, kernel, Python, and controller configuration
   versions; telemetry output path; run ID/context path; monitor interval; and
   assembler timeout. These values describe the run and do not set a maximum
   admissible feature gap.
7. Verify there are no existing live listeners/topologies that could be
   affected. Abort rather than attach to an unowned topology.

## Minimal observation run

Use the existing isolated Stage 2/7 topology and a single explicitly
identified benign run. Collect baseline controller connection and
port-description events, then use only the existing bounded ordinary
connectivity workload (if the approved runner requires it). No attack
scenario, packet-copy rule, packet capture, or mitigation is in scope.
Record the run boundary and stop collection before topology teardown. A
no-workload collection interval may be used if the harness supports it without
changing topology behavior; do not invent a different workload just to
increase counter activity.

The collection should retain:

- schema-2 `connection_boundary` records with controller instance, DPID,
  epoch sequence, epoch ID, UTC and monotonic connection time;
- schema-2 `flow_collection` request/completion records with collection ID,
  DPID, XID, epoch ID, run ID, part count, request/completion timestamps, and
  elapsed collection time;
- `incomplete_collection` records for every timeout, disconnect, cancelled,
  ambiguous, unmatched, duplicate, or rejected collection;
- schema-2 `flow_snapshot` records linked to a complete collection and epoch,
  with source FlowRecord IDs and collector monotonic completion time;
- `observation_window` outputs, retaining invalid/missing reasons and null
  feature values where the input pair is invalid;
- controller logs and an independent, read-only OVS version/protocol/bridge
  identity record sufficient to confirm the test context.

Do not interpret OpenFlow rule counters as packet-level bidirectional flows.

## Lifecycle checks

### Normal collection

For each request, correlate on `(datapath_epoch_id, datapath_id, xid,
collection_id)`. Confirm the request precedes exactly one terminal completion,
all parts belong to that identity, and snapshots follow only a final reply.
Accept a source-verified pair only when both snapshots link to distinct,
complete collections in the same observed epoch and run, with no intervening
run or connection invalidation and valid monotonic timing. Run the existing
`audit_snapshot_pair_provenance` against the append-ordered source stream.
Historical schema-1 records may validate as legacy JSONL but must fail this
source-verified feature gate.

### Disconnect and reconnect

Within the isolated test window, observe an ordinary bounded controller
disconnect/reconnect only if the separately approved procedure permits it.
Do not manipulate a production switch or external controller. Verify the
new connection object receives a distinct epoch, the old epoch closes or is
marked ambiguous, pending old-epoch collections become incomplete, and no
pair spanning epochs is accepted. A delayed old-object reply must not become a
snapshot in the new epoch. If a safe deterministic disconnect cannot be
arranged through the existing testbed, report that branch untested rather than
forging a live event.

### Incomplete collection

First rely on offline tests for the deterministic timeout/cancellation
branches. A live incomplete branch may be observed if a naturally delayed or
interrupted collection occurs. Deliberately stopping the controller while a
request is pending is optional and requires explicit inclusion in the later
approval; it must be bounded and isolated. No OpenFlow fault injection is
proposed. Any missing final multipart part must yield an incomplete terminal
record and no snapshot. A late reply after timeout must remain unmatched and
must not complete the expired request.

## Cadence and gap measurement

Use collector monotonic completion timestamps, not nominal poll settings or
wall-clock differences. Snapshot monotonic completion timestamps currently
support adjacent per-rule snapshot-gap measurement where snapshots exist.
Exact request cadence, completion cadence including empty snapshots, and
request-to-completion latency do not have sufficient persisted monotonic
timestamps yet. Add and validate those fields before reporting those
quantities. Once available, report request/complete/incomplete counts,
multipart part-count distribution, completion latency, and within-run/epoch
snapshot gaps with sample count, empirical minimum, median, upper quantiles,
and maximum. Separate reconnects, timeout events, monitor delays, and run
boundaries. State when sample count is too small for stable quantiles.

Do not choose or imply a maximum admissible feature gap from this one run.
Review cadence/gap evidence and collection failure behavior first; a numeric
policy requires a separate documented decision and must be frozen before any
live-native dataset is generated.

## Cleanup, aborts, and artifacts

Abort immediately if packet-copy/mirror configuration is present, the
topology is not isolated, a detector or mitigation component starts, an epoch
or XID link is missing/contradictory, a supposedly complete collection lacks
its final part, a snapshot is emitted after an incomplete terminal event, or
cleanup cannot be confirmed. Do not repair configuration during the run.

Stop the workload, close the run context, stop the topology/controller using
the existing cleanup path, and independently confirm no test bridge/rules or
controller listener remains. Preserve failed and incomplete artifacts; do
not silently retry or overwrite them.

Expected artifacts for the future runner are: raw telemetry JSONL, Ryu
structured logs, separate run metadata/journal, environment/topology manifest,
read-only OVS state/version record, JSONL validator output, source-pair
provenance audit summary, cadence/gap summary, and cleanup record. The runner,
lineage CLI, cadence tool, and several manifest/report writers are not yet
implemented. Include UTC and monotonic timing, run ID, controller-instance
ID, topology/config ID, code/config hashes when available, monitor interval,
timeout setting, and tool versions. No packet bytes, captures, labels, model
outputs, or mitigation events should be present. Before timestamp
instrumentation is extended, do not claim monotonic request/completion cadence
from UTC or reconstructed values.

## Historical readiness decision before offline prerequisites (2026-10-21)

Epoch and multipart instrumentation is reviewable and offline-tested, but its
real Ryu event lineage is not demonstrated. **The live test is not yet ready
for approval.** The existing runner violates benign-only scope, does not
explicitly configure the Ryu listen port, and records PacketIn metadata; source
audit and cadence CLIs and monotonic collection timestamps are also missing.
Resolve the PacketIn boundary and implement/test these narrow prerequisites
before requesting separate approval. Even then, approval would cover only the
specified benign observation run, not disconnect/reconnect fault injection.
The live-use gate and numeric maximum-gap decision remain blocked until
actual source-linked records and cadence/gap evidence are reviewed.

## Final offline safety review (2026-10-22)

This review inspected source and synthetic tests only. No runner, Ryu, Mininet,
OVS command, privilege escalation, or traffic workload was executed.

### Runner and packet-visibility findings

- The new entry point has no scenario selector or attack-runner import. Its
  only generated traffic is six fixed `h1` commands using
  `ping -c 1 -W 1 10.0.0.3`, followed by fixed sleeps. The prior mixed runner
  remains separate and was not invoked.
- It builds argv for the repository-used Ryu option
  `--ofp-tcp-listen-port 6653`; shell strings are not used for process
  startup. The Mininet host command contains only the fixed source/destination
  workload values.
- The output path is rejected before preflight subprocesses. The run UUID is
  now allocated after that rejection and before preflight. Directory creation
  uses exclusive `mkdir`; dangling symlinks are also rejected before any
  preflight command.
- Policy A is the actual behavior. The table-miss rule still sends packets to
  Ryu and `packet_in_handler()` parses headers for L2 forwarding. The new
  config flag skips PacketIn `TelemetryObservation` serialization in both the
  ordinary and optional copied-packet paths; it does not suppress PacketIns
  or prevent Ryu from seeing packet bytes. Learning, flow installation, and
  PacketOut logic remain outside that recording guard. Port-description
  observations remain possible and are counted separately. This is
  rule-counter-feature-only, not zero packet visibility.
- Packet-copy and explicit test-rule settings are set false by the runner.
  The runner does not configure a mirror, a PacketIn copy rule, packet capture,
  or payload persistence. No claim is made that ordinary PacketIns cannot
  carry packet bytes into Ryu.
- Normal completion requires the controller process to exit, bridge `s1` to
  be absent, and the controller listener to refuse a connection before the
  summary can say `cleanup_verified: true`. Startup/workload exceptions still
  enter nested cleanup; they propagate and do not write a successful summary.
  Offline tests now cover stopped-process, residual-bridge, and residual-
  listener failures. Runtime cleanup remains unverified.
- OVS service/bridge preflight and post-cleanup bridge queries now have
  five-second subprocess timeouts. Version queries are also bounded. However,
  the Mininet topology API calls are synchronous and do not have runner-level
  deadlines: `create_network()` invokes `Mininet.build()/start()`, each
  `h1.cmd()` waits for Mininet's shell sentinel, and `network.stop()` runs
  synchronously. The locally inspected Mininet 2.3.1b4 `Node.waitOutput()`
  loops until that sentinel without a timeout, and `Mininet.start()/stop()`
  do not accept a timeout. The ping's `-W 1` bounds ping's reply wait, not the
  outer Mininet shell/API call. Therefore the strict bounded-wait requirement
  is not met, and a stuck topology start, command, or teardown could prevent
  the runner from reaching its cleanup verification. This is a concrete
  blocker for approval; no wrapper or asynchronous cleanup workaround was
  added because it could create unsafe concurrent teardown.

### Provenance and audit semantics

The source path uses `time.monotonic_ns()` for request start, multipart part
receipt/final completion, snapshot completion, and incomplete terminal
recording, within one controller process. A request record and its completion
record copy the same request start; snapshots copy the final completion time.
UTC timestamps are retained as wall-clock event labels. Pair validation uses
schema-2 request, terminal, snapshot, controller-instance and epoch fields;
legacy schema-1 snapshots cannot enter the source-verified pair path. These
checks establish structural lineage only, not cryptographic authenticity.
Ryu callback ordering, actual emitted lineage, runtime collection completeness,
and clock/cadence behavior remain to be validated in the approved test.

The auditor now reports raw request and terminal record counts separately
from collections with valid complete lineage, raw snapshot records separately
from snapshots linked to such collections, and source-verified accepted and
rejected pairs. Empty complete collections count as completed collections but
have no snapshot and cannot create a feature pair. PacketIn observations are
counted by type but never used for pairs or timing.

Cadence fields have distinct meanings:

- Request gaps are request-to-request intervals within a run/epoch.
- Completion gaps are complete-terminal-to-complete-terminal intervals within
  a run/epoch.
- Collection duration is request start to final multipart completion.
- Snapshot gaps are measured only between adjacent same-rule snapshots whose
  source provenance pair is accepted; incomplete or missing monotonic values
  yield no duration.

No maximum-gap policy is selected. Output paths are checked against the input
and each other, including symlink/hard-link aliases. Output write failures
return nonzero before printing an `AUDIT_COMPLETE` report. The audit does not
modify its input.

### Concrete fixes and checks

The review fixed concrete offline defects: dangling output symlinks could
bypass the runner's early reuse check; run-ID allocation occurred after
preflight subprocesses; auditor outputs could alias and overwrite the input
or fail with an unhandled output exception; the cadence report mixed
invalid/incomplete collections with missing timestamps and did not report
source-verified snapshot gaps or distinct validated collection/snapshot
counts; schema-2 linkage did not compare UTC timestamps across request,
completion, snapshot, and nested FlowRecord source fields; and successful run
summaries lacked a packaged software/config/source inventory. Focused tests
cover these cases plus cleanup failure, explicit port configuration, Policy A
configuration, schema-2 lineage, invalid timestamps, empty collections,
PacketIn exclusion/forwarding-structure checks, unsupported attack selection,
and deterministic repeated summaries. The focused offline suite passed 88
tests on 2026-10-22.

On successful completion, the runner summary records bounded version-query
outputs for Ryu manager, Mininet, `ovs-vsctl`, and `ovs-ofctl`; Python/platform,
controller PID/argv/port/settings; workload and run times; and SHA-256 values
for the runner, auditor, controller/configuration, and live-feature/provenance
sources, plus explicit false values for the test rule, packet-copy mode, and
PacketIn telemetry recording. The approved run package must preserve that
summary with the runner/controller logs, JSONL, audit outputs, run journal,
and cleanup result.
The version queries are argv-only `--version` invocations with a five-second
timeout and are not executed during this review. Available local metadata was
Python 3.11.16 in the project venv, system Python 3.14.6, Mininet 2.3.1b4 in
the locally inspected Python 3.14.6 system package, pytest 9.1.1, Ruff 0.16.10,
mypy 2.4.0, and Eventlet 0.41.2 in the Ryu venv. Ryu and OVS version metadata
was unavailable locally; their version commands were deliberately not
executed.

The runner now checks `importlib.util.find_spec("mininet")` using its own
interpreter before any external preflight process. This detects an unavailable
Mininet Python module early; it does not prove that Mininet can initialize in
the runtime environment. The project Python 3.11 venv does not expose Mininet
metadata, while the local system Python 3.14 package was available for source
inspection. The runner has not been executed under either interpreter.

### Preflight, aborts, and approval status

Before a separately approved run, preserve a new immutable output path and
the source/hash baseline; confirm required executables and existing OVS
service; refuse an existing `s1` or listener on 6653; record exact software
versions and environment; confirm controller argv and all three false
settings (test rule, packet-copy, PacketIn telemetry recording); confirm no
mirror/capture configuration; then start only the benign runner. Abort before
workload on any mismatch, inaccessible prerequisite, non-OpenFlow-1.3
configuration, packet-copy/mirror state, missing run/epoch/XID/monotonic
lineage, malformed/incomplete collection, unexpected listener/bridge, or
uncertain cleanup. Preserve failed output and never retry in-place. Do not
feed these records to feature training or inference, and do not select a
maximum-gap policy from this run.

**Verdict: BLOCKED.** The runner does not meet the bounded-wait requirement
for Mininet topology startup, host command completion, or topology teardown.
Do not submit it for execution approval until a separately reviewed bounded
orchestration/cleanup design is implemented and tested offline. This is not
approval to execute, does not validate live Ryu lineage or cleanup, and does
not unblock live feature use, training, inference, detector integration, or
mitigation. Environment-version capture is implemented but unexecuted. The
maximum-gap policy remains unset.

**Superseded by the final offline safety review below:** source review found
that Mininet startup, synchronous host command completion, and Mininet
teardown lack runner-level deadlines. The current verdict is therefore
**BLOCKED** until bounded orchestration and cleanup are designed and tested.

## Offline implementation update — 2026-10-21

The repository now has a separate, unexecuted benign-only entry point:
`scripts/run_stage7_rule_counter_validation.py`. It does not dispatch the
Stage 3 attack runner; it reuses only its run-context writer. Its fixed workload is six bounded `h1`-to-`h3`
single-ping operations, one second apart, followed by 2.5 seconds for final
flow-stat polls. It requires a new output directory, generates a fresh UUID
run ID, requires the established Stage 2 OpenFlow port 6653, and passes
`--ofp-tcp-listen-port 6653` to Ryu. **This runner has not been executed.**

### Packet visibility decision: Policy A

The proposed collection is **rule-counter-feature-only, not zero packet
visibility**. `stage2_controller.py` installs a table-miss output-to-controller
rule for the existing learning-switch behavior. Unmatched packets can
therefore reach Ryu, where `packet_in_handler()` parses Ethernet metadata
before forwarding. Removing that rule or changing forwarding solely for
collection would be a separate architecture change and is not justified here.

The additive `SDN_STAGE2_RECORD_PACKETIN_TELEMETRY` setting defaults to true
for existing behavior. The new runner explicitly sets it false, and also
keeps packet-copy mode and the explicit test rule false. Ordinary PacketIns
may still reach Ryu and may be parsed/logged for L2 forwarding, but the
PacketIn handler does not serialize their `TelemetryObservation` records.
Port-description observations may still be present in `telemetry_observation`
records; the offline audit counts them separately. The source-provenance audit
constructs pairs only from `flow_snapshot` records. Cadence uses only
`flow_collection` and `flow_snapshot` monotonic fields. PacketIn records never
contribute to a feature pair or cadence sample. This is not evidence that Ryu
received no packet bytes.

Policy B (zero PacketIn visibility at Ryu) is not selected: the existing
table-miss rule makes it incompatible with the current learning-switch path
without a separate forwarding-mode redesign. Disabling packet-copy rules alone
would not establish zero PacketIn visibility.

### Implemented offline audit interfaces

The read-only lineage and cadence command is:

```bash
.venv/bin/python scripts/audit_stage7_rule_counter_telemetry.py \
  experiments/stage7-telemetry/<approved-run>/telemetry.jsonl \
  --summary-json experiments/stage7-telemetry/<approved-run>/lineage-cadence-summary.json \
  --report-md experiments/stage7-telemetry/<approved-run>/lineage-cadence-report.md
```

It first calls `validate_telemetry_jsonl()`, then checks request/terminal/
snapshot linkage and invokes `audit_snapshot_pair_provenance()` for adjacent
same-rule snapshots. It exits nonzero unless at least one source-verified pair
is accepted and the stream has no audit issues. No feature vector is built, so
no maximum-gap policy is selected. Empty complete collections are reported
separately; timing gaps are listed only when supported by integer monotonic
timestamps.

New schema-2 producers write `started_monotonic_ns` on flow-stat requests,
both `started_monotonic_ns` and `completed_monotonic_ns` on complete terminal
records, and `terminal_monotonic_ns` on incomplete terminal records. Snapshot
records retain `collector_monotonic_ns`. These additive values come from
`time.monotonic_ns()` at the existing request, final-reply, and incomplete
recording points. Historical schema-1 records remain accepted by the general
validator where supported but cannot pass the source-verified audit. Older
schema-2 records without the new monotonic fields remain structurally readable
but are timing-incomplete; no historical timing is reconstructed from UTC or
`elapsed_seconds`.

### Future command sequence (unexecuted; separate approval required)

Offline checks and inventory commands:

```bash
.venv/bin/pytest -q tests/unit/test_live_observation_telemetry.py tests/unit/test_live_feature_builder.py tests/unit/test_stage2_config.py tests/unit/test_stage7_rule_counter_audit.py
.venv/bin/ruff check networking/ryu/config.py networking/ryu/stage2_controller.py scripts/run_stage7_rule_counter_validation.py scripts/audit_stage7_rule_counter_telemetry.py src/sdn_defense/telemetry_audit.py
python3.11 --version
ovs-vsctl --version
ovs-ofctl --version
mn --version
.venv-ryu/bin/ryu-manager --version
```

The following command is **not executed here**. It is privileged and starts
the local OVS/Mininet/Ryu testbed and the six benign pings. A separate review
must first authorize that host and confirm the isolated topology and root
access:

```bash
sudo env PYTHONPATH="$PWD" /usr/bin/python3 scripts/run_stage7_rule_counter_validation.py \
  --output-dir experiments/stage7-telemetry/<new-unique-run-directory> \
  --ryu-manager .venv-ryu/bin/ryu-manager
```

After the runner exits, invoke the offline JSONL validator/auditor command
above and review both reports. Measure cadence and gap distributions first;
do not pass the records to the feature builder until a maximum-gap policy is
reviewed separately. This proposal does not establish live Ryu event lineage,
privilege/SELinux behavior, or cleanup success.

### Current gate

The offline prerequisites are implemented and covered by synthetic tests.
The live plan is **prepared for separate approval, not approved or validated**.
Actual Ryu schema-2 event lineage, controller/topology cleanup behavior,
PacketIn suppression at the recorder boundary, and measured cadence/gaps are
still unverified. Long-running XID wrap/reuse is outside the short-run scope.
Structural provenance checks are not cryptographic authentication.

Final focused offline rerun on 2026-10-22: 88 passed across the four targeted
test modules. Ruff passed for the changed Python files; targeted mypy passed
for the three changed source modules. Both CLI `--help` paths completed without
starting services. The unbounded Mininet API calls remain the approval blocker.
