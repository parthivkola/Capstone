# Remaining Stages and Go/No-Go Gates

**Planning date:** 2026-10-21  
**Purpose:** Dependency-aware route from the current evidence-backed project to a defensible live-native detection and bounded-defense capstone. This plan creates no new results and authorizes no traffic or model work by itself.

**Repository-state note (2026-10-21):** the requested project path's nested
directory `explainable-adaptive-sdn-defense-appliance` does not exist in this
workspace. The available project files are at the workspace root. That root
has no Git metadata, so `git status`, branch, and commit could not be
established; no repository commit is asserted. The current README is stale:
it says Stage 3 is planning-only and that no ML or mitigation implementation
exists, while the Stage 3 generators, Stage 5 artifacts, and Stage 7 code and
reports are present. This audit does not rewrite unrelated README history.

## Current capstone target

The minimum viable research system is:

1. OpenFlow rule-counter collection with complete-collection and datapath-epoch provenance.
2. Validated snapshot pairing and the four fixed live-native rule-counter features.
3. A live-native detector trained only from observations generated under the same frozen feature contract.
4. Structured evidence, uncertainty, and risk decisions.
5. Narrow exact-scope SDN mitigation with independent switch-state confirmation, expiry, and rollback.
6. A reproducible report containing detector, safety, availability, and cost results.

The Stage 5 RF is an offline research model and remains disconnected. GraphSAGE is deferred. Packet-derived features are not in the critical path until packet observation passes a new safety and completeness review; the B1 result means the current mirror method is unfrozen. Physical hardware alerts, dashboards, and databases remain out of scope unless implementation evidence later shows they are already working and directly needed.

## Submission-critical versus capstone-critical work

The official conference page lists October 31, 2026 as the full-paper date in its Important Dates block, alongside an earlier September 30 date; the CMT deadline and timezone need confirmation. The current manuscript was not found in the workspace. For the submission window, prioritize locating the manuscript/template, organizer clarifications, evidence-aligned writing, reference verification, and 10–12 page formatting. Do not rush unfinished live-data/model stages to create paper claims.

| Submission-critical by working deadline | Capstone work that should remain post-submission unless independently completed and reviewed |
|---|---|
| Obtain current manuscript and official template. | Freeze live snapshot gap and collection/epoch semantics (Stage 1 below). |
| Confirm CMT full-paper deadline/timezone, abstract/page rules; resolve camera-ready date discrepancy in writing. | Approve and execute a safe rule-counter-only collection plan (Stages 2–4). |
| Rewrite claims using only frozen results; keep RQ1–RQ3 as distinct studies. | Train/evaluate live-native detector on newly collected run-labeled data (Stage 5). |
| Verify references, remove placeholders/author notes, verify diagrams/abstract/keywords/similarity. | Connect evidence-aware decisions and then re-validate controlled enforcement (Stages 6–7). |
| Include limitations: no temporal concept-drift finding, no RF parity, no live detector, no reliable packet-mirror freeze, no explanation-fidelity result. | Adaptation ablations only after static live detector credibility; package/report (Stages 8–9). |

If the paper must be submitted before these gates pass, describe Stages 1–9 as future work and do not imply they are complete.

## Ordered stage gates

### Stage 1 — Freeze snapshot-gap semantics and audit collection completeness/datapath epochs

**Dependencies/blockers:** Existing `ObservationWindow` and `LiveRuleFeatureVectorV1` definitions exist, but the maximum admissible snapshot gap remains caller-supplied and unfrozen. The builder accepts caller-supplied collection-complete and datapath-epoch metadata; the real source must prove these fields.

**Deliverables:** A versioned collection/pairing protocol that specifies (a) when a multipart stats collection is complete, (b) time source and interval, (c) max gap and gap closure, (d) reset/replacement/disappearance semantics, (e) datapath connection epoch creation and closure, (f) run-boundary interaction, and (g) rule identity continuity. Provide an audit map from Ryu collector events to the feature builder input wrapper.

**Validation/exit criteria:** Deterministic tests for complete/incomplete/multipart timeout, empty complete snapshot, duplicate/out-of-order collection, counter decrease, missing rule, reconnect/new epoch, run boundary, and max-gap behavior. Demonstrate metadata is sourced from actual collector lifecycle—not supplied by a caller guess. Ensure invalid/missing remains distinct from measured zero. Freeze the protocol before data collection.

**Safety restrictions:** Offline review/unit tests only until protocol freeze; no detector, no policy, no mitigation. No packet copy.

**Preserve:** Stage 5 data/prepared data/results/protocols; FlowRecord meaning; Stage 7 mitigation protocol; Stage 6 deferred status; existing historical telemetry artifacts.

**Go/no-go:** Go only if actual complete-snapshot and epoch provenance can be reconstructed without ambiguity. Otherwise redesign collector instrumentation and repeat these tests; do not build a training dataset.

**Stage 7I.3 status (2026-10-21): BLOCKED for live use.** The four-value
builder is implemented and its explicit gap boundary is synthetic-testable.
The builder limit remains required from its caller with no default; the Ryu
counter engine separately uses a hard-coded 30-second limit, which is not a
validated live-feature policy. The builder trusts its caller's completeness
boolean and non-empty datapath epoch ID. The Ryu source logs complete
collection and connection-boundary events, but the feature-builder input
wrapper is not source-authenticated to those events and `FlowSnapshot` has
no datapath-epoch field. Do not create training features until this provenance
path is made explicit and validated. See
[`live-feature-builder.md`](live-feature-builder.md#stage-7i3--snapshot-pairing-prerequisite-audit-2026-10-21).

**Stage 7I.3 offline provenance audit update:** an append-ordered source-record
validator and `build_source_verified` entry point now require one requested
and one completed collection record plus a linked snapshot and same observed
datapath epoch. Synthetic tests cover completion, timeout/incomplete records,
epoch/run boundaries, and ambiguous lifecycle. The current Ryu source emits
request/completion/collection-ID linkage, but not a datapath epoch ID in
connection, collection, or snapshot records. Therefore its existing stream
fails closed at this gate. The new tests do not establish live validity.

**Gate remains BLOCKED:** the next prerequisite is offline Ryu instrumentation
for connection-epoch creation/closure and propagation through multipart
requests, terminal outcomes, and snapshots, including invalidation on an
unidentified disconnect. After source tests and review, a separately
approved rule-counter-only validation must verify the actual emitted lineage
and collect cadence/gap evidence. No numeric maximum gap is selected here.
The focused offline feature/telemetry tests for this update passed 41 cases;
Ruff and targeted mypy passed. These checks do not validate a live Ryu run.

**Stage 7I.3 source instrumentation addendum (2026-10-21):** Ryu source code
now creates controller-process-scoped datapath epochs from observed datapath
connection objects, propagates them through request/completion/incomplete and
snapshot records, and invalidates pending collections on timeout, run change,
disconnect, reconnect, shutdown, or ambiguous disconnect. The offline
provenance audit requires a connection boundary whose controller-instance,
datapath, and sequence fields agree with the epoch ID. Synthetic tests cover
the epoch/collection state machine and its fail-closed cases. The preceding
paragraphs are retained as historical audit context from before this change.

**Current gate remains BLOCKED:** this change has not been run in Ryu, and
synthetic lifecycle tests cannot prove actual Ryu event ordering or emitted
JSONL lineage. The next safe action is review of this instrumentation. After
review, a separately approved rule-counter-only validation must verify
connection/request/reply/terminal/snapshot links from a real Ryu stream and
measure collection cadence and gaps. Only then can the maximum admissible
snapshot gap be considered. The existing 30-second counter-engine setting
remains runtime behavior, not a validated feature-contract threshold. No
packet-derived telemetry, detector, training, inference, or mitigation is
authorized by this update.

### Stage 2 — Approve a safe rule-counter-only observation plan

**Dependencies/blockers:** Stage 1 semantics frozen. Packet observation is excluded; B1 invalidated universal `snaplen=54` assumptions. No attack labels are introduced at this stage.

**Deliverables:** Preregistered collection plan limited initially to validated OpenFlow rule counters: topology, bridge/port and rule scope, cadence, duration, run context, raw record schema, max gap, rate/storage bounds, completeness and cleanup plan, separate scenario journal, privacy and retention policy, exact commands, and stop conditions.

**Validation/exit criteria:** Static preflight and unit validation show no detector/policy/mitigation imports on the observation path, no mutation outside the isolated test topology, deterministic manifest, versioned schemas, and explicit no-data/invalid states. Independent reviewer signs the run plan and hash list.

**Safety restrictions:** No traffic until the written plan and allowed test window are approved. No packet capture/mirroring or payloads. No real-world interfaces.

**Preserve:** All Stage 5 artifacts and protocols, existing Stage 7 protocol and prior results, telemetry history, FlowRecord semantics, GraphSAGE decision.

**Go/no-go:** Go only if the runner is configuration-auditable, cleanup-gated, and cannot reach the mitigation adapter. If evidence scope depends on packet-level semantics, stop and return to observability design.

### Stage 3 — Validate live observation quality and select one observable pilot scenario

**Dependencies/blockers:** Stages 1–2 passed. Existing generic scan telemetry was partial (one of eight destination ports visible in PacketIn); packet-copy telemetry remains unfrozen after B1. Do not assume a port scan is the pilot.

**Deliverables:** A small number of controlled rule-counter-only benign and candidate-scenario runs with unique run IDs, manifests, scenario journals separate from telemetry, validators, completeness/gap summaries, resource and service-availability notes, and a written pilot-selection record. Candidate pilot is selected only after measurements establish distinguishable evidence under allowed features.

**Validation/exit criteria:** All collected files replay/validate; no cross-run mixing; whole run metadata is correlated; all known missingness/reset/epoch cases accounted for; benign and candidate records have enough complete observations to define candidate features. Report descriptive evidence only at this gate. Scenario selected based on observed signal and repeatable instrumentation, not assumed attack visibility.

**Safety restrictions:** Isolated Mininet only; bounded workloads authorized by the separate plan; no mitigation; stop on unsafe/ambiguous collection. No packet payload or broad packet mirror.

**Preserve:** Frozen ML evidence, protocol files, historical telemetry, and all prior B1/truncation artifacts (do not rewrite past outcomes).

**Go/no-go:** Go only when observability is independently measurable and repeatable. If no scenario is distinguishable with rule counters, revise the scientific question or obtain separate approval for a safely validated observation mechanism; do not fabricate features.

### Stage 4 — Build run-labeled live-native dataset with whole-run splits

**Dependencies/blockers:** Stage 3 pilot and feature schema freeze. Require multiple independent runs per condition and enough benign runs to characterize variation. Label granularity is scenario/run-level weak or controlled-condition labels, not per-flow ground truth.

**Deliverables:** Immutable versioned dataset, raw telemetry and separate run/context and label tables; exact feature-builder/schema hash; run IDs; split-group IDs; collection/coverage metadata; scenario journal references; data dictionary; label policy and ambiguity states; sealed split manifest. Assign entire runs to train, validation, or test before deriving overlapping windows.

**Validation/exit criteria:** Recompute each feature from raw source observations; reproduce feature order and values exactly; no run/window overlap between partitions; labels do not enter predictors; scenario/run IDs and post-action results remain evaluation metadata; hashes and row/window counts reconcile. Include benign-only validation runs and a sealed held-out run set.

**Safety restrictions:** No Stage 5 test data or labels for live model fitting/calibration. No post-action observations as pre-action features. No threshold selection on sealed test.

**Preserve:** Stage 5 raw/prepared datasets and protocols; no reusing the 77 RF model; Stage 6 remains deferred; frozen Stage 7 risk thresholds untouched.

**Go/no-go:** Go only if whole-run separation, label provenance, feature reproducibility, and observation coverage pass. If runs are too few or coverage is materially different by label condition, collect more approved runs or stop the model study.

### Stage 5 — Evaluate simple baselines and a suitable lightweight ML model

**Dependencies/blockers:** Stage 4 dataset frozen. No live model is authorized by existing offline Stage 5 evidence.

**Deliverables:** Baselines (e.g., majority/constant and preregistered simple rule/statistical baseline), then one justified lightweight supervised model on live-native features; exact training pipeline and model artifact; validation-selected operating points only; run-level test results and resource/latency report; per-class error analysis.

**Validation/exit criteria:** Report macro F1, per-class F1, FPR/FNR with denominator and run-level confidence/variation, detection latency, missingness/coverage-stratified performance, CPU/RSS, calibration if probabilities will influence policy, and comparison against fixed baselines. Repeat with whole-run test untouched until the protocol is frozen. A model proceeds only if performance and uncertainty are meaningful against benign run variability and minimum operational constraints set before final testing.

**Safety restrictions:** Offline training/evaluation first. No automatic mitigation. No RF reuse or retraining of Stage 5. Do not tune on test runs.

**Preserve:** Stage 5 metrics/protocols remain as historical unrelated evaluations; Stage 7 action thresholds remain frozen and cannot be tuned from the test set.

**Go/no-go:** Go only when held-out-run results are reproducible, calibration/uncertainty is characterized, and false-positive operating limits meet preregistered validation criteria. Otherwise remain observe-only or revise the feature/dataset protocol.

### Stage 6 — Integrate evidence-aware decisions

**Dependencies/blockers:** Stage 5 detector credible and its output calibration/uncertainty known. Existing DetectionResult and RiskPolicy interfaces exist, but must be fed from the new detector only through an explicit adapter and provenance.

**Deliverables:** Narrow detector-output adapter; schema/model/provenance fields; evidence freshness and coverage gates; reason codes that reference actual input evidence; observe-only default; audit correlation from observation IDs through decision IDs; replay tests against frozen policy.

**Validation/exit criteria:** Verify benign/unknown/uncertain and missing/stale/low-coverage cases fail safe; explanations are traceable to evidence and tested for stability/faithfulness before claims; threshold/action-rate requirements use validation data only; no test result alters cutoffs. Demonstrate no feature leakage from run labels or post-action evidence.

**Safety restrictions:** Default observation-only. No Ryu action in development/replay tests. No LLM decision-making. No adaptation yet.

**Preserve:** Frozen Stage 7 protocol and action-rate limits; do not adjust risk thresholds or lifecycle semantics. Preserve Stage 5 datasets and results.

**Go/no-go:** Go to controlled enforcement only when model/calibration provenance, exact action scope, evidence freshness, protected-scope behavior, and audit lineage are all tested. Any uncertainty or incomplete coverage should abstain.

### Stage 7 — Validate detection-to-enforcement, service availability, confirmation, expiry, rollback

**Dependencies/blockers:** Stage 6 passes; existing OVS/Ryu enforcement substrate already passed with synthetic detection fixtures, but no real detector is integrated.

**Deliverables:** Isolated, opt-in integration test with one frozen pilot scenario and bounded action scope; traffic/service availability measurements; SUBMITTED and independent CONFIRMED events; action cookie/scope evidence; TTL and rollback checks; protected flow, adapter failure, and verifier failure checks; no residual rule/listener after cleanup.

**Validation/exit criteria:** Independently verify installed rule state and absence on rollback; measure target-flow outcome and non-target/benign disruption; prove expiry and rollback under normal and injected failure paths; preserve complete audit chain and action-rate limits. Report false mitigation rate, confirmation rate, rollback success, disruption, and latency with denominators.

**Safety restrictions:** Authorized isolated testbed only; exact-scope rules, short bounded test duration, protected-flow safeguards, strict TTL, fail-closed capability checks, cleanup in finally path. No production interfaces.

**Preserve:** Stage 7 protocol and TTL/action-rate definitions; Stage 5 frozen; no unsupported rate limiting claim.

**Go/no-go:** Go to adaptation only when static detector results are credible and enforcement remains available, reversible, and independently verifiable. If mitigation causes unbounded or unexplained service loss, disable enforcement and return to design.

### Stage 8 — Run adaptation ablations after static live detector is credible

**Dependencies/blockers:** Stages 4–7 passed, adequate repeated runs and delayed-label eligibility protocol, candidate drift/shift signal shown selective on validation, and anchor data/protection rules frozen. Stage 5F is offline source-window evidence and cannot be presented as live adaptation validation.

**Deliverables:** Pre-registered static vs scheduled/triggered live-native model comparisons; PSI/input-shift signal separated from label/performance evidence; candidate gating arms; bounded fitting, candidate validation, anchor checks, rollback, update latency/resource logs; sealed run-level test.

**Validation/exit criteria:** Trigger precision/selectivity and false alarm on benign runs; no PSI-only authorization; matured labels eligible under protocol; candidate validation and protected anchor acceptance; no test-window tuning; measurable next-window outcome, latency and compute cost; adaptation ablations on identical whole-run splits.

**Safety restrictions:** Offline/replay adaptation first; no unbounded online fitting; no action escalation from PSI alone; no retraining of frozen Stage 5 RF.

**Preserve:** Stage 5F protocol/results unchanged and clearly separate; Stage 7 adaptation gate unchanged unless a new versioned protocol is reviewed and frozen.

**Go/no-go:** Go only if static detector remains credible, adaptation trigger is selective, updates pass validation/anchor tests, and benefits exceed update cost without worsening preregistered safety limits. Otherwise retain static model.

### Stage 9 — Final reproducibility package and capstone report

**Dependencies/blockers:** All research-critical stages to be claimed as completed have passed their gates; failed/incomplete components are disclosed.

**Deliverables:** Reproduction commands and environment lock; manifests/hashes; run/split/feature schemas; validator outputs; data provenance; model/policy versions; test and integration reports; final diagrams; claim-to-evidence matrix; limitations and archived artifacts.

**Validation/exit criteria:** A clean reviewer can reproduce data validation, deterministic feature builds, offline evaluation, and approved system validation from documented instructions; all reported values reconcile with machine-readable artifacts; frozen hash checks pass; unsupported claims removed; full paper and capstone use the same terminology and boundaries.

**Safety restrictions:** Reproduction instructions distinguish offline commands from privileged isolated network tests and include explicit warnings/guards. No automatic attack/mitigation execution from generic scripts.

**Preserve:** All frozen Stage 5 and Stage 7 protocols/results; archive rather than overwrite historical failures and audits.

**Go/no-go:** Completion only when each claimed result has a source artifact and validation trail. Missing evidence is reported as a limitation, not filled by reconstruction.

## Cross-stage frozen-artifact policy

Throughout Stages 1–9, retain Stage 5 raw/prepared data, labels, splits, configs, protocols and result JSON unchanged; do not reinterpret Stage 5F as temporal concept drift; do not alter Stage 7 risk/action thresholds or mitigation lifecycle; keep GraphSAGE deferred; keep FlowRecord as a rule-stat snapshot; preserve packet-observation failures and prior diagnostics as historical evidence. New live-native data and models require separate versions, manifests, split protocols, and approval.

### Stage 7I.3 review update (2026-10-21)

Offline review confirms source code links connection epochs to datapath object,
collection request/reply, and snapshots. Source-pair verification requires
schema-2 lineage; historical schema-1 records remain available to general
replay validation but cannot qualify for live features. The audit provides
structural consistency, not cryptographic authenticity. Ryu event lineage,
XID allocator wrap behavior, and measured collection cadence/gaps remain
unverified. The separately approved, not-yet-executed validation proposal is
[`stage7i3-rule-counter-live-validation-plan.md`](stage7i3-rule-counter-live-validation-plan.md).
Live feature collection remains **BLOCKED** and no maximum-gap value is
selected.

### Stage 7I.3 offline prerequisites update (2026-10-21)

**Implemented offline:** a separate benign-only runner
(`scripts/run_stage7_rule_counter_validation.py`) uses explicit Ryu port 6653,
requires a new output directory, tags a fresh run ID, and has no attack
dispatch. An additive PacketIn telemetry-recording setting suppresses
PacketIn-derived JSONL observations for this runner without changing
learning-switch table-miss behavior. The future experiment is therefore
rule-counter-feature-only, not zero packet visibility: Ryu may still receive
and parse ordinary PacketIns for forwarding. The audit CLI validates JSONL and
source-verifies rule-counter pairs; cadence uses only recorded monotonic
values. No maximum-gap threshold is set.

**Not validated live:** the benign-only runner has not been executed. The live
test remains blocked until separately approved, run, and reviewed. Actual Ryu
event lineage, cadence/gap distribution, host cleanup behavior, and recorder
suppression under live controller events remain unverified. Historical
schema-2 records missing monotonic request/completion values are readable but
cannot provide measured cadence; historical schema-1 records cannot pass the
source-verified pair gate. This offline prerequisite stage authorizes no
detector, training dataset, inference, or mitigation.

### Stage 7I.3 final offline safety review (2026-10-22)

The benign-only runner and JSONL auditor received focused offline fixes and
regression tests. The runner rejects pre-existing directories and dangling
symlinks before preflight processes, allocates its run ID before preflight,
and only reports cleanup verified after controller exit, bridge absence, and
listener absence checks pass. The audit CLI refuses input/output aliases and
reports output failures with a nonzero incomplete result. Its summary now
distinguishes raw records from lineage-valid collections/snapshots and reports
request intervals, completion intervals, request-to-completion durations,
and accepted same-rule snapshot gaps as separate measurements.

On successful completion the benign runner summary also captures bounded
Ryu/Mininet/OVS version-query output, controller PID/argv/settings, workload
parameters and timestamps, and SHA-256 source/configuration hashes. These
queries are specified in source but have not been executed in this offline
review.

Policy A remains in force: PacketIns may reach and be parsed by Ryu for
learning-switch forwarding, while their `TelemetryObservation` writes are
disabled for the rule-counter collection. This is not zero packet visibility.
No live event lineage, actual cleanup, or measured cadence has been validated.
**Gate status: BLOCKED for approval.** Mininet topology build/start,
synchronous host-shell command waits, and topology teardown have no
runner-level deadline. The local Mininet implementation waits for a shell
sentinel without a timeout; a stalled call can prevent cleanup verification.
Require a separately reviewed bounded orchestration and cleanup design with
offline failure-path tests before submitting the benign run for approval.
This does not authorize feature use, training, inference, detector
integration, or mitigation. The maximum-gap policy remains unset.



Final offline safety review (2026-10-22) added a Mininet-module availability
check and passed 88 focused tests, Ruff, and targeted mypy. Mininet topology
startup, synchronous host command completion, and teardown remain unbounded,
so the live approval gate remains blocked.
