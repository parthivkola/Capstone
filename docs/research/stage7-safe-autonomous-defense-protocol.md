# Stage 7 — Safe Autonomous SDN Defense Protocol

**Status:** frozen protocol design; implementation, model training, and network actions have not started. Stages 5A–5F remain frozen. GraphSAGE is deferred. Stage 7 is an empirical study of decision policy and bounded response, not a presumption that automation is beneficial.

## Research question

> Can an SDN defense system safely translate uncertain detection results into proportionate, explainable, and reversible mitigation actions while adapting to changes in its learned environment?

The study keeps source/distribution shift terminology. PSI measures input-distribution change; it does not identify attacks or establish a change in `P(Y|X)`.

## 1. Read-only review and evidence boundary

| Information | Current evidence | What is not available now |
|---|---|---|
| Classification/confidence | Offline Stage 5 Random Forest outputs; RF `predict_proba` is available in the experiment code. Stage 5F is binary Benign/Attack. | No live detector invokes these models from Ryu. Stage 5F result artifacts contain aggregate results, not a live score stream. |
| Novelty | Stage 5E.2B Isolation Forest scores and Stage 5E.2C RF UNKNOWN decisions exist as offline experiments. | No online novelty service or per-flow novelty result. |
| Distribution shift | Stage 5F records PSI over source windows; all 20 evaluation windows signaled at least five features. | No live PSI monitor; PSI is global to a window, not evidence that an individual flow is malicious. |
| Persistence | Ryu polls flow statistics at a configured interval (2 seconds by default); `FlowRecord` can identify some matched rules/flows. | No alert persistence tracker. Current L2 rules often lack a complete 5-tuple, so repeated same-flow evidence may be unavailable. |
| Flow/host identity | `FlowRecord` optionally carries datapath, IP/MAC, ports, and ingress port when present in the OpenFlow match. Stage 3 logs fixed Mininet scenario host/target details. | No general asset inventory or guaranteed complete flow key. |
| Attack evidence | Stage 3 scenario/fixture logs, OVS counters, and Ryu rule/port observations are documented. | These are scenario observations, not detector evidence or attack classifications. Current Ryu logs do not decode ARP sender claims, DNS names, or TCP SYN counts as typed evidence. |
| Affected asset importance | Fixed lab roles: h1 client, h2 test host, h3 server; protected h1↔h3 reachability is a documented baseline. | No business criticality or production asset score. |
| Mitigation/reversibility | Technology-neutral `DecisionRecord` has an expiry field; `MitigationPort` declares apply/rollback. | No typed `DetectionResult`, risk engine, OpenFlow mitigation adapter, action registry, TTL enforcement, or rollback execution exists. |

Stage 4 `FlowRecord` has no label or score and does not itself mean a packet-level flow. Stage 3 observations are JSONL scenario/configuration/fixture/topology records; they are not joined to model-ready CICFlowMeter rows. Stage 5 uses 77 CICFlowMeter features, whereas Stage 2 Ryu currently emits OpenFlow rule counters/matches. The feature parity and flow correlation needed for live model decisions are therefore **not established**. A later implementation must pass a parity/correlation gate before making end-to-end detection or containment claims.

Stage 5 contextual findings are fixed: Stage 5E.2A assigned 99.86% of LOIC-HTTP to Benign; Stage 5E.2B had 0% LOIC-HTTP unknown recall at its primary operating point; Stage 5E.2C had 0.0536% LOIC-HTTP unknown recall at approximately 1% validation benign rejection; Stage 5F PSI signaled all evaluation windows. These findings motivate caution and explicit abstention/adaptation gates. They do not validate a mitigation policy, and PSI is not an attack signal. No Stage 5/6 artifact is changed by this protocol.

## 2. Detection, risk, and execution are separate

The future transport-neutral `DetectionResult` will report a prediction and provenance only. It will not select or execute an action. Fields are optional when the source cannot provide them:

| Field | Meaning and availability rule |
|---|---|
| `classification` | `BENIGN`, `ATTACK`, or explicit `UNKNOWN` from a novelty/rejection-capable detector. For the Stage 5F binary RF, the predicted class is Benign/Attack. |
| `confidence` | Finite score in `[0,1]`, with score definition/model ID recorded. RF class probability is available offline; absent from current Ryu observations. |
| `novelty_score` / `novelty_state` | Optional, only from a separately validated novelty component. UNKNOWN is not synonymous with attack. |
| `distribution_shift_state` | Optional global/window PSI state with window ID. It must not be attached to a specific flow as attack evidence. |
| `evidence` | Bounded references to observed feature values or Stage 3/Ryu event IDs; no fabricated semantic explanation. |
| `flow_key` / `host_key` | Optional exact observed match identity. Missing or incomplete identity prohibits disruptive action. |
| `observed_at` | Source timestamp; stale evidence cannot authorize or extend action. |

`UNCERTAIN` is a risk-engine abstention state, not an extra classifier class. It applies to explicit UNKNOWN, confidence below its validation-selected minimum, conflicting evidence, stale evidence, or an incomplete result. The **risk engine** maps a valid result to risk/action and records reason codes. The **mitigation adapter** executes only that approved, scoped action and reports success/failure. Detection never calls Ryu or directly causes BLOCK.

The existing `DecisionRecord` and `DetectionPort` do not implement this separation: `DetectionPort.assess` currently returns a decision-shaped object containing risk/action. Stage 7 implementation must introduce a separate detection result and policy decision contract without changing frozen Stage 5/6 artifacts.

## 3. Pre-registered uncertainty and risk policy

The policy uses validation-selected confidence cutoffs, not values selected after final evaluation. For a binary RF, `p_attack` is the sum of attack-class probabilities (or the Attack probability in Stage 5F). On a disjoint calibration partition, freeze three cutoffs before test execution:

- `τ_rate`: lowest score-group boundary whose benign action rate is at most **5%**.
- `τ_quarantine`: lowest score-group boundary whose benign action rate is at most **1%**.
- `τ_block`: lowest score-group boundary whose benign action rate is at most **0.1%**.

The whole tied score group is treated together. If no nontrivial cutoff meets a budget, use the conservative no-action cutoff and report that the operating point is unattainable. Store numeric cutoffs, calibration identity, and achieved benign rates in a signed/frozen pre-test manifest. Test labels/scores are inaccessible to calibration. These are operating constraints, not claims of optimality.

Risk state/action mapping:

| Risk | Required evidence rule | Default action |
|---|---|---|
| LOW | Benign; score below `τ_rate`; distribution-shift signal alone; or insufficient/stale/unscoped evidence. | MONITOR |
| MEDIUM | Attack score at/above `τ_rate` but not meeting HIGH evidence; or repeated UNKNOWN/UNCERTAIN with a complete scoped identity. | RATE_LIMIT, only if a verified meter/action adapter supports it; otherwise MONITOR. |
| HIGH | Attack score at/above `τ_quarantine` plus at least one independent scenario/flow corroborator; or at/above `τ_block` without the stronger VERY HIGH evidence. | QUARANTINE, flow-scoped; otherwise MONITOR. |
| VERY HIGH | Attack score at/above `τ_block`, same scoped identity flagged in at least two consecutive 2-second observations, and independent corroborating evidence. No protected-flow match. | BLOCK, exact flow scope only. |

Confidence is the primary model signal. A novelty signal alone can raise a result no higher than MEDIUM; novelty does not prove malice. Distribution shift alone never increases risk or action severity. `UNCERTAIN` is capped at MEDIUM and can only reach RATE_LIMIT after repeated, scoped evidence; otherwise it maps to MONITOR. If h1↔h3 protected traffic is matched, or exact action scope cannot be constructed, the action is MONITOR. Asset importance is not scored; only the fixed lab protected-flow declaration is used.

The two corroborators must have distinct provenance (for example model score plus a scenario/fixture event); duplicated copies of one signal do not count twice. For current Stage 3 runs, scenario evidence is limited to the documented local fixture/agent events and Ryu/OVS observations. If a scenario-specific signal is not actually emitted, it is unavailable and must not be inferred.

## 4. Four policy conditions

All four policies receive the same frozen DetectionResult stream, thresholds, scenario order, and exact action scope. The labels below define policy behavior, not model classes.

| Policy | Frozen decision rule |
|---|---|
| **A — Always Block** | `ATTACK` → immediate exact-flow BLOCK, independent of confidence. BENIGN/UNCERTAIN/UNKNOWN → MONITOR. This is the intentionally unsafe comparator; TTL and scope limits still apply. |
| **B — Confidence-based** | Use only `p_attack` and `τ_rate/τ_quarantine/τ_block`: below `τ_rate` MONITOR; `[τ_rate, τ_quarantine)` RATE_LIMIT; `[τ_quarantine, τ_block)` QUARANTINE; at/above `τ_block` BLOCK. BENIGN/UNCERTAIN/UNKNOWN without a numeric attack score → MONITOR. |
| **C — Risk-aware** | Apply the risk table in §3 using confidence plus available independent evidence, persistence, novelty, shift, and protected-flow state. Missing context never escalates. Actions have fixed TTL and expire; no automatic extension. |
| **D — Risk-aware + reversible** | Same risk decision as C, plus midpoint re-evaluation, immediate rollback on changed/stale evidence, and at most one conditional extension. Exact lifecycle is §5. |

Policy A is a comparison baseline, not a recommended operating mode. Policy C is bounded even though D adds active re-evaluation. No policy parameters may be changed after final evaluation begins.

## 5. Bounded, reversible action lifecycle

All disruptive actions are local Mininet-only, logged before/after execution, exact-flow or explicitly fixed ingress-port scoped, and cookie-tagged for deletion. No switch-wide, controller-wide, arbitrary-target, physical-network, or permanent rule is allowed. If the required OpenFlow match/action is unavailable, degrade to MONITOR.

| Action | Initial TTL | Midpoint check (Policy D) | Maximum total duration |
|---|---:|---:|---:|
| RATE_LIMIT | 30 seconds | 15 seconds | 60 seconds |
| QUARANTINE | 15 seconds | 7.5 seconds | 30 seconds |
| BLOCK | 10 seconds | 5 seconds | 20 seconds |

The test harness sets Ryu observation polling to 2 seconds. At midpoint, extend once for one original TTL only if the same exact flow remains ATTACK at its frozen tier, fresh corroboration remains present, the flow is not protected, and the action adapter confirms the first rule is active. BENIGN, UNCERTAIN/UNKNOWN, stale/missing evidence (>5 seconds), identity mismatch, protected-flow match, or scenario completion causes immediate exact-rule rollback. If no valid re-evaluation arrives, the rule expires without extension. Policies A–C also use the initial TTL and expire without extension.

On installation failure: log and alert, do not escalate or broaden scope. On rollback failure: issue one exact-cookie delete retry, log/alert failure, stop the current scenario, then tear down Mininet/OVS test state; never flush unrelated flows. Cleanup runs on normal completion, timeout, controller loss, or exception. Expiry and cleanup are independently verified from OVS state. An action that cannot be proven reversible is not eligible for automation.

Rate limiting is permitted only after OVS meter support and exact meter removal are verified; current Stage 2 code does not implement meters. Quarantine/block require an explicitly reviewed match and cookie. Stage 2 currently installs only forwarding/test rules and has no such mitigation adapter.

## 6. Adaptation gate and update safety

Stage 5F is a frozen offline source/distribution-shift experiment; its results and protocol remain untouched. Stage 7 does not convert its PSI signals directly into actions or retraining. The new defense gate is a distinct policy:

1. **Detect input shift:** use the frozen Stage 5F PSI signal (`PSI ≥ 0.20` on at least 5 of 77 features) only as a source/window distribution-shift signal. Its known tendency to signal every Stage 5F evaluation window is recorded as a reason it cannot alone authorize updates.
2. **Check behavior evidence:** after labels mature, compute macro F1, attack FNR, benign FPR, UNKNOWN/UNCERTAIN rates on the completed window. Require a pre-registered degradation (macro F1 decline >0.05 or benign FPR increase >0.02 versus initial validation) **or** a validation-calibrated out-of-control uncertainty/unknown rate. Current-window labels are unavailable to this check.
3. **Check eligibility/value:** require one-window label release, verified labels, and a deterministic bounded buffer. If labels are unavailable, HOLD. Estimate update cost from measured fitting/resource cost; do not use a post-test scalar utility to justify updating.
4. **Fit candidate:** reuse the Stage 5F bounded retraining procedure, clearly as a separate Stage 7 run: at most 100,000 deterministically selected rows, one-window delay, no current/future labels, no sealed-anchor data. Keep model/configuration and split identities fixed.
5. **Validate/promote:** validate candidate on a deterministic held-out portion of eligible matured data and the sealed initial anchor. Reject if anchor macro F1 falls by >0.05 or anchor benign FPR rises by >0.02 relative to the initial model; also reject if recent held-out validation fails to improve the pre-registered primary objective without exceeding its benign-FPR constraint. Promotion/rollback is logged. W4 labels remain evaluation-only in the Stage 5F schedule; no terminal update.

This gate distinguishes shift detection, adaptation decision, candidate fitting, validation, and promotion. It does not claim concept drift. Numeric uncertainty control limits are selected on the calibration partition and frozen before final test.

## 7. Controlled scenario mapping

Only the fixed Stage 3 topology and bounds are permitted. Actions below are candidates subject to §3–5 and available exact scope; they are not assumptions that the current controller detects the scenario.

| Scenario | Available observable evidence | Safe first response | Escalation | Rollback/cleanup |
|---|---|---|---|---|
| ARP spoofing | Fixed h1 ARP-table before/during/after; bounded agent event; Ryu packet-in MAC/port observations where emitted. Current typed flow stats do not expose ARP sender protocol address. | MONITOR; no inference from a MAC change alone. | At most exact h2 ingress/ARP scope quarantine if conflicting fixed h3 mapping is independently confirmed and adapter can match it; otherwise no escalation. | Restore h1 neighbor entry, verify h3 mapping/reachability, delete exact temporary rule, stop sender. |
| DHCP starvation | Local fixture request/lease log, DHCP flow counters and scenario identity. No external DHCP service. | MONITOR or bounded h2→fixture RATE_LIMIT if meter verified. | QUARANTINE only after repeated bounded requests and confirmed pool pressure; never exhaust beyond the Stage 3 four-address fixture. | Stop clients/fixture, reset leases/pool, exact rule rollback, verify service is no longer listening. |
| Port scanning | Fixed h2→h3 probes, allowlisted destination ports, OVS/Ryu flow counters, probe outcome log. | MONITOR; then RATE_LIMIT exact source/destination/port set if supported. | QUARANTINE only on repeated confirmed probes; BLOCK only if all VERY HIGH requirements are met. | Stop probe agent; delete scenario rules; confirm h1↔h3 baseline. |
| SYN flooding | Bounded h2→h3:18080 sender event and counters. Current Ryu stats do not count TCP SYN flags. | RATE_LIMIT exact h2→h3:18080 if meter is verified; otherwise MONITOR. | QUARANTINE/BLOCK only with corroborating scenario event and persistence; never use broad destination/service block. | Stop sender, delete exact rule/meter, verify h1↔h3 service reachability. |
| Rogue-device simulation | Existing h2 link/OVS port state, fixed MAC, Ryu port/packet-in events. This is not a real unknown device. | MONITOR and record port activation. | Temporary h2 ingress-port quarantine only if port identity is exact and the fixed protected path remains unaffected. | Stop sender, restore h2 link state, delete exact rule, verify port/reachability. |
| DNS anomaly | Local nonrecursive h3 fixture query log, fixed `.test` names, h2→h3:53 counters. Ryu does not currently expose queried names. | MONITOR or RATE_LIMIT exact client→fixture flow if supported. | QUARANTINE only for repeated local fixture evidence; do not block based on unavailable name semantics. | Stop client/fixture, clear fixture state, delete rule, verify no upstream queries and topology cleanup. |

No Internet-facing traffic, arbitrary target selection, persistence, unrestricted attack, automatic attack generation, or production asset is part of this protocol.

## 8. Evaluation design and comparison

### Offline decision-policy replay

Use the frozen CSE-SFH-A and CSE-SFH-B source memberships and Stage 5D 77-feature preprocessing/Random Forest configuration as a **new Stage 7 replay**, with outputs stored only under `experiments/stage7/`. Do not overwrite Stage 5 artifacts. Train-source predictions used for calibration are split deterministically by source and label; held-out source rows remain inaccessible until thresholds and policies are frozen. Recompute row-level scores because frozen Stage 5 reports do not contain a complete per-row score stream. Evaluate each policy on the same held-out source rows and seeds. The offline replay measures policy decisions and false-action/attack-action rates; it does **not** measure containment or mitigation latency.

### Mininet action-safety evaluation

Before any automated policy run, pass a feature-parity/correlation gate: demonstrate that the live detector consumes the same documented feature semantics and can associate each result to an exact Stage 3 flow/host scope. Current Stage 2/3 components do not pass this gate. Until then, Mininet can validate only a separately labeled adapter lifecycle test with explicit test decisions; it cannot validate ML detection or policy effectiveness. If the gate later passes, run each bounded Stage 3 scenario individually, with benign h1↔h3 protected-flow controls and Policies A–D in paired scenario blocks. The fixed topology remains isolated.

Use five deterministic repetitions per scenario-policy pair, ordered by a preregistered seed-2026 permutation within each scenario block. Keep a separate calibration partition; no final scenario repetition selects thresholds. Log configuration, input DetectionResult, policy reason, exact OpenFlow action/cookie/TTL, timestamps, OVS verification, cleanup, and deviations. A failed cleanup invalidates that run and blocks the next run until manually restored; do not silently replace it.

## 9. Metrics and cost evaluation

Detection metrics: macro F1, per-class F1, benign FPR, and attack FNR as Benign. Defense metrics: attack containment rate (only for a validated live detector/action path), containment latency, false-block rate, legitimate-flow disruption, mitigation duration, unnecessary mitigation count, rollback count, policy decision latency, and action execution latency. Resource metrics: CPU, memory, model inference latency, and explanation latency where implemented. Record unavailable measurements as unavailable; offline model metrics are not live containment evidence.

Use a **multi-objective cost table**, not an after-the-fact scalar utility with arbitrary weights:

| Benefit/cost dimension | Unit and interpretation |
|---|---|
| Attack containment | Count/rate of predeclared malicious test flows contained within the fixed response window. |
| False block | Count/rate of benign-labelled flows receiving BLOCK. |
| Legitimate disruption | Protected h1↔h3 probes failed and total seconds disrupted. |
| Response delay | Median and p95 policy-to-action and scenario-start-to-containment latency. |
| Mitigation exposure | Rule count, exact scope, duration, TTL extensions, rollback/cleanup failures. |
| Adaptation cost | Update count, fitting/inference time, CPU, peak RSS, buffer rows, and anchor regression. |

Compare the policies as a Pareto table/frontier; do not collapse trade-offs into one utility score. If a scalar is later required, weights must be elicited and frozen from supervisor/operator safety priorities before the final test set is opened, then report the full unweighted dimensions too.

## 10. Adaptation and mitigation metrics

Report per scenario, policy, seed, and run: confusion counts/primary detection metrics; attack containment and latency where end-to-end evidence exists; false blocks; benign-flow disruption; action type/scope/TTL; unnecessary actions; extension/rollback/cleanup counts; decision/action/inference/explanation timing; CPU/memory; and source/window shift/adaptation events separately. Report per-class F1 and macro F1; accuracy is contextual only. Summarize paired policy differences on identical runs with mean/SD and confidence intervals where the number and dependence structure support them. Repetitions on the same Mininet topology are repeated testbed runs, not independent real networks.

An explanation is a faithful, reproducible decision record: input result ID, contributing evidence IDs/values, risk state, policy rule/reason code, chosen action, scope, expiry, and rollback outcome. This stage does not prescribe SHAP/GNNExplainer. Test fidelity by replaying the same immutable inputs through the policy and verifying the same action/reason; test stability on identical repeated inputs. Natural-language plausibility is not a fidelity metric.

## 11. Reproducibility and stop criteria

Freeze and hash before final evaluation: Stage 5 source/prepared manifests, exact train/validation/test source membership, row-level prediction artifact, numeric validation-derived thresholds, model parameters/seeds, policy table, action TTL/match/cookie rules, protected-flow configuration, Stage 3 scenario configs, Ryu/OVS versions, software environment, and metric definitions. Keep final labels and scenario outcomes sealed until policy/threshold artifacts are frozen. Log all failed runs and deviations.

Stop before automated action evaluation if any of these fail: feature parity/correlation, exact flow/action scope, protected-flow tests, bounded TTL verification, rollback/cleanup, or threshold freeze. Stop a run on controller disconnect, unexpected external interface/traffic, protected-flow disruption, scope mismatch, or failed cleanup. Do not respond by broadening scope or relaxing thresholds.

## 12. Stage 7 feasibility decision

The **policy protocol is ready for implementation and unit testing**, but the complete autonomous-defense evaluation is **not ready to claim or run end-to-end**. The current Ryu adapter has no mitigation actions; the current detector is offline and its CICFlowMeter feature vector is not produced by Stage 2/3; stage logs do not yet correlate model scores with exact actions. The first Stage 7 implementation must therefore establish the transport-neutral detection/decision separation and a fail-closed Mininet adapter boundary, then prove feature and flow-key parity before any automated policy comparison. Until that gate passes, only offline decision replay and action-lifecycle safety tests are in scope; no security effectiveness claim is permitted.
