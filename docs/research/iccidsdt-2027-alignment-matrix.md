# ICCIDSDT-2027 Paper Alignment and Evidence Matrix

**Audit date:** 2026-10-21  
**Purpose:** Align the proposed paper with the conference page, repository evidence, and the current system boundary. This document is an audit and revision guide; it does not create new research results.

## Conference requirements

The [official ICCIDSDT-2027 page](https://manuu.edu.in/ICCIDSDT2027/) identifies the event as the **2nd International Conference on Computational Intelligence, Data Science, and Digital Transformations (ICCIDSDT-2027)**, scheduled for January 22–23, 2027 at MANUU, Hyderabad. The page directs authors to submit through CMT by selecting ICCIDSDT-2027.

| Requirement | Official page states | Action/status |
|---|---|---|
| Relevant tracks | Advanced Network Technologies and Cybersecurity; Computational Intelligence and Machine Learning; Data Science, Big Data, and Analytics | Strongest fit: cybersecurity/network monitoring, with supporting fit to explainable AI and data quality. |
| Full paper deadline | The Important Dates block lists **October 31, 2026** for full-paper submission, with a nearby **September 30, 2026** date also displayed in the same block. | Use October 31 as the working deadline as instructed; confirm deadline and CMT close time/time zone in the portal. |
| Abstract | Maximum **400 words** | Keep at or below 400; count with the submission system's rules. |
| Manuscript length | At least **10 pages** to be considered for review/publication; camera-ready maximum **12 pages** | Plan for 10–12 pages in the official template. The page-count rule for initial submission versus camera-ready should be confirmed if ambiguous. |
| Format | Official Word and LaTeX templates are linked from the page | Download the current ICCIDSDT-2027 template from the conference page/CMT and preserve its styles. Template files were not present in this repository. |
| Similarity | Papers with similarity **more than 10%** will not appear in proceedings | Treat 10% as a strict upper boundary; verify the organizer's similarity tool and exclusions. This is not a substitute for citation review. |
| Publication outlet | Selected and presented papers are stated to appear in ICCIDSDT-2027 proceedings in **Lecture Notes in Networks and Systems (LNNS)** | Do not promise acceptance or indexing. The site lists indexing services, but publication/indexing remains subject to selection and publisher/indexer processes. |
| Camera-ready date | Important Dates lists **November 20, 2026**; camera-ready instructions say submit by **November 15, 2026** | **Unresolved official-page discrepancy. Obtain written organizer confirmation. Do not choose one date silently.** |

The title in the official page header shortens the acronym to “ICCIDST 2027” in one heading, while the full event name and paper-submission instructions use ICCIDSDT-2027. Use the full name/acronym from the page and portal listing.

## Paper positioning

**Proposed title:** *From Offline Intrusion Detection to Verifiable SDN Defense: A Measurement Study of Source-Shift Adaptation, Feature Compatibility, and Bounded Enforcement*

**Central question:** When an intrusion detector is developed on public datasets, what must be verified before its performance and decisions can be trusted in a live SDN defense system?

The paper should present three linked deployment questions but keep their evidence and experiments separate:

| Research question | Evidence source | Defensible result | Boundary |
|---|---|---|---|
| RQ1. Under the frozen CSE-CIC-IDS2018 source-window protocol, how do static, periodic, and PSI-triggered updates compare? | Stage 5F frozen protocol/results and seven prepared source files | Report per-window macro F1, per-class F1, benign FPR, attack FNR, update events, and cost, with all 20 PSI window checks signaled. | Source/distribution-shift evaluation only. The imposed source order is not chronological, and it does not establish temporal concept drift. |
| RQ2. How much of the offline predictor schema is semantically reproducible from the live SDN observations, and what live-native inputs are actually supported? | Stage 5 feature schema; Stage 4 FlowRecord; Stage 7 telemetry artifacts; Stage 7I compatibility and v1 feature-builder contracts/tests | The current 77-feature RF input lacks parity; the audit counts 1 EXACT, 0 DERIVABLE, 2 APPROXIMATION_REQUIRED, 61 UNAVAILABLE, 13 SEMANTICALLY_INCOMPATIBLE. A four-value rule-counter schema and offline synthetic builder are specified/implemented. | The four-feature builder was tested synthetically; neither the builder nor packet observation is validated as a trustworthy live training pipeline. |
| RQ3. Can bounded SDN actions be independently verified, expired, and rolled back? | Stage 7 live Mininet/OVS/Ryu validation and adapter/orchestrator reports | Exact-scope BLOCK installation and OVS-state confirmation, target/non-target traffic behavior, TTL, and rollback were verified in the isolated testbed. | Synthetic detections drove integration validation. No real detector produced or authorized an action. Rate limiting remains unsupported. |

### Contribution statement

Use a contribution statement bounded to **measurement of evidence continuity and deployment constraints across separate offline-learning, live-observation, and enforcement studies**. Do not claim that combining SDN, ML, XAI, or adaptation is itself novel. The contribution's novelty relative to prior work remains a hypothesis until a reference-level literature audit is completed. No measured explanation fidelity or end-to-end explainable defense result exists.

## Section-to-evidence alignment

| Paper section | Content to include | Primary repository evidence | Status and corrective action |
|---|---|---|---|
| Abstract and keywords | Three separate RQs, frozen offline study, telemetry compatibility gap, independently verified mitigation substrate; no single combined detector trial | Stage 5B–F results; Stage 7 docs; Stage 7I docs | Draft after all figures/tables are fixed; ≤400 words. Avoid “autonomous defense achieved.” |
| 1. Introduction and research questions | Motivation: benchmark results do not imply live feature parity or verified enforcement. State RQ1–RQ3 and boundaries. | This matrix; protocols below | Keep the central argument about evidence continuity; do not present the system as a complete deployed appliance. |
| 2. Related work and contribution | SDN IDS, dataset shift/adaptation, explainability, safe/reversible mitigation; compare precise method/evidence, not buzzword combinations | No manuscript or verified bibliography found | Audit every cited source against the original publication. A novel-contribution claim is unresolved until this is done. |
| 3. System and evaluation boundaries | Diagram with labels: implemented; live-testbed validated; synthetic-only; proposed; deferred. Separate offline Stage 5 and live SDN plane. | `docs/architecture/stage7-live-enforcement.md`; `docs/research/live-feature-compatibility-audit.md`; `docs/research/live-feature-builder.md`; Stage 6 feasibility docs | No diagram should show Stage 5 RF connected to live Ryu/OVS. Mark packet observation unfrozen and GraphSAGE deferred. |
| 4. Dataset audit and methods | Dataset provenance, label/split boundaries, 77-feature CSE schema, UNSW official train/test baseline, reciprocal CSE source holdouts, LOIC open-set protocol, source-window 5F protocol | `docs/research/dataset-audit/stage5a-dataset-audit.md`; `stage5b-baseline-protocol.md`; `stage5c1-cse-protocol.md`; `stage5d-preparation.md`; `stage5e2c-rf-open-set.md`; `stage5f-drift-adaptation-protocol.md`; machine-readable experiment JSON | Describe each protocol independently. Do not pool metrics or treat rows/seeds as independent captures. |
| 5. Source-window adaptation results | Static vs periodic vs PSI-triggered, all W1–W4 rows, relevant per-class metrics and false rates, update/cost table | `docs/research/stage5f-source-distribution-shift-results.md`; `experiments/stage5f/source-distribution-shift-results.json` | Report PSI triggered on 20/20 evaluated windows; emphasize its lack of selectivity. Say source/distribution shift, not concept drift. |
| 6. Offline-to-live compatibility and telemetry observability | Feature-by-feature compatibility count; distinguish rule counters from packet flows; validated generic telemetry and failed/unfrozen packet observation | `docs/research/live-feature-mapping.csv`; `live-feature-compatibility-audit.md`; `live-feature-contract-v1.md`; `live-feature-builder.md`; `stage7-attack-observability-audit.md`; packet observation repeatability and B1 forensic audit | State packet scan partial observability: eight probes generated, one destination port appeared in generic PacketIn; later mirror B1 violated the requested 54-byte bound for 33/37 IPv6 frames and selection was unresolved. Do not claim consistent complete scan visibility. |
| 7. Independent SDN enforcement validation | Exact scope, SUBMITTED vs CONFIRMED semantics, independent OVS verification, unrelated-flow preservation, TTL, rollback, protected flow | `docs/architecture/stage7-live-enforcement.md`; Stage 7 test/report artifacts | Call it enforcement-substrate validation. Synthetic fixture integration is not real-detector-to-mitigation validation. State RATE_LIMIT unsupported. |
| 8. Limitations and implications | No RF model artifact/live parity; no live-native dataset/model; coverage, packet observer, Eventlet warning; no explanation-fidelity tests; no dashboard/database/hardware claim; GraphSAGE deferred | Compatibility, telemetry, B1, stage plan | Make unknowns explicit. No live detector or end-to-end defense claim. |
| 9. Conclusion and references | Summarize what was measured vs what remains blocked | All above | Verify original references; remove unverified citations, placeholders, internal comments and author-check notes. |

## Evidence ledger for numerical claims

Use source artifacts as the numerical authority. Include values only with the associated protocol, split, metric, and limitation.

### Stage 5B — UNSW-NB15

- **Artifact/protocol:** `experiments/stage5b/unsw-nb15-official-baselines.json`, `experiments/stage5b/config.json`, and `docs/research/dataset-audit/stage5b-baseline-protocol.md`.
- **Dataset/split:** official UNSW-NB15 train/test files; seeded stratified validation is drawn only from official training data; official test remains held out.
- **RF:** 10-class classification; accuracy **0.674124**, macro-F1 **0.487591**, weighted-F1 **0.727194**. Benign FPR **0.412568**; attack-as-benign FNR **0.006000**. Do not summarize these as “strong detection”: low macro-F1 and high benign FPR are material.
- **Isolation Forest:** a separate binary benign-vs-attack novelty baseline, not a multiclass RF comparison. Accuracy **0.629767**, macro-F1 **0.613405**, benign FPR **0.070432**, attack FNR **0.614930**. Keep task distinction explicit.
- **Limit:** one dataset's official split; not cross-dataset generalization or live inference.

### Stage 5D — CSE-CIC-IDS2018 source-file holdout

- **Artifact/protocol:** `experiments/stage5d/cse-source-holdout-rf.json`, `experiments/stage5c1/cse-protocol.json`, and `docs/research/dataset-audit/stage5d-source-holdout-results.md`.
- **Split:** reciprocal source-file holdouts A and B, not random row splits; same 77-feature RF configuration as Stage 5B. Test rows are overwhelmingly benign and only a small set of attack labels appear in each test file.
- **A:** accuracy **0.995351**, union-of-supported-or-predicted-labels macro-F1 **0.259719**, test-supported macro-F1 **0.519438**, weighted-F1 **0.997353**, benign FPR **0.004384**, attack-as-benign FNR **0.409894**.
- **B:** accuracy **0.990413**, union macro-F1 **0.199560**, test-supported macro-F1 **0.399120**, weighted-F1 **0.994907**, benign FPR **0.009510**, attack-as-benign FNR **0.138122**.
- **Limit:** no within-source reference split is defined by the frozen protocol; no source generalization gap can be computed. High accuracy/weighted F1 do not resolve minority-class errors or unsupported test labels.

### Stage 5E — held-out LOIC-HTTP open-set

- **Artifact/protocol:** `experiments/stage5e/cse-unseen-loic-http-rf-open-set.json`, corresponding closed-set and Isolation Forest JSON, and `docs/research/dataset-audit/stage5e2a-closed-set-unseen-class.md`, `stage5e2b-novelty-detection.md`, `stage5e2c-rf-open-set.md`.
- **Split:** Tuesday CSE source held out; LOIC-HTTP absent from training class vocabulary. Confidence threshold selected from benign validation only; primary target 1% validation benign rejection.
- **RF rejection result:** 576,191 LOIC-HTTP rows; unknown recall **0.053628%** (309 rejected), known rate **99.946372%**; test benign rejection/FPR **1.309813%**; unknown precision **0.321550%**; unknown F1 **0.000919**. Closed-set RF called **99.8631%** of those flows benign. Isolation Forest's primary 1% operating point gave **0.000000%** LOIC unknown recall.
- **Interpretation:** negative open-set finding. Do not call this successful zero-day or unknown-attack detection.

### Stage 5F — source/distribution windows

- **Artifact/protocol:** `experiments/stage5f/source-distribution-shift-results.json`, `experiments/stage5f/drift-adaptation-protocol.json`, and the Stage 5F results/protocol documents.
- **Design:** five algorithmic seeds on the same finite source files; imposed order W1–W4 is not chronological. Same 77-feature offline RF. PSI reference/bin edges use initial-fit data; later-window labels are evaluation-only until eligible under the frozen delayed-label rule.
- **Macro-F1 (static / periodic / PSI-triggered):** W1 **0.420611 / 0.420611 / 0.420611**; W2 **0.499826 / 0.499826 / 0.499826**; W3 **0.482392 / 0.483865 / 0.483865**; W4 **0.499886 / 0.508761 / 0.570637**. Include per-class F1 and benign FPR / attack FNR alongside these aggregate values in the actual paper table.
- **False-rate context:** W4 attack FNR was **1.000000 / 0.928177 / 0.097238**, while benign FPR was **0.000108 / 0.002428 / 0.003732** respectively. This is an observed source-window result, not a live operating point.
- **Trigger/cost:** PSI triggered on **20/20** evaluated seed-window combinations (W1–W4 × five seeds), despite **0/5** initial-validation false alarms. Periodic updates: 5 attempted/accepted; PSI-triggered: 10 attempted/accepted; no rollback. Mean release-to-fit completion was **26.462 s** periodic (5 updates) and **50.889 s** triggered (10 updates). Peak process RSS **2,283,622,400 bytes**; CPU utilization and whole-experiment wall time were not recorded.
- **Limit:** this measures performance on defined source windows and source/distribution shifts. It does not establish temporal concept drift or PSI selectivity.

### Stage 7 — observation and enforcement

- **Generic live telemetry:** `experiments/stage7-telemetry/live-2026-10-08-03/collection-summary.json` records 20 flow collections, 34 snapshots, 42 ObservationWindows, 53 telemetry observations, seven connection boundaries, four run boundaries, and zero incomplete runs across two controlled runs. Port-scan journal: eight probes; Ryu PacketIn exposed one TCP probe destination port (22). L2 rule counters aggregated traffic and did not disclose the full scanned-port set. This supports **partial observability, insufficient for defensible scan detection**.
- **Mirror packet observation:** the single 54-byte no-options IPv4/TCP header test is narrow. The later B1 repeatability attempt found 33 of 37 IPv6 frames exceeded 54 bytes and selection provenance was unresolved; campaign stopped before any scan repetition. Packet-observation foundation remains **unfrozen**. Never use the initial 8/8 single scan copy result without this qualifier.
- **Enforcement:** the isolated OVS/Ryu validation independently observed exact-cookie/scope/drop rule state, tested target and unrelated traffic, expiry, protected-flow rejection and rollback. It establishes a bounded enforcement substrate. A synthetic DetectionResult fixture was used for synthetic integration; the RF was not connected and did not authorize the real OVS action.

## Claims to remove or qualify

| Unsupported or risky phrasing | Corrective action |
|---|---|
| “The system detects zero-day attacks” | Replace with the negative LOIC-HTTP open-set result and its validation-calibrated threshold context. |
| “PSI detects concept drift” | Say PSI flagged all 20 defined source-window checks. PSI is feature-distribution change evidence, not proof of concept drift or label-conditional change. |
| “The RF operates on live Ryu flows” | Remove. It remains offline-only; 77-feature semantic compatibility is not established and model artifact is unavailable. |
| “FlowRecord is a network flow record equivalent to CICFlowMeter” | Replace with “OpenFlow rule-stat snapshot”; explicitly distinguish aggregate rule counters from bidirectional packet flow records. |
| “The live detector blocks attacks” / “end-to-end autonomous defense validated” | Remove. Only synthetic detection fixtures reached the validated enforcement substrate; no real detector result authorized mitigation. |
| “All scan ports are reliably visible” | Remove. Generic PacketIn saw one of eight; a separate one-off packet-copy run is qualified by the later B1 failure and is not frozen. |
| “Explainable AI explains the actions faithfully” | Remove unless a faithfulness/stability evaluation exists. Explainability fidelity has not been measured. |
| “GraphSAGE comparison” | Remove; GraphSAGE is deferred and was not evaluated. |
| “Dashboard/database/hardware alerting is implemented” | Remove unless current implementation and validation artifacts establish each component. |

## Manuscript availability and work required

A workspace search on 2026-10-21 found no conference manuscript (`.docx`, `.tex`, `.odt`, or manuscript PDF) and no ICCIDSDT template file. `docs/report/README.md` only describes that directory's purpose. Therefore this audit cannot responsibly revise the paper, verify its references, remove author-check notes, validate diagrams, or establish its page count. Supply the current manuscript and official template/source before those edits. No manuscript was created or edited by this task.

## References and organizer confirmations before submission

1. Use the official event page and CMT entry to confirm full-paper cutoff/time zone and current template version.
2. Email the organizers to resolve the November 15 vs November 20 camera-ready dates and ask whether the 10-page minimum applies to the initial submission.
3. Verify every reference against the original paper/publisher page; remove references that cannot be verified. The manuscript/bibliography was unavailable, so this reference audit remains pending.
4. Ensure the 10–12 page final paper is not padded with unrelated hardware/dashboard or speculative architecture content.

