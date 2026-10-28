# Stage 7 real detector integration readiness

## Finding

**The current Stage 5 Random Forest is not suitable for live inference from the Stage 4 `FlowRecord` contract, and is not authorized for live autonomous mitigation.** Stage 5's CSE-CIC-IDS2018 model input is a frozen ordered vector of 77 `float32` CICFlowMeter-derived predictors. Stage 4 records are Ryu/OpenFlow flow-stat snapshots: aggregate counters and rule age plus optional match selectors. They are not equivalent bidirectional packet-flow records.

The project contains Stage 5 training configurations and result artifacts, but the inspected project tree contains no persisted trained Random Forest artifact. The evaluation runners fit models in memory. Thus there is no deployable trained estimator to load, in addition to the feature-parity blocker.

The machine-readable feature-by-feature matrix is [`stage7-real-detector-feature-compatibility.json`](stage7-real-detector-feature-compatibility.json). Its ordered predictor list is taken directly from the frozen Stage 5D preparation manifest. The compatibility assessment is conservative and does not alter any Stage 5 artifacts.

## Read-only review findings

### Stage 5 detector input

The reviewed detector is the Stage 5D CSE-CIC-IDS2018 `sklearn.ensemble.RandomForestClassifier` configuration: 100 trees, maximum depth 18, `sqrt` feature selection, minimum leaf size 2, `balanced_subsample` class weights, seed 2026, and one job. Later frozen experiments use the same 77 predictors for the CSE unseen-class RF and the Stage 5F binary source/distribution-shift RF. Stage 5F's task is binary Benign/Attack; it does not create a separate live-compatible feature schema.

The predictors are numeric CICFlowMeter columns. The Stage 5D preparation casts the prepared CSV values to `float32`, without an imputer or learned scaling transform. Stage 5 preparation documentation records as unknown the CICFlowMeter version, extraction settings, authoritative units/semantics, timestamp semantics, and cross-source capture/extraction consistency. Feature names and values alone do not fill those provenance gaps.

The Stage 5D preparation and RF results are not a model package: no serialized estimator, fitted feature transformer, or calibration artifact for Stage 7 thresholds was found in the project tree. The run configurations and scores do not permit reconstructing a trained model without fitting again, which this milestone does not do.

### Stage 4 live input

`FlowRecord` v1 represents one Ryu flow-stat snapshot. It has rule identity/provenance (`datapath_id`, table, priority, cookie, raw match), optional IP/protocol/address/port match fields, cumulative rule packet/byte counters, rule age in seconds, observation timestamp, optional TCP flags match, and an empty-counter marker. Missing selectors remain absent. Stage 4 explicitly documents that these are not packet-level bidirectional conversation records; its `tcp_flags` is a match selector when present, not observed packet flag counts.

The 77 predictors describe packet-derived directional statistics, per-packet lengths and headers, packet inter-arrival times, TCP flag counts, bulk/subflow statistics, initial TCP windows, and active/idle periods. The official [CICFlowMeter feature implementation](https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/FlowFeature.java) corroborates that these fields are features of its packet-derived flow representation. This external implementation reference does not resolve the unknown version/settings used for the acquired CSE files.

## Feature compatibility matrix

`EXACT` means equal quantity and semantics are present; `DERIVABLE` means a deterministic computation preserves meaning. `APPROXIMATION_REQUIRED` means a tempting estimate would change semantics and must not enter RF input. `UNAVAILABLE` means necessary telemetry is absent. `SEMANTICALLY_INCOMPATIBLE` means a related live field measures something different.

| Stage 5 predictor | Status | Related live field(s) | Assessment |
| --- | --- | --- | --- |
| `Protocol` | EXACT | `ip_protocol` | FlowRecord.ip_protocol is the IP protocol number; it matches CICFlowMeter Protocol when the OpenFlow match contains ip_proto. The field is optional on wildcarded/non-IP entries, so an individual record may still be rejected for a missing value. |
| `Flow Duration` | SEMANTICALLY_INCOMPATIBLE | `duration_seconds` | FlowRecord.duration_seconds is the age of an installed OpenFlow rule at the snapshot. CICFlowMeter Flow Duration describes the packet-derived bidirectional flow duration (reported in a different unit/semantic interval); converting seconds to microseconds would not make the underlying quantity equivalent. |
| `Tot Fwd Pkts` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Tot Bwd Pkts` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `TotLen Fwd Pkts` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `TotLen Bwd Pkts` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Fwd Pkt Len Max` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Fwd Pkt Len Min` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Fwd Pkt Len Mean` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Fwd Pkt Len Std` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Bwd Pkt Len Max` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Bwd Pkt Len Min` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Bwd Pkt Len Mean` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Bwd Pkt Len Std` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Flow Byts/s` | APPROXIMATION_REQUIRED | `byte_count`, `duration_seconds` | A ratio of the cumulative OpenFlow rule counter to rule age could be calculated, but rule-age and CICFlowMeter packet-flow duration boundaries differ. The result would be an approximation with changed semantics and is prohibited for RF input. |
| `Flow Pkts/s` | APPROXIMATION_REQUIRED | `packet_count`, `duration_seconds` | A ratio of the cumulative OpenFlow rule counter to rule age could be calculated, but rule-age and CICFlowMeter packet-flow duration boundaries differ. The result would be an approximation with changed semantics and is prohibited for RF input. |
| `Flow IAT Mean` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Flow IAT Std` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Flow IAT Max` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Flow IAT Min` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Fwd IAT Tot` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Fwd IAT Mean` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Fwd IAT Std` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Fwd IAT Max` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Fwd IAT Min` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Bwd IAT Tot` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Bwd IAT Mean` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Bwd IAT Std` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Bwd IAT Max` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Bwd IAT Min` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Fwd PSH Flags` | SEMANTICALLY_INCOMPATIBLE | `tcp_flags` | FlowRecord.tcp_flags, when present, is an OpenFlow match selector, not packet-level counts or directional occurrences of this flag. It cannot reproduce the CICFlowMeter flag feature. |
| `Bwd PSH Flags` | SEMANTICALLY_INCOMPATIBLE | `tcp_flags` | FlowRecord.tcp_flags, when present, is an OpenFlow match selector, not packet-level counts or directional occurrences of this flag. It cannot reproduce the CICFlowMeter flag feature. |
| `Fwd URG Flags` | SEMANTICALLY_INCOMPATIBLE | `tcp_flags` | FlowRecord.tcp_flags, when present, is an OpenFlow match selector, not packet-level counts or directional occurrences of this flag. It cannot reproduce the CICFlowMeter flag feature. |
| `Bwd URG Flags` | SEMANTICALLY_INCOMPATIBLE | `tcp_flags` | FlowRecord.tcp_flags, when present, is an OpenFlow match selector, not packet-level counts or directional occurrences of this flag. It cannot reproduce the CICFlowMeter flag feature. |
| `Fwd Header Len` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Bwd Header Len` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Fwd Pkts/s` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Bwd Pkts/s` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Pkt Len Min` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Pkt Len Max` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Pkt Len Mean` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Pkt Len Std` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Pkt Len Var` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `FIN Flag Cnt` | SEMANTICALLY_INCOMPATIBLE | `tcp_flags` | FlowRecord.tcp_flags, when present, is an OpenFlow match selector, not packet-level counts or directional occurrences of this flag. It cannot reproduce the CICFlowMeter flag feature. |
| `SYN Flag Cnt` | SEMANTICALLY_INCOMPATIBLE | `tcp_flags` | FlowRecord.tcp_flags, when present, is an OpenFlow match selector, not packet-level counts or directional occurrences of this flag. It cannot reproduce the CICFlowMeter flag feature. |
| `RST Flag Cnt` | SEMANTICALLY_INCOMPATIBLE | `tcp_flags` | FlowRecord.tcp_flags, when present, is an OpenFlow match selector, not packet-level counts or directional occurrences of this flag. It cannot reproduce the CICFlowMeter flag feature. |
| `PSH Flag Cnt` | SEMANTICALLY_INCOMPATIBLE | `tcp_flags` | FlowRecord.tcp_flags, when present, is an OpenFlow match selector, not packet-level counts or directional occurrences of this flag. It cannot reproduce the CICFlowMeter flag feature. |
| `ACK Flag Cnt` | SEMANTICALLY_INCOMPATIBLE | `tcp_flags` | FlowRecord.tcp_flags, when present, is an OpenFlow match selector, not packet-level counts or directional occurrences of this flag. It cannot reproduce the CICFlowMeter flag feature. |
| `URG Flag Cnt` | SEMANTICALLY_INCOMPATIBLE | `tcp_flags` | FlowRecord.tcp_flags, when present, is an OpenFlow match selector, not packet-level counts or directional occurrences of this flag. It cannot reproduce the CICFlowMeter flag feature. |
| `CWE Flag Count` | SEMANTICALLY_INCOMPATIBLE | `tcp_flags` | FlowRecord.tcp_flags, when present, is an OpenFlow match selector, not packet-level counts or directional occurrences of this flag. It cannot reproduce the CICFlowMeter flag feature. |
| `ECE Flag Cnt` | SEMANTICALLY_INCOMPATIBLE | `tcp_flags` | FlowRecord.tcp_flags, when present, is an OpenFlow match selector, not packet-level counts or directional occurrences of this flag. It cannot reproduce the CICFlowMeter flag feature. |
| `Down/Up Ratio` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Pkt Size Avg` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Fwd Seg Size Avg` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Bwd Seg Size Avg` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Fwd Byts/b Avg` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Fwd Pkts/b Avg` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Fwd Blk Rate Avg` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Bwd Byts/b Avg` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Bwd Pkts/b Avg` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Bwd Blk Rate Avg` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Subflow Fwd Pkts` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Subflow Fwd Byts` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Subflow Bwd Pkts` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Subflow Bwd Byts` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Init Fwd Win Byts` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Init Bwd Win Byts` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Fwd Act Data Pkts` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Fwd Seg Size Min` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Active Mean` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Active Std` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Active Max` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Active Min` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Idle Mean` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Idle Std` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Idle Max` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |
| `Idle Min` | UNAVAILABLE | — | The current FlowRecord has no packet-level bidirectional flow aggregation for this quantity. No value can be produced from current fields without introducing new telemetry or changing feature semantics. |

### Compatibility totals

| Status | Feature count |
| --- | ---: |
| EXACT | 1 |
| DERIVABLE | 0 |
| APPROXIMATION_REQUIRED | 2 |
| UNAVAILABLE | 61 |
| SEMANTICALLY_INCOMPATIBLE | 13 |

`Protocol` is an exact representation when an IP protocol match is present, but the FlowRecord field is optional on wildcarded/non-IP rules. That one feature does not establish a usable vector. Two rates could be calculated by dividing a rule's cumulative counters by rule age, but that changes the temporal boundary from CICFlowMeter's packet-defined flow to OpenFlow rule lifetime; these are classified `APPROXIMATION_REQUIRED`, not usable values. No feature was classified `DERIVABLE` because the current contract provides no additional source quantity with unchanged semantics.

## Decision and safe boundary

**Selected option: D — the Stage 5 RF remains offline-only; Stage 7 needs a separate live-detector protocol or a separately justified feature/telemetry bridge.** The current 77-feature RF cannot consume Stage 4 data with verified semantic parity. Even if future packet capture or flow aggregation made those features computable, parity would require documented unit/definition verification against the actual extractor configuration; that provenance is currently unknown.

The existing `DetectionResult` contract is already shared by synthetic fixtures and downstream policy. It can carry classification, confidence, separate novelty score/state, separate source/window shift state, evidence references, scope, timestamp, model identity, and provenance. No duplicate real-result contract or adapter was added. `synthetic_test_fixture_only` remains the synthetic provenance marker. No real result was created, and no model identity/version is asserted.

No detector adapter, inference path, or observation-only service was implemented. That is intentional: an observe-only path would still require valid model inputs and would otherwise hide the parity failure. The feature gate added for this milestone rejects live inference whenever any feature is not `EXACT` or `DERIVABLE`; it does not extract, impute, approximate, fit, or call a model. The policy/orchestrator is therefore not invoked by this compatibility layer, and no mitigation is authorized.

## Confidence, novelty, and source/distribution shift

The frozen Stage 7 protocol requires validation-calibrated attack-score thresholds meeting benign action-rate bounds (5% for RATE_LIMIT, 1% for QUARANTINE, 0.1% for BLOCK), frozen before final test. This repository review found no real-detector calibration artifact providing Stage 7 thresholds. The numeric thresholds in Stage 7 synthetic integration fixtures are explicitly test-only and must not be reused. The Stage 5E.2C confidence rejection threshold belongs to its offline CSE unseen-source experiment, not a live Stage 7 calibration. **No live action threshold is currently authorized.**

Known-class prediction/confidence, novelty/UNKNOWN, and PSI/source-window shift remain distinct signals. Stage 5E.2A assigned 99.8631% of the unseen LOIC-HTTP test flows to Benign in its closed-set evaluation. Stage 5E.2B reported 0% LOIC-HTTP unknown recall at its primary operating point; Stage 5E.2C reported 0.053628% unknown recall at approximately 1% validation benign rejection. These are frozen offline results, not live performance evidence. Stage 5F reported PSI signals in all evaluated source windows; PSI alone remains insufficient to authorize adaptation or risk escalation under the frozen protocol.

## Tests and scope

Unit tests validate that the matrix exactly follows the frozen 77-name manifest, status totals agree, the fail-closed gate rejects incompatible inputs, and the shared `DetectionResult` contract preserves provenance and separates confidence, novelty, and shift fields. Those contract tests do not represent inference results.

This milestone did not run traffic, load or train a model, alter data, tune thresholds, invoke the policy/orchestrator, execute mitigation, or run a final research experiment. The next defensible step requires a separately reviewed live-compatible detector protocol and an evidence-backed feature source; it must not silently repurpose Stage 5 CICFlowMeter columns.
