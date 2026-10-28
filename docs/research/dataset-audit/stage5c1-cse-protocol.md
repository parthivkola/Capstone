# Stage 5C.1 — Frozen CSE-CIC-IDS2018 Protocol

**Status: frozen protocol; no model was trained.** Stage 5A, 5B, and 5C artifacts and all raw CSE files are inputs only and remain unchanged. This document freezes preprocessing and source-file evaluation decisions for later implementation.

## 1. Data sources and integrity

The ten original CSE-CIC-IDS2018 CSVs remain separate source groups. Their relative paths, Stage 5A SHA-256 values, row/column counts, label counts, and audit observations are recorded in [`cse-protocol.json`](../../../experiments/stage5c1/cse-protocol.json). Raw files are immutable. The Stage 5A audit reports no missing cells in these files; it does report non-finite feature cells and repeated header rows in three files.

Files with repeated headers, excluded from the two frozen configurations, are Friday 16-February, Thursday 1-March, and Wednesday 28-February. They are not silently moved into either train or test group. The two configurations use only their explicitly listed source files.

## 2. Frozen common schema

The model-ready schema is the common **80-column ordered schema** below. The 20-February source has four additional raw columns—`Flow ID`, `Src IP`, `Src Port`, and `Dst IP`. Its reader must explicitly project to this ordered 80-column schema; these source-only fields do not enter model-ready rows. Projection creates derived records only; the raw file is retained unchanged.

```text

Dst Port, Protocol, Timestamp, Flow Duration, Tot Fwd Pkts, Tot Bwd Pkts, TotLen Fwd Pkts, TotLen Bwd Pkts, Fwd Pkt Len Max, Fwd Pkt Len Min, Fwd Pkt Len Mean, Fwd Pkt Len Std, Bwd Pkt Len Max, Bwd Pkt Len Min, Bwd Pkt Len Mean, Bwd Pkt Len Std, Flow Byts/s, Flow Pkts/s, Flow IAT Mean, Flow IAT Std, Flow IAT Max, Flow IAT Min, Fwd IAT Tot, Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max, Fwd IAT Min, Bwd IAT Tot, Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd IAT Min, Fwd PSH Flags, Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags, Fwd Header Len, Bwd Header Len, Fwd Pkts/s, Bwd Pkts/s, Pkt Len Min, Pkt Len Max, Pkt Len Mean, Pkt Len Std, Pkt Len Var, FIN Flag Cnt, SYN Flag Cnt, RST Flag Cnt, PSH Flag Cnt, ACK Flag Cnt, URG Flag Cnt, CWE Flag Count, ECE Flag Cnt, Down/Up Ratio, Pkt Size Avg, Fwd Seg Size Avg, Bwd Seg Size Avg, Fwd Byts/b Avg, Fwd Pkts/b Avg, Fwd Blk Rate Avg, Bwd Byts/b Avg, Bwd Pkts/b Avg, Bwd Blk Rate Avg, Subflow Fwd Pkts, Subflow Fwd Byts, Subflow Bwd Pkts, Subflow Bwd Byts, Init Fwd Win Byts, Init Bwd Win Byts, Fwd Act Data Pkts, Fwd Seg Size Min, Active Mean, Active Std, Active Max, Active Min, Idle Mean, Idle Std, Idle Max, Idle Min, Label
```

`Label` is the target, not a feature. Label strings are preserved exactly; this protocol does not normalize capitalization, spelling, or attack names.

## 3. Row-quality decisions

### Repeated header rows

A parsed CSV data row is a malformed repeated header if and only if its cells exactly equal that source CSV's ordered header, cell for cell. Exclude each such row from model-ready data. Do not trim, normalize, or coerce cells before comparison. Stage 5A identified 1 repeated row in Friday 16-February, 25 in Thursday 1-March, and 33 in Wednesday 28-February (59 total). None of the source files selected in holdouts A/B has an audited repeated header row. Raw files remain unchanged.

### Non-finite values

After projecting each row to the common schema, inspect numeric common-schema feature cells (excluding the `Label` target). If any is NaN, positive infinity, or negative infinity, exclude that entire row. Do not impute or replace non-finite values. A legitimate finite zero is retained. Record per-file input rows, repeated-header rows, NaN-affected rows, infinity-affected rows, their union, and retained rows; Stage 5A cell totals are not row totals, so affected-row counts are not inferred here.

Stage 5A reports zero missing cells for the CSE files. If future preparation finds an ordinary missing token outside the NaN/Inf cases, stop and report it for a separate policy decision; do not silently impute or discard it under this protocol.

Exact duplicates are not automatically removed. Report duplicate counts per source file. This is independent of repeated-header exclusion.

## 4. Primary feature policy

Exclude these fields from primary model features:

| Field | Decision and rationale |
| --- | --- |
| `Label` | Target value; never a predictor. |
| `Flow ID` | Flow identifier, present only in the 20-February source; not part of the common schema. |
| `Src IP` | Endpoint identity can encode host/capture/attack identity; 20-February-only and excluded by common projection. |
| `Dst IP` | Endpoint identity can encode host/capture/attack identity; 20-February-only and excluded by common projection. |
| `Timestamp` | Can encode capture day/time and source identity; exclude to prevent temporal/source shortcut leakage in this source-file holdout. |
| `Dst Port` | Conservative exclusion: can act as a service/attack shortcut and Stage 5A flags it as identifier-like. Retention would require a separately documented justification and protocol revision. |

`Src Port` is also absent from the common schema and is projected out as a source-only 20-February field. `Protocol` and aggregate packet/flow statistics remain eligible candidates, subject to this policy and later feature manifest. Every future run must record the exact feature list and excluded fields. No columns are silently dropped.

## 5. Frozen source-file holdouts

No random row splitting is allowed across source files. Every listed CSV is an indivisible group. Inner validation, if later required, must be drawn only from training source files and must preserve source grouping; no validation row may come from the held-out source file.

### CSE-SFH-A

**Train:**

- `Friday-02-03-2018_TrafficForML_CICFlowMeter.csv`
- `Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv`
- `Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv`
- `Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv`
- `Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv`
- `Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv`

**Test:** `Friday-23-02-2018_TrafficForML_CICFlowMeter.csv`

All test labels—Benign, Brute Force -Web, Brute Force -XSS, and SQL Injection—have training support; the precise per-file counts are in the JSON manifest.

### CSE-SFH-B

**Train:**

- `Friday-02-03-2018_TrafficForML_CICFlowMeter.csv`
- `Friday-23-02-2018_TrafficForML_CICFlowMeter.csv`
- `Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv`
- `Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv`
- `Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv`
- `Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv`

**Test:** `Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv`

All test labels—Benign, Brute Force -Web, Brute Force -XSS, and SQL Injection—have training support; exact counts are in the JSON manifest.

These are reciprocal held-out-file configurations; preserve their membership exactly. The remaining three source files are not selected in either configuration because they contain repeated header rows and their label/data-row artifacts need a separate protocol decision. The selected configurations also avoid the three files involved in Stage 5A's one shared exact-row signature.

## 6. Separate unseen-class/source condition

`DDoS attacks-LOIC-HTTP` occurs in the 20-February source and not in the other nine files. The 20-February source is in both frozen training sets, with 576,191 audited examples of that label in each configuration. Therefore, this label has training support in A and B and is not a held-out class in either test file.

A future experiment that holds out the 20-February source must be reported separately as an unseen-class/source condition; the LOIC-HTTP label then has no support in the other source files. Do not mix its score into the known-class holdout result or claim known-class performance for that condition.

## 7. Required later run manifest and unresolved ambiguity

Before any Stage 5D model execution, record per-file row counts before and after each filter, repeated-header and non-finite affected-row counts (including their overlap), retained-row totals, exact projected and excluded columns, class distributions, source SHA-256 values, software versions, and holdout ID. No random seed is needed for the primary source partition; any training or within-training validation seed must be separately configured and recorded.

Stage 5C.1 does not resolve whether all ten captures used identical CICFlowMeter versions/settings or validate the physical units of the common feature names. It does not decide what to do if ordinary missing tokens appear despite the audit reporting zero missing cells. These conditions must be surfaced before training, not silently repaired.

**No models, preprocessing transforms, or dataset mutations are performed by this protocol stage.**
