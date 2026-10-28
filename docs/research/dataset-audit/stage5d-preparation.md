# Stage 5D-Prep — CSE-CIC-IDS2018 model-ready preparation

**Status:** completed preparation and provenance verification; no models trained. Stage 5A, 5B, 5C, and 5C.1 remain frozen. Raw CSVs were read only.

## Preparation implementation

The preparation reads only the seven source files used by the union of frozen holdouts A and B, one file at a time. Before parsing, each file SHA-256 is checked against the frozen Stage 5C audit value. For each row, its full source header is compared cell-for-cell to detect repeated headers; otherwise it is projected by column name onto the exact ordered Stage 5C.1 common schema. Numeric fields are identified from Stage 5A inferred types. Rows with a NaN, positive infinity, or negative infinity in any numeric projected feature are excluded. Finite zero is preserved. No imputation, normalization, deduplication, model fitting, or label rewriting occurs. A source mismatch or malformed row fails closed.

For the 20-February source, this explicitly projects 84 raw columns onto the common 80. The four extra raw columns are `Flow ID`, `Src IP`, `Src Port`, and `Dst IP`; none is included in the projected output.

Each derived artifact is a deterministic gzip CSV (fixed gzip timestamp, UTF-8, LF row endings) containing the 77 model features in common-schema order followed by `Label`. Derived files are under `data/processed/`, outside `data/raw/` and ignored by Git. Artifact paths, hashes, sizes, source hashes, exact feature names, row counts, and labels are in [`cse-preparation.json`](../../../experiments/stage5d/cse-preparation.json).

## Provenance

### Verified from repository artifacts and acquired files

- Stage 5A / 5C.1 record source paths, SHA-256 digests, ordered schemas, and audited row counts. All seven used source hashes matched their frozen digests before preparation.
- CSV headers and values were directly read; label strings and timestamp strings are observable in the acquired files. The timestamp values are text strings in a date-time-like representation; the repository does not establish timezone, clock source, precision, or generation semantics. Stage 5C records suspicious 1970 timestamp minima in the 22-February source. Timestamp is excluded from model features.
- The 20-February extra-column structure and the exact 80-column projection are recorded in the frozen protocol.

### Unknown / not verified

- CICFlowMeter version for any individual source file.
- Feature extraction settings/configuration, including generation options.
- Authoritative physical units and full semantics for feature fields. Column names and observed value ranges are not proof of units.
- Whether all source files were captured at consistent sensor locations and processed with equivalent capture and extraction settings.
- The original download source is not recorded in the Stage 5A repository metadata. No missing provenance was inferred or filled in.

## Per-source preparation statistics

“Original rows” counts parsed data records, excluding the CSV header. `NaN rows` and `+Inf rows` / `-Inf rows` are independently counted and can overlap. `Non-finite rows` is their union. `Excluded rows` is repeated-header rows plus non-finite rows; these conditions are disjoint because repeated headers are removed before numeric inspection. Counts below are from the performed streaming pass.

| Source file | Original rows | Repeated headers | NaN rows | +Inf rows | -Inf rows | Non-finite row union | Final usable | Excluded | Features | Final class counts |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `Friday-02-03-2018_TrafficForML_CICFlowMeter.csv` | 1,048,575 | 0 | 2,558 | 4,050 | 0 | 4,050 | 1,044,525 | 4,050 | 77 | Benign: 758,334; Bot: 286,191 |
| `Friday-23-02-2018_TrafficForML_CICFlowMeter.csv` | 1,048,575 | 0 | 3,754 | 5,708 | 0 | 5,708 | 1,042,867 | 5,708 | 77 | Benign: 1,042,301; Brute Force -Web: 362; Brute Force -XSS: 151; SQL Injection: 53 |
| `Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv` | 7,948,748 | 0 | 36,767 | 59,453 | 0 | 59,453 | 7,889,295 | 59,453 | 77 | Benign: 7,313,104; DDoS attacks-LOIC-HTTP: 576,191 |
| `Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv` | 1,048,575 | 0 | 4,921 | 8,027 | 0 | 8,027 | 1,040,548 | 8,027 | 77 | Benign: 988,050; DoS attacks-GoldenEye: 41,508; DoS attacks-Slowloris: 10,990 |
| `Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv` | 1,048,575 | 0 | 3,569 | 5,610 | 0 | 5,610 | 1,042,965 | 5,610 | 77 | Benign: 1,042,603; Brute Force -Web: 249; Brute Force -XSS: 79; SQL Injection: 34 |
| `Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv` | 1,048,575 | 0 | 2,277 | 3,824 | 0 | 3,824 | 1,044,751 | 3,824 | 77 | Benign: 663,808; FTP-BruteForce: 193,354; SSH-Bruteforce: 187,589 |
| `Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv` | 1,048,575 | 0 | 0 | 0 | 0 | 0 | 1,048,575 | 0 | 77 | Benign: 360,833; DDOS attack-HOIC: 686,012; DDOS attack-LOIC-UDP: 1,730 |

The final label vocabulary for each source is exactly the set of class-count keys in the table and machine-readable report. No class labels are canonicalized. Every selected source used the same 80-column projected schema and the same 77 feature names. All seven had zero exact repeated-header rows in this observed preparation pass.

## Frozen feature policy

The common schema has 80 columns. `Label`, `Timestamp`, and `Dst Port` are present in that common schema and excluded from predictors; the result is **77 features plus the `Label` target**. The other frozen excluded fields (`Flow ID`, `Src IP`, `Dst IP`) are not in the common schema and are source-only columns on 20-February. `Src Port` is also a 20-February-only extra projected away under the frozen common-schema rule; this is schema projection, not an extra model-feature exclusion. No other common-schema column was excluded.

Exact ordered model feature names:

```text
Protocol, Flow Duration, Tot Fwd Pkts, Tot Bwd Pkts, TotLen Fwd Pkts, TotLen Bwd Pkts, Fwd Pkt Len Max, Fwd Pkt Len Min, Fwd Pkt Len Mean, Fwd Pkt Len Std, Bwd Pkt Len Max, Bwd Pkt Len Min, Bwd Pkt Len Mean, Bwd Pkt Len Std, Flow Byts/s, Flow Pkts/s, Flow IAT Mean, Flow IAT Std, Flow IAT Max, Flow IAT Min, Fwd IAT Tot, Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max, Fwd IAT Min, Bwd IAT Tot, Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd IAT Min, Fwd PSH Flags, Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags, Fwd Header Len, Bwd Header Len, Fwd Pkts/s, Bwd Pkts/s, Pkt Len Min, Pkt Len Max, Pkt Len Mean, Pkt Len Std, Pkt Len Var, FIN Flag Cnt, SYN Flag Cnt, RST Flag Cnt, PSH Flag Cnt, ACK Flag Cnt, URG Flag Cnt, CWE Flag Count, ECE Flag Cnt, Down/Up Ratio, Pkt Size Avg, Fwd Seg Size Avg, Bwd Seg Size Avg, Fwd Byts/b Avg, Fwd Pkts/b Avg, Fwd Blk Rate Avg, Bwd Byts/b Avg, Bwd Pkts/b Avg, Bwd Blk Rate Avg, Subflow Fwd Pkts, Subflow Fwd Byts, Subflow Bwd Pkts, Subflow Bwd Byts, Init Fwd Win Byts, Init Bwd Win Byts, Fwd Act Data Pkts, Fwd Seg Size Min, Active Mean, Active Std, Active Max, Active Min, Idle Mean, Idle Std, Idle Max, Idle Min
```

## Frozen holdout label support

### CSE-SFH-A

Train sources: `Friday-02-03-2018_TrafficForML_CICFlowMeter.csv`, `Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv`, `Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv`, `Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv`, `Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv`, `Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv`.
Test source: `Friday-23-02-2018_TrafficForML_CICFlowMeter.csv`.

| Test label | Test usable rows | Training usable rows | Supported in training |
|---|---:|---:|---|
| Benign | 1,042,301 | 11,126,732 | yes |
| Brute Force -Web | 362 | 249 | yes |
| Brute Force -XSS | 151 | 79 | yes |
| SQL Injection | 53 | 34 | yes |

All test labels have training support: **yes**.
`DDoS attacks-LOIC-HTTP` training count: **576,191**; represented in training: **true**; absent from training: **false**.

### CSE-SFH-B

Train sources: `Friday-02-03-2018_TrafficForML_CICFlowMeter.csv`, `Friday-23-02-2018_TrafficForML_CICFlowMeter.csv`, `Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv`, `Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv`, `Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv`, `Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv`.
Test source: `Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv`.

| Test label | Test usable rows | Training usable rows | Supported in training |
|---|---:|---:|---|
| Benign | 1,042,603 | 11,126,430 | yes |
| Brute Force -Web | 249 | 362 | yes |
| Brute Force -XSS | 79 | 151 | yes |
| SQL Injection | 34 | 53 | yes |

All test labels have training support: **yes**.
`DDoS attacks-LOIC-HTTP` training count: **576,191**; represented in training: **true**; absent from training: **false**.

Thus LOIC-HTTP is represented in training in both configurations and is not an unseen class in these holdouts. This preparation verifies label support only; it does not train or score a classifier.

## Reproduction

From the repository root, with the project environment available:

```bash
.venv/bin/python scripts/prepare_stage5d_cse.py
```

The command rechecks source SHA-256 values, rewrites only the seven derived gzip CSVs under `data/processed/stage5d/cse-cic-ids2018/`, and updates the JSON report. It does not write under `data/raw/`.

## Limitations

- Provenance gaps above remain unresolved and must not be converted into assumed dataset consistency or feature-unit claims.
- Stage 5D-Prep prepares inputs and verifies source/label support; it gives no evidence about model performance or security effectiveness.
- Model training readiness is conditional on review of the missing extraction provenance and the prepared-artifact report; this stage does not authorize training automatically.
