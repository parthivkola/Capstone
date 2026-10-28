# Stage 5C CSE-CIC-IDS2018 Schema Analysis

This is a read-only schema/protocol analysis. It uses the immutable Stage 5A audit for streaming per-cell facts and re-opened only each raw CSV's first record to verify its header. It does not fit preprocessing, impute values, merge files, or train models.

## Summary decision

- The 20-February file has 84 columns: the same ordered 80-column standard schema plus four identifier fields prepended. No standard column is missing from it.
- Its shared-column inferred types match the standard-schema files without repeated header rows. Three other files have 78 shared fields inferred as `mixed` because exact repeated header rows occur within the data; this is a data-row artifact, not a 20-February semantic type difference.
- A structural 80-column intersection exists. A scientifically validated all-ten-file feature schema remains **provisional**, pending repeated-header and non-finite value policies and confirmation that the files use compatible CICFlowMeter versions/settings.
- 20-February is safe to include only conditionally: project explicitly onto the shared 80 columns, exclude identifier/time fields, and define handling for its 118,906 non-finite cells. It cannot serve as a known-class held-out file because `DDoS attacks-LOIC-HTTP` occurs only there.

## Per-file audit

Exact ordered headers and normalized name sets are stored per file in the JSON. `standard-80` and `feb20-84` schema definitions below provide readable cross-references; `standard-80-with-repeated-header-data` has the exact standard header but inferred types affected by repeated header rows.

| Source file | Rows | Columns/schema | Labels | Missing / non-finite | Duplicate rows | Repeated header rows | Timestamp range | Identifier-like columns | Raw header matches audit |
| --- | ---: | --- | --- | ---: | ---: | ---: | --- | --- | --- |
| `Friday-02-03-2018_TrafficForML_CICFlowMeter.csv` | 1,048,575 | 80 / `standard-80` | Label: Benign, Bot | 0 / 8,100 | 5,459 | 0 | Timestamp 2018-03-02T01:00:00 … 2018-03-02T12:59:59 | Dst Port, Timestamp | True |
| `Friday-16-02-2018_TrafficForML_CICFlowMeter.csv` | 1,048,575 | 80 / `standard-80-with-repeated-header-data` | Label: Benign, DoS attacks-Hulk, DoS attacks-SlowHTTPTest, Label | 0 / 0 | 147,586 | 1 | Timestamp 2018-02-16T01:00:32 … 2018-02-16T12:58:24 | Dst Port, Timestamp | True |
| `Friday-23-02-2018_TrafficForML_CICFlowMeter.csv` | 1,048,575 | 80 / `standard-80` | Label: Benign, Brute Force -Web, Brute Force -XSS, SQL Injection | 0 / 11,416 | 2,614 | 0 | Timestamp 2018-02-23T01:00:00 … 2018-02-23T12:59:59 | Dst Port, Timestamp | True |
| `Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv` | 7,948,748 | 84 / `feb20-84` | Label: Benign, DDoS attacks-LOIC-HTTP | 0 / 118,906 | 2 | 0 | Timestamp 2018-02-20T01:00:00 … 2018-02-20T12:59:59 | Flow ID, Src IP, Src Port, Dst IP, Dst Port, Timestamp | True |
| `Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv` | 331,125 | 80 / `standard-80-with-repeated-header-data` | Label: Benign, Infilteration, Label | 0 / 5,838 | 97 | 25 | Timestamp 2018-03-01T01:00:00 … 2018-03-01T12:59:59 | Dst Port, Timestamp | True |
| `Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv` | 1,048,575 | 80 / `standard-80` | Label: Benign, DoS attacks-GoldenEye, DoS attacks-Slowloris | 0 / 16,054 | 2,421 | 0 | Timestamp 2018-02-15T01:00:00 … 2018-02-15T12:59:59 | Dst Port, Timestamp | True |
| `Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv` | 1,048,575 | 80 / `standard-80` | Label: Benign, Brute Force -Web, Brute Force -XSS, SQL Injection | 0 / 11,220 | 3,278 | 0 | Timestamp 1970-01-10T03:04:26 … 2018-02-22T12:59:59 | Dst Port, Timestamp | True |
| `Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv` | 1,048,575 | 80 / `standard-80` | Label: Benign, FTP-BruteForce, SSH-Bruteforce | 0 / 7,648 | 225,628 | 0 | Timestamp 1970-01-05T03:01:17 … 2018-02-14T12:59:59 | Dst Port, Timestamp | True |
| `Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv` | 1,048,575 | 80 / `standard-80` | Label: Benign, DDOS attack-HOIC, DDOS attack-LOIC-UDP | 0 / 0 | 17,557 | 0 | Timestamp 2018-02-21T01:55:46 … 2018-02-21T10:43:21 | Dst Port, Timestamp | True |
| `Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv` | 613,104 | 80 / `standard-80-with-repeated-header-data` | Label: Benign, Infilteration, Label | 0 / 12,338 | 6,121 | 33 | Timestamp 2018-02-28T01:00:00 … 2018-02-28T12:59:59 | Dst Port, Timestamp | True |

### Standard 80-column ordered schema

```text
Dst Port, Protocol, Timestamp, Flow Duration, Tot Fwd Pkts, Tot Bwd Pkts, TotLen Fwd Pkts, TotLen Bwd Pkts, Fwd Pkt Len Max, Fwd Pkt Len Min, Fwd Pkt Len Mean, Fwd Pkt Len Std, Bwd Pkt Len Max, Bwd Pkt Len Min, Bwd Pkt Len Mean, Bwd Pkt Len Std, Flow Byts/s, Flow Pkts/s, Flow IAT Mean, Flow IAT Std, Flow IAT Max, Flow IAT Min, Fwd IAT Tot, Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max, Fwd IAT Min, Bwd IAT Tot, Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd IAT Min, Fwd PSH Flags, Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags, Fwd Header Len, Bwd Header Len, Fwd Pkts/s, Bwd Pkts/s, Pkt Len Min, Pkt Len Max, Pkt Len Mean, Pkt Len Std, Pkt Len Var, FIN Flag Cnt, SYN Flag Cnt, RST Flag Cnt, PSH Flag Cnt, ACK Flag Cnt, URG Flag Cnt, CWE Flag Count, ECE Flag Cnt, Down/Up Ratio, Pkt Size Avg, Fwd Seg Size Avg, Bwd Seg Size Avg, Fwd Byts/b Avg, Fwd Pkts/b Avg, Fwd Blk Rate Avg, Bwd Byts/b Avg, Bwd Pkts/b Avg, Bwd Blk Rate Avg, Subflow Fwd Pkts, Subflow Fwd Byts, Subflow Bwd Pkts, Subflow Bwd Byts, Init Fwd Win Byts, Init Bwd Win Byts, Fwd Act Data Pkts, Fwd Seg Size Min, Active Mean, Active Std, Active Max, Active Min, Idle Mean, Idle Std, Idle Max, Idle Min, Label
```

### 20-February 84-column ordered schema

```text
Flow ID, Src IP, Src Port, Dst IP, Dst Port, Protocol, Timestamp, Flow Duration, Tot Fwd Pkts, Tot Bwd Pkts, TotLen Fwd Pkts, TotLen Bwd Pkts, Fwd Pkt Len Max, Fwd Pkt Len Min, Fwd Pkt Len Mean, Fwd Pkt Len Std, Bwd Pkt Len Max, Bwd Pkt Len Min, Bwd Pkt Len Mean, Bwd Pkt Len Std, Flow Byts/s, Flow Pkts/s, Flow IAT Mean, Flow IAT Std, Flow IAT Max, Flow IAT Min, Fwd IAT Tot, Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max, Fwd IAT Min, Bwd IAT Tot, Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd IAT Min, Fwd PSH Flags, Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags, Fwd Header Len, Bwd Header Len, Fwd Pkts/s, Bwd Pkts/s, Pkt Len Min, Pkt Len Max, Pkt Len Mean, Pkt Len Std, Pkt Len Var, FIN Flag Cnt, SYN Flag Cnt, RST Flag Cnt, PSH Flag Cnt, ACK Flag Cnt, URG Flag Cnt, CWE Flag Count, ECE Flag Cnt, Down/Up Ratio, Pkt Size Avg, Fwd Seg Size Avg, Bwd Seg Size Avg, Fwd Byts/b Avg, Fwd Pkts/b Avg, Fwd Blk Rate Avg, Bwd Byts/b Avg, Bwd Pkts/b Avg, Bwd Blk Rate Avg, Subflow Fwd Pkts, Subflow Fwd Byts, Subflow Bwd Pkts, Subflow Bwd Byts, Init Fwd Win Byts, Init Bwd Win Byts, Fwd Act Data Pkts, Fwd Seg Size Min, Active Mean, Active Std, Active Max, Active Min, Idle Mean, Idle Std, Idle Max, Idle Min, Label
```

### Normalized schema set

Normalization: Unicode NFKC, case-fold, trim, then replace punctuation/whitespace runs with `_`. This is used for equality diagnostics only; raw headers are unchanged.

```text
ack_flag_cnt, active_max, active_mean, active_min, active_std, bwd_blk_rate_avg, bwd_byts_b_avg, bwd_header_len, bwd_iat_max, bwd_iat_mean, bwd_iat_min, bwd_iat_std, bwd_iat_tot, bwd_pkt_len_max, bwd_pkt_len_mean, bwd_pkt_len_min, bwd_pkt_len_std, bwd_pkts_b_avg, bwd_pkts_s, bwd_psh_flags, bwd_seg_size_avg, bwd_urg_flags, cwe_flag_count, down_up_ratio, dst_port, ece_flag_cnt, fin_flag_cnt, flow_byts_s, flow_duration, flow_iat_max, flow_iat_mean, flow_iat_min, flow_iat_std, flow_pkts_s, fwd_act_data_pkts, fwd_blk_rate_avg, fwd_byts_b_avg, fwd_header_len, fwd_iat_max, fwd_iat_mean, fwd_iat_min, fwd_iat_std, fwd_iat_tot, fwd_pkt_len_max, fwd_pkt_len_mean, fwd_pkt_len_min, fwd_pkt_len_std, fwd_pkts_b_avg, fwd_pkts_s, fwd_psh_flags, fwd_seg_size_avg, fwd_seg_size_min, fwd_urg_flags, idle_max, idle_mean, idle_min, idle_std, init_bwd_win_byts, init_fwd_win_byts, label, pkt_len_max, pkt_len_mean, pkt_len_min, pkt_len_std, pkt_len_var, pkt_size_avg, protocol, psh_flag_cnt, rst_flag_cnt, subflow_bwd_byts, subflow_bwd_pkts, subflow_fwd_byts, subflow_fwd_pkts, syn_flag_cnt, timestamp, tot_bwd_pkts, tot_fwd_pkts, totlen_bwd_pkts, totlen_fwd_pkts, urg_flag_cnt
```

The 20-February normalized set is this common set plus `flow_id`, `src_ip`, `src_port`, and `dst_ip`.

## Explicit 20-February comparisons

| Compared file | Only in 20-Feb | Missing from 20-Feb | Same-name inferred type mismatches | Label columns/vocabulary |
| --- | --- | --- | ---: | --- |
| `Friday-02-03-2018_TrafficForML_CICFlowMeter.csv` | Flow ID, Src IP, Src Port, Dst IP | none | 0 | same Label column; vocabulary differs by source |
| `Friday-16-02-2018_TrafficForML_CICFlowMeter.csv` | Flow ID, Src IP, Src Port, Dst IP | none | 78 | same Label column; vocabulary differs by source |
| `Friday-23-02-2018_TrafficForML_CICFlowMeter.csv` | Flow ID, Src IP, Src Port, Dst IP | none | 0 | same Label column; vocabulary differs by source |
| `Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv` | Flow ID, Src IP, Src Port, Dst IP | none | 78 | same Label column; vocabulary differs by source |
| `Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv` | Flow ID, Src IP, Src Port, Dst IP | none | 0 | same Label column; vocabulary differs by source |
| `Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv` | Flow ID, Src IP, Src Port, Dst IP | none | 0 | same Label column; vocabulary differs by source |
| `Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv` | Flow ID, Src IP, Src Port, Dst IP | none | 0 | same Label column; vocabulary differs by source |
| `Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv` | Flow ID, Src IP, Src Port, Dst IP | none | 0 | same Label column; vocabulary differs by source |
| `Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv` | Flow ID, Src IP, Src Port, Dst IP | none | 78 | same Label column; vocabulary differs by source |

The JSON contains the exact per-column mismatch maps for all nine comparisons. For the standard-schema files without repeated headers there are no shared-name type mismatches. For Friday 16-February, Thursday 1-March, and Wednesday 28-February, the mismatch count is 78 each: these shared columns are inferred `mixed` against 20-February's numeric types. Timestamp and Label remain string/category. The repeated-header observation explains this apparent difference.

### February 20 difference interpretation

- **Only in 20-February:** `Flow ID`, `Src IP`, `Src Port`, `Dst IP`.
- **Missing from 20-February:** none of the standard 80 columns.
- **Ordering:** the four extra fields are prepended; all shared names retain the standard relative order.
- **Semantics:** the four extra fields are flow/endpoint identifiers. Their addition is semantic schema enrichment, not a spelling-only formatting variation. Their exclusion from a common model projection would be explicit.
- **Common-column types:** no type mismatch against six standard files without repeated headers; 78 apparent mixed-type mismatches against each of the three repeated-header files. No conversion is proposed here.
- **Label:** all use `Label`, but per-file class sets differ. The 20-February-only label `DDoS attacks-LOIC-HTTP` makes that source unsuitable as known-class test against all other files.
- **Other suspicious content:** Friday 16-February has one exact repeated header row, Thursday 1-March has 25, Wednesday 28-February has 33. Stage 5A also observed non-finite values in `Flow Byts/s` and `Flow Pkts/s` (including 59,453 each on 20-February). Timestamp ranges on Wednesday 14-February and Thursday 22-February include values in 1970 and require review before temporal use. No data were changed.

## Candidate common schemas

### Structural 80-column intersection

All ten files contain the same exact 80 standard header names in the same relative order. The
20-February file adds four prepended identifier columns. This establishes a structural
intersection, not by itself semantic equivalence of units/extractor settings. A future common
projection can retain the 80 shared columns, with an explicit feature policy that excludes Label
and leakage-prone identifiers/time fields. The JSON records the full candidate feature list and
inferred type per source.

### Candidate model feature projection (not applied)

A conservative later experiment could use the shared CICFlowMeter columns after explicitly excluding `Label`, `Timestamp`, `Dst Port`, and, for 20-February, `Flow ID`, `Src IP`, `Src Port`, and `Dst IP`. `Dst Port` is flagged identifier-like by Stage 5A and is excluded conservatively here; a later protocol may retain it only with a documented justification. `Protocol` and aggregate flow statistics remain candidates. This proposal does not assert final semantic compatibility.

## Source-file holdout protocol candidates

All source files remain indivisible groups. Candidate training groups avoid the three files with detected repeated-header rows. These are **protocol candidates**, not executed experiments; other non-finite values remain and require a declared handling policy:

| Candidate | Training files | Held-out file | Held-out labels with training support | Status |
| --- | --- | --- | --- | --- |
| `known-class-holdout-friday-23-02-2018` | Friday-02-03-2018_TrafficForML_CICFlowMeter.csv, Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv, Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv, Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv, Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv, Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv | Friday-23-02-2018_TrafficForML_CICFlowMeter.csv | all | Candidate; explicit data-quality decisions required |
| `known-class-holdout-thursday-22-02-2018` | Friday-02-03-2018_TrafficForML_CICFlowMeter.csv, Friday-23-02-2018_TrafficForML_CICFlowMeter.csv, Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv, Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv, Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv, Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv | Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv | all | Candidate; explicit data-quality decisions required |

In these candidates, the 20-February file is a training source and requires an explicit 80-column projection. The `Brute Force -Web`, `Brute Force -XSS`, and `SQL Injection` labels are present in both Friday 23-February and Thursday 22-February, so the support check passes for either held-out file. The candidates omit all three files involved in Stage 5A's sole shared exact-row signature. Non-finite flow-rate values still require a predeclared policy; do not train until approved.

### Separate unseen-class/source conditions

- Hold out `Friday-02-03-2018_TrafficForML_CICFlowMeter.csv`: labels absent from all other source files: Bot; treat as a separate unseen-class/source condition, not known-class classification.
- Hold out `Friday-16-02-2018_TrafficForML_CICFlowMeter.csv`: labels absent from all other source files: DoS attacks-Hulk, DoS attacks-SlowHTTPTest; treat as a separate unseen-class/source condition, not known-class classification.
- Hold out `Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv`: labels absent from all other source files: DDoS attacks-LOIC-HTTP; treat as a separate unseen-class/source condition, not known-class classification.
- Hold out `Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv`: labels absent from all other source files: DoS attacks-GoldenEye, DoS attacks-Slowloris; treat as a separate unseen-class/source condition, not known-class classification.
- Hold out `Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv`: labels absent from all other source files: FTP-BruteForce, SSH-Bruteforce; treat as a separate unseen-class/source condition, not known-class classification.
- Hold out `Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv`: labels absent from all other source files: DDOS attack-HOIC, DDOS attack-LOIC-UDP; treat as a separate unseen-class/source condition, not known-class classification.

## Decision and blockers

The 20-February file may be included in a future known-class source-holdout training set under an explicit common-schema projection, but it is not a valid known-class held-out source for its unique LOIC-HTTP label. It is not yet approved as model input because the four extra identifier fields need exclusion, shared feature semantics lack extractor provenance confirmation, and non-finite values require a declared policy.

Before training, resolve: (1) repeated-header row treatment for the three affected source files; (2) non-finite `Flow Byts/s`/`Flow Pkts/s` handling without changing raw files; (3) CICFlowMeter provenance/unit compatibility; (4) final identifier/time feature exclusions; and (5) whether the experiment is known-class holdout or unseen-class/source evaluation. No resolution was silently applied in Stage 5C.

Stage 5C performs no model training and makes no detection-effectiveness claim.
