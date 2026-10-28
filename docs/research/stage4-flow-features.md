# Stage 4: Reproducible Flow Records and Feature Extraction

## Scope and boundary

Stage 4 defines a typed, deterministic representation for the per-flow statistics currently emitted by the Stage 2 Ryu controller. It is a data-contract and conversion stage only. It does not classify traffic, infer attacks, fit preprocessing, choose thresholds, attach labels, build graphs, or take network action. The Stage 2 and Stage 3 implementations are unchanged.

The extractor accepts one structured Ryu `flow_statistics` event (the JSON object following `stage2_event=` in the controller log). Stage 3 scenario JSONL currently records scenario configuration, fixture events, topology state and cleanup; it does not contain equivalent per-flow counter snapshots. Those scenario event records are therefore not silently converted into flow rows. A future collector may join timestamps and flow observations under a separately specified protocol. The planned dynamic unknown Mininet host `h4` remains a later evaluation scenario and is not implemented here.

## FlowRecord schema, version 1

All fields are serialized in each JSONL row. `record_id` is a SHA-256 digest over the canonical JSON encoding of every other field. Numeric values retain source units. Missing values are JSON `null`.

| Field | Type | Meaning / source |
| --- | --- | --- |
| `schema_version` | integer | Contract version (`1`). |
| `record_id` | string | Stable content identifier; recomputed and verified on load. |
| `observed_at` | string or null | Event observation time normalized to UTC RFC 3339 form (`Z`); absent remains null. |
| `observation_source` | string | Currently `ryu_flow_statistics`. |
| `datapath_id` | string or null | Ryu switch/datapath identifier. |
| `table_id` | integer or null | OpenFlow table identifier. |
| `priority` | integer or null | OpenFlow rule priority. |
| `cookie` | string or null | OpenFlow cookie normalized to lowercase hexadecimal (for example `0x0`). |
| `duration_seconds` | finite number or null | Ryu-reported flow-entry duration in seconds at this snapshot. It is not first-seen/last-seen time. |
| `packet_count` | integer or null | Switch-reported packets matched by this rule at snapshot time. |
| `byte_count` | integer or null | Switch-reported bytes matched by this rule at snapshot time. |
| `eth_type` | integer or null | Ethernet type from the OpenFlow match (for example IPv4 `2048`). |
| `ip_protocol` | integer or null | IP protocol number from `ip_proto`, where matched. |
| `protocol` | string or null | Canonical `tcp`, `udp`, `icmp`, or `icmpv6` for recognized IP protocol numbers; an explicit source string is lowercased. Unknown numeric protocols remain represented by `ip_protocol` and have null `protocol`. |
| `src_ip`, `dst_ip` | string or null | Canonical IPv4/IPv6 address from the corresponding IP match field. |
| `src_mac`, `dst_mac` | string or null | Source/destination Ethernet match value. |
| `src_port`, `dst_port` | integer or null | TCP/UDP source/destination port where present in the match. |
| `in_port` | integer or null | OpenFlow ingress port where present in the match. |
| `tcp_flags` | integer or null | TCP flags only when the observation explicitly contains a `tcp_flags` match field. Current Stage 2 stats do not measure packet-level flag counts. |
| `is_empty` | boolean or null | True only when both counters are present and zero; false when both are present and at least one is nonzero; null if either is missing. Zero-counter rule snapshots are retained. |
| `match_raw` | string or null | Original Ryu match representation, retained for provenance; not a model feature. |

The extraction contract intentionally has no label, attack family, predicted class, score, fitted normalization, or split identifier. A flow-table entry is a rule match and may aggregate multiple traffic observations; it should not be described as a packet-level flow without a separately defined flow-aggregation contract.

## Extraction and validation rules

- Ryu's `match` mapping or its `OFPMatch(oxm_fields={...})` textual representation is parsed using Python literal parsing, never `eval`. Only the listed recognized match keys are mapped to fields; raw text is retained unchanged.
- Direct structured keys take precedence over corresponding match fields. Source protocol numbers are retained; common protocol strings are derived deterministically.
- Missing values remain null; the extractor does not impute, scale, normalize, select features, or use dataset statistics.
- Negative counters/ports, out-of-range protocol/port identifiers, malformed IP addresses, invalid or timezone-naive timestamps, non-finite/negative durations, and invalid cookies are rejected with `FlowRecordError`.
- Timestamps with offsets are converted to UTC at microsecond precision. A missing timestamp remains null; no current-time value is synthesized.
- Empty zero-counter snapshots are retained and marked with `is_empty=true`; they are not discarded as “uninteresting”.
- Duplicate means identical normalized record content, including timestamp and counters. Such records have the same `record_id`; `deduplicate_records` removes exact duplicates while preserving first-seen order. Repeated snapshots with changed time or counters remain distinct records.
- JSONL loading verifies schema, exact fields, derived `is_empty`, and the record hash. By default it retains duplicates; callers must explicitly request deduplication.

These operations are row-local and do not inspect labels, future partitions, or aggregate data. Dataset-specific cleaning and split assignment belong to later stages, with test data excluded from all fitting and selection as required by the research protocol.

## Serialization and provenance

The interchange format is UTF-8 JSON Lines, one schema-versioned object per line. The standard library JSON encoder writes sorted keys, compact separators, disallows NaN/Infinity, and includes a final newline. It is convenient for later pandas or other tabular ingestion without introducing a runtime dependency. Keep the source log, extraction command, code revision, and resulting JSONL together in the experiment manifest when creating a research run; generated outputs are not automatically committed.

The read-only converter accepts the existing Stage 2 structured log and writes extracted records:

```bash
python scripts/extract_ryu_flow_records.py /tmp/stage2-ryu.log /tmp/stage4-flow-records.jsonl
```

To remove exact repeated snapshots explicitly:

```bash
python scripts/extract_ryu_flow_records.py /tmp/stage2-ryu.log /tmp/stage4-flow-records-deduplicated.jsonl --deduplicate
```

To load records from Python, use `extract_ryu_log`, `read_jsonl`, and `write_jsonl` in `src.sdn_defense.flow_records`. The converter reads the input only; it does not start Mininet/Ryu or send traffic.

## Small local validation

When `/tmp/stage2-ryu.log` from the previously completed Stage 2 validation is available, run the converter command above. It should report the number of `flow_statistics` events written; inspect the JSONL output for schema fields, UTC timestamps, counters, parsed match fields, and deterministic IDs. This is extraction validation against an existing controller observation, not a new SDN test. No Stage 3 traffic is generated by this procedure. If the local log is absent, rerun the documented Stage 2 validation only in its authorized local Mininet environment before converting its output.

## Assumptions and limitations

- Stage 2's current controller emits flow-entry counters and match text, not packet-level bidirectional conversation records, TCP flag counters, rule action details, or packet timestamps. Those fields are not inferred.
- The `match_raw` field can contain a controller-specific textual form. Structured fields are extracted only from recognized OpenFlow match keys; unrecognized values remain available in raw provenance text but are not interpreted.
- A missing IP/port is meaningful: the OpenFlow match may be wildcarded. It is not a zero value.
- The flow-entry counters are cumulative at each observation; a later stage must define whether to use snapshots or counter deltas and how to handle counter resets.
- A switch rule can match benign and scenario traffic together. Stage 4 does not claim that each record corresponds to one attack or one host conversation.
- No Stage 4 output establishes detection effectiveness, supports research hypotheses, or validates any ML approach.
