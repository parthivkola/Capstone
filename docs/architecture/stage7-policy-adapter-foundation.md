# Stage 7 Policy and Mitigation Adapter Foundation

This document describes the bounded reusable foundation implemented from the frozen [Stage 7 protocol](../research/stage7-safe-autonomous-defense-protocol.md). It does not change that protocol, connect inference to Ryu, or authorize a live mitigation run.

## Boundaries

```text
DetectionResult → RiskPolicy → RiskDecision → MitigationAction
                                                  ↓
                                      MitigationAdapter → Ryu/OpenFlow
                                                  ↓
                                      lifecycle / exact rollback
```

`DetectionResult` carries a real classifier state, optional confidence/attack score, optional novelty/shift state, provenance-bearing evidence, observation time, and optional exact scope. It contains no action. `RiskPolicy` is a pure deterministic component. `RiskDecision` records risk, action, reasons, evidence IDs, timestamp, and abstention. Only a non-MONITOR decision can be materialized into an immutable TTL-bounded `MitigationAction`.

The original generic `DecisionRecord`/`MitigationPort` remain for compatibility with Stage 1 callers. The Stage 7 detector port now returns the separate `DetectionResult`; the Stage 7 `MitigationAdapter` accepts only `MitigationAction` and returns an explicit adapter status.

## Policy behavior

`RiskPolicyConfig` loads action TTLs and persistence limits from `experiments/stage7/defense-protocol.json`; numeric confidence cutoffs must be supplied from a validation-only calibration manifest. There are no default score thresholds. It supports the frozen A/B/C/D comparison modes. Unknown is never converted into Attack. Missing/stale confidence or scope, protected-flow overlap, or unsupported action capability falls back to MONITOR. PSI does not raise risk. UNCERTAIN is limited to monitor/rate-limit outcomes.

Scopes are immutable selector tuples and reject empty/global or incomplete flow selectors. The guard treats a proposed scope as protected if no shared selector proves it disjoint from a declared protected scope. No host importance is inferred.

## Lifecycle and audit

`MitigationLifecycle` is a clock-independent state machine with explicit `now` inputs. It supports proposal, activation, one midpoint extension after all evidence/capability predicates pass, TTL expiry, and terminal rollback. Expiry returns a deterministic action-specific rollback request. It does not call an adapter; an application service must reconcile the request with the adapter result.

`DefenseAuditEvent` and the audit builders retain result/decision/action IDs, real scores only when supplied, scope, reason, policy version, adapter status, cookie, TTL, and rollback state. The Ryu adapter retains events in memory and may also send them to a caller-provided sink. The in-memory list is process-local and is not durable storage.

## Ryu/OpenFlow adapter

`networking/ryu/mitigation_adapter.py` is separate from the Stage 2 controller and imports no Ryu modules outside the existing adapter surface. It accepts a Ryu datapath mapping and builds OpenFlow 1.3 flow-mod messages through that datapath's parser. BLOCK and QUARANTINE use exact-scope drop rules, caller-configured table/priority, a deterministic 64-bit cookie derived from action ID, and the action TTL as `hard_timeout`. Rollback sends a strict delete matching the exact cookie, table, priority, and original match; unrelated rules are not selected.

The adapter sends no action merely by construction. `flow_mod_support_verified` defaults false; a caller must explicitly enable the capability only after an authorized local adapter check. This repository run did not verify drop-rule installation against OVS. Rate limiting is always reported UNSUPPORTED: no meter install/remove path or frozen rate/burst value exists. Fixture-only scopes are also unsupported by the OpenFlow adapter. The risk engine therefore fails closed to MONITOR unless the adapter advertises the exact action/scope capability.

## Validation and limits

Unit tests use fake datapaths/parsers and do not start Ryu, OVS, Mininet, or attack scenarios. They validate message construction and exact correlation only; they do not prove that a real switch accepted or removed a rule. No Stage 2 controller behavior, Stage 3 scenario, Stage 5 artifact, Stage 6 status, dataset, or model was changed or executed. Live feature parity, flow-score correlation, actual meter support, protected-flow enforcement, and end-to-end rollback remain prerequisites for later evaluation.
