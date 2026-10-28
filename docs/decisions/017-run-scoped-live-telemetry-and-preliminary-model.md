# ADR 017: Run-scoped live telemetry and unapproved supervised candidate

- **Status:** Accepted for controlled lab evaluation; operational attack detection remains unapproved.
- **Date:** 2026-10-28

## Context

The collector retained an append-only Ryu telemetry file for benign and scan scenarios in one controller process. The provenance auditor correctly rejects a stream containing requests from multiple run IDs. The live API poller also needs to inspect complete windows while the Ryu datapath is connected. The available live feature contract remains the four OpenFlow rule-counter values and cannot use the offline 77-feature CICFlowMeter model.

## Decision

Retain the original combined raw stream and additionally write append-only telemetry streams keyed by the active run ID. The API poller consumes only these run-scoped streams while the controller reports a fresh active datapath/epoch. After collection, the parent derives final scenario views by copying records according to their existing recorded run IDs; it never edits the raw stream or invents lineage.

Build supervised labels only from the collector's completed scenario journal and successful bounded child-process record. Assign complete run IDs to train, validation and test. Train a transparent four-feature logistic candidate with validation-only threshold selection and signed standardized contributions. Keep the candidate hash-verified but unapproved and inference-disabled; the provisional robust benign scorer remains the only active live scorer and never makes an attack classification.

## Alternatives considered

- Relax the auditor to accept mixed run IDs: rejected because it weakens provenance.
- Reconstruct or sort telemetry after collection: rejected because it obscures event order and original evidence.
- Reuse the offline 77-feature artifact: rejected because the schemas and semantics are incompatible.
- Treat anomaly scores as attack labels or auto-approve the supervised candidate: rejected because the observed data is limited to three runs per class and includes a benign false alert.

## Consequences

The mixed collector now emits run-scoped streams that can be audited and scored during an active controller epoch. The API persisted actual port-scan and benign anomaly scores with source hashes and explanations. The preliminary classifier has a measurable held-out result but only one held-out run per class; it is insufficient for operational approval. Mitigation remains disabled. Additional independent benign variations and scan runs are needed before approval evaluation.
