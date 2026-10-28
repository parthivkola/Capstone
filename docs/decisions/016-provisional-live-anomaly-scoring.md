# ADR 016: Provisional live scoring from benign OpenFlow calibration

- Status: Accepted for research monitoring; not approved for operational attack detection or mitigation
- Date: 2026-10-28

## Context

The offline application model consumes 77 CICFlowMeter fields. Validated live telemetry produces four rule-counter features with different semantics. A benign-only isolated Mininet/Ryu/OVS run is available, but there are no labeled live attack runs or independent held-out evaluation groups.

## Decision

Keep the 77-feature offline inference path separate. Provide a separately versioned robust deviation baseline for exactly the four live features, calibrated only from complete, source-audited benign windows. Its fixed threshold is an engineering setting, not a validated operating point. Score only fresh windows whose run/epoch is currently reported by Ryu. Persist each window once by stable ID, together with feature values, source hashes and IDs, score and signed per-feature deviations. Label the output anomaly/deviation evidence, never an attack class or probability. Do not authorize mitigation from this score.

## Alternatives considered

- Reuse or pad inputs for the offline 77-feature model: rejected because the feature semantics and schema are incompatible.
- Train a supervised live classifier: rejected until real controlled scenario labels and run-separated data exist.
- Leave live telemetry unscored: rejected as it would discard valid, provenance-checked measurements that can support explicitly provisional anomaly monitoring.
- Calibrate from synthetic fixtures: rejected because synthetic data is not live evidence.

## Consequences

The API and React page can demonstrate a real OpenFlow-to-score path when a fresh lab run and compatible local calibration artifact exist. A single benign calibration run cannot estimate run variation or detection quality. The threshold has no attack-validation evidence, rule identity is only a canonical selector identity, and scores are not probabilities. Fresh checkouts must restore the ignored calibration artifact from an eligible benign run. Live mitigation remains disabled until separately approved detector and enforcement evidence exists.

## Evidence

Calibration source: benign run `live-2026-10-28-first-verified-benign-04` (ten valid windows). Scored source: benign run `live-2026-10-28-first-verified-benign-05` (ten valid windows, API persisted ten unique score records while Ryu reported the active epoch). Calibration SHA-256: `6497b79dfb3a6f5f6840220e35e1bcdc60efae32e3369a62caff735e1fcedbc2`.
