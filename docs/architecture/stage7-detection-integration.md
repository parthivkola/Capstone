# Stage 7 Synthetic Detection-to-Enforcement Integration

This is an integration validation of the existing Stage 7 policy and bounded OVS enforcement boundary. It uses synthetic `DetectionResult` fixtures and bounded UDP echo probes. It does not load the RF model, consume Stage 5 rows, run Stage 3 attack scenarios, or measure detection/defense effectiveness.

## Data and decision boundaries

```text
synthetic DetectionResult
        ↓
RiskPolicy.evaluate / decide
        ↓
RiskDecision (policy arm and reason retained)
        ↓
MitigationAction (exact flow scope and protocol TTL)
        ↓
MitigationOrchestrator
        ↓
loopback Ryu gateway → OpenFlow 1.3 → OVS
        ↓
independent OvsFlowVerifier
```

Fixture provenance is `synthetic_test_fixture_only`. The test-only numeric confidence cutoffs are fixture values used to traverse policy branches; they are not validation-calibrated thresholds and are not research operating points. Policies A–D retain their frozen definitions. C and D share risk decisions; D's identity remains explicit for its reversible lifecycle.

Fixtures cover BENIGN, low/medium/high/very-high ATTACK, UNKNOWN, and an ATTACK result with insufficient confidence to produce a certain decision. Shift signals do not independently escalate risk. Unknown/uncertain outcomes remain monitor-only or bounded by the frozen policy and adapter capability.

## Run the local live validation

Prerequisites are the Stage 2 Fedora Mininet/OVS setup and the pinned `.venv-ryu` Ryu runtime. Run from the project root; this test requires sudo and refuses an existing `s1` bridge. Traffic is limited to three Mininet hosts on the isolated local topology.

```bash
RYU_SOURCE_DIR="${RYU_SOURCE_DIR:-$HOME/.cache/sdn-defense/ryu-stage2/d6cda4f427ff8de82b94c58aa826824a106014c2}"
sudo env \
  PATH="$PWD/.venv/bin:$PWD/.venv-ryu/bin:$PATH" \
  PYTHONPATH="$PWD:$RYU_SOURCE_DIR" \
  RYU_SOURCE_DIR="$RYU_SOURCE_DIR" \
  SDN_STAGE2_RYU_MANAGER="$PWD/.venv-ryu/bin/ryu-manager" \
  /usr/bin/python3 scripts/run_stage7_detection_enforcement.py
```

The report and Ryu log are written to `/tmp/stage7-detection-enforcement.json` and `/tmp/stage7-detection-enforcement-ryu.log`. The run validates baseline connectivity, protected-flow monitor behavior, a synthetic very-high-risk exact tuple block, independent OVS confirmation, unrelated-flow preservation, exact rollback, TTL expiry/rollback, and cleanup. RATE_LIMIT remains unsupported.

The opt-in pytest integration is `tests/system/test_stage7_detection_enforcement.py`, enabled with `SDN_STAGE7_RUN_DETECTION_INTEGRATION=1` under root. Ordinary pytest does not start Mininet or change network state.

## Scope limits

This proves only that a typed synthetic result can traverse the existing policy, action, orchestrator, Ryu adapter, OVS, and independent verifier. It does not establish ML feature parity, detector calibration, attack detection, attack containment, policy comparison outcomes, or autonomous-defense effectiveness.
