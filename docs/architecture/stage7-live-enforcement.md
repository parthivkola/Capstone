# Stage 7 Live Enforcement Boundary

This milestone adds a local enforcement orchestrator and a controlled Mininet/OVS/Ryu validation harness. It does not connect a detector, evaluate Policies A–D on attack traffic, or change the frozen [Stage 7 protocol](../research/stage7-safe-autonomous-defense-protocol.md).

## Responsibility boundary

```text
MitigationAction
      ↓ exact-scope/protected-flow checks
MitigationOrchestrator
      ├── adapter.apply() → SUBMITTED (local request only)
      ├── OvsFlowVerifier → CONFIRMED (independent switch-state observation)
      ├── TTL → exact rollback request
      └── adapter.rollback() → SUBMITTED → OVS absence observation → ROLLED_BACK
```

`RiskPolicy` does not import Ryu or OVS. The orchestrator accepts an adapter and a switch-state verifier through small protocols. `SocketRyuMitigationAdapter` sends a bounded action request to a Ryu app bound only to `127.0.0.1`; the Ryu app uses the existing Stage 7 OpenFlow adapter and connected datapath map. The orchestrator then polls `ovs-ofctl -O OpenFlow13 dump-flows` independently.

`SUBMITTED` means the local adapter/Ryu gateway returned after sending the FlowMod. It is not a switch acknowledgement. `CONFIRMED` is emitted only if an independent OVS flow dump contains the expected cookie, the expected scope selectors, and a drop action. Confirmation time and elapsed latency are recorded. Rollback is reported `ROLLED_BACK` only after an independent dump no longer contains the action cookie. A query error or timeout is `FAILED`, never confirmation.

The OVS verifier targets one configured local bridge and rejects unsafe bridge names. A bridge-scoped dump is the independent state source; datapath ID is also included in the event. The live harness compares the DPID in the action scope to the bridge discovered from the one-switch topology.

## Local live validation

The script runs only a small UDP echo test between the existing h1, h2, and h3 Mininet hosts. It first checks target and non-target traffic, then verifies a single exact `(datapath, source IP, destination IP, UDP destination port)` block, unrelated traffic, strict action rollback, and a separate two-second test TTL. It also checks protected-scope rejection, missing datapath handling, and unsupported rate limiting. The short TTL is a test fixture and does not change production TTL values in the frozen protocol. No Stage 3 attack scenario is started.

Run from the repository root on an isolated Fedora development host. The command requires root because Mininet/OVS modify network namespaces and bridges. It refuses to start if an `s1` bridge already exists.

Stage 7 uses the established OpenFlow controller port `127.0.0.1:6653`; the separate loopback action gateway remains on port `16654`. The earlier Stage 7 port `16653` was labeled `unreserved_port_t` by this Fedora host's SELinux policy, and an AVC denial blocked `ovs-vswitchd` from connecting. Port `6653` follows the existing Stage 2 configuration and the host's `openflow_port_t` labeling. No SELinux policy change was made or is required for this configuration. This is an environment-specific compatibility choice. The privileged validation passed on 2026-10-08: OVS connected to Ryu, which discovered datapath `0000000000000001` over OpenFlow 1.3. The runner also independently confirmed exact-scope rule installation and rollback, traffic blocking and restoration, TTL expiry, protected-scope rejection, and unsupported rate limiting. An initial run exposed an inverted target-probe assertion; the assertion was corrected to match `udp_probe`'s boolean contract before the passing run.

```bash
RYU_SOURCE_DIR="${RYU_SOURCE_DIR:-$HOME/.cache/sdn-defense/ryu-stage2/d6cda4f427ff8de82b94c58aa826824a106014c2}"
sudo env \
  PATH="$PWD/.venv/bin:$PWD/.venv-ryu/bin:$PATH" \
  PYTHONPATH="$PWD:$RYU_SOURCE_DIR" \
  RYU_SOURCE_DIR="$RYU_SOURCE_DIR" \
  SDN_STAGE2_RYU_MANAGER="$PWD/.venv-ryu/bin/ryu-manager" \
  /usr/bin/python3 scripts/run_stage7_live_validation.py
```

The machine-readable run report is written to `/tmp/stage7-live-validation.json`; the Ryu log is `/tmp/stage7-live-ryu.log`. Set `SDN_STAGE7_VALIDATION_REPORT` before `sudo env` to choose a different report path. Cleanup runs in `finally`: host echo processes stop, tracked rules are rolled back when possible, Mininet stops, and Ryu receives SIGINT with bounded termination fallback. A cleanup error is recorded in the report.

The equivalent opt-in system test is kept separate from unit tests:

```bash
sudo env \
  PATH="$PWD/.venv/bin:$PWD/.venv-ryu/bin:$PATH" \
  PYTHONPATH="$PWD:$RYU_SOURCE_DIR" \
  RYU_SOURCE_DIR="$RYU_SOURCE_DIR" \
  SDN_STAGE2_RYU_MANAGER="$PWD/.venv-ryu/bin/ryu-manager" \
  SDN_STAGE7_VALIDATION_PYTHON=/usr/bin/python3 \
  SDN_STAGE7_RUN_LIVE_TESTS=1 \
  "$PWD/.venv/bin/pytest" tests/system/test_stage7_live_enforcement.py
```

Ordinary `pytest` skips this privileged test unless `SDN_STAGE7_RUN_LIVE_TESTS=1` is explicitly set.

## Capability evidence and current limits

The development host reports Open vSwitch `3.6.2-1.fc44`; Ryu manager `4.34` starts from the pinned Python 3.11 environment. The OVS CLI advertises OpenFlow 1.3 selection, flow dumps, and meter-feature commands. Those CLI commands alone do not establish a live bridge capability.

In the current non-root inspection, `openvswitch` was active, but reading `/var/run/openvswitch/db.sock` failed with `Permission denied`; no bridge, controller connection, datapath ID, installed rule, switch match support, cookie visibility, or meter features could therefore be observed in this session. The live runner records these values from the actual `s1` bridge when successfully run as root. Until that run passes, real OVS enforcement is **unverified** and `CONFIRMED` has not been observed in a live network.

Rate limiting remains unsupported by the mitigation adapter even if an OVS meter feature query later succeeds. Meter installation, rate/burst policy, and rollback have not been implemented or verified. The Stage 7 Ryu gateway defaults its flow-mod capability off; the controlled runner enables it only for its isolated local validation process after its bridge/controller checks. The gateway is not attached to the production Stage 2 controller entry point and is not a detector-to-Ryu pipeline.

The Ryu 4.34 runtime emitted the existing Eventlet deprecation warning and a green-thread `RLock` warning during startup smoke validation. The gateway and Stage 2 controller did start and bind loopback/OpenFlow test ports, but no switch connected in that unprivileged smoke check.
