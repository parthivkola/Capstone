"""Run the synthetic Stage 7 detection-to-real-OVS integration validation.

This requires root, the isolated Stage 2 Mininet topology, local OVS, and the
pinned Ryu runtime. It uses synthetic detector records and bounded UDP echo
probes only; it does not load ML models or run attack scenarios.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from time import sleep
from typing import Any

from networking.ovs.verification import OvsFlowVerifier
from networking.ryu.stage7_socket_adapter import SocketRyuMitigationAdapter
from scripts.run_stage7_live_validation import (
    BRIDGE,
    CONTROLLER_PORT,
    GATEWAY_PORT,
    _tcp_open,
    require,
    run,
    udp_probe,
    udp_server,
    verify_preconditions,
    wait_for,
)
from services.detection.synthetic_fixtures import SyntheticCase, make_synthetic_detection
from services.mitigation.integration import DetectionEnforcementService
from services.mitigation.orchestrator import MitigationOrchestrator, OrchestrationConfig
from services.mitigation.policy import PolicyMode, ProtectedFlow, RiskPolicy, RiskPolicyConfig
from src.sdn_defense.contracts import (
    ActionType,
    ConfidenceThresholds,
    EnforcementStatus,
)

ROOT = Path.cwd()
REPORT_PATH = Path(
    os.environ.get("SDN_STAGE7_INTEGRATION_REPORT", "/tmp/stage7-detection-enforcement.json")
)
PROTOCOL_PATH = ROOT / "experiments/stage7/defense-protocol.json"


def _mitigation_cookies(flow_dump: str) -> set[str]:
    """Return nonzero flow cookies so packet counters do not affect safety checks."""

    cookies = set(re.findall(r"\bcookie=0x([0-9a-fA-F]+)", flow_dump))
    return {cookie.lower() for cookie in cookies if int(cookie, 16) != 0}


def _make_policy() -> RiskPolicy:
    protocol = json.loads(PROTOCOL_PATH.read_text(encoding="utf-8"))
    # These cutoffs are synthetic fixture values solely to traverse the frozen
    # policy branches. They are not validation-calibrated detector thresholds.
    thresholds = ConfidenceThresholds(0.2, 0.5, 0.8, "synthetic-integration-fixture-only")
    return RiskPolicy(
        RiskPolicyConfig.from_protocol(
            protocol,
            thresholds,
            persistence_observations=2,
            observation_interval_seconds=2.0,
        )
    )


def _trace_dict(trace: Any) -> dict[str, object]:
    action = trace.action
    return {
        "detection": {
            "event_id": trace.detection.event_id,
            "classification": trace.detection.classification.value,
            "confidence": trace.detection.confidence,
            "attack_score": trace.detection.attack_score,
            "provenance": trace.detection.provenance,
            "scope": None
            if trace.detection.scope is None
            else {
                "kind": trace.detection.scope.kind.value,
                "selectors": dict(trace.detection.scope.selectors),
            },
        },
        "decision": {
            "decision_id": trace.decision.decision_id,
            "result_id": trace.decision.result_id,
            "risk_level": trace.decision.risk_level.value,
            "action": trace.decision.action.value,
            "reason": trace.decision.reason,
            "policy_version": trace.decision.policy_version,
            "policy_arm": trace.decision.policy_arm,
            "uncertain": trace.decision.uncertain,
        },
        "action": None
        if action is None
        else {
            "action_id": action.action_id,
            "decision_id": action.decision_id,
            "action": action.action.value,
            "scope": {
                "kind": action.scope.kind.value,
                "selectors": dict(action.scope.selectors),
            },
            "reason": action.reason,
            "evidence_refs": list(action.evidence_refs),
            "policy_version": action.policy_version,
            "created_at": action.created_at.isoformat(),
            "expires_at": action.expires_at.isoformat(),
            "ttl_seconds": action.ttl_seconds,
            "extension_count": action.extension_count,
            "rollback_state": action.rollback_state.value,
        },
        "enforcement_events": [event.to_dict() for event in trace.enforcement_events],
        "audit_events": [event.to_dict() for event in trace.audit_events],
    }


def main() -> int:
    require(os.geteuid() == 0, "run with sudo: Mininet/OVS integration requires root")
    report: dict[str, Any] = {
        "result": "INCOMPLETE",
        "started_at": datetime.now(UTC).isoformat(),
        "environment": {},
        "checks": {},
        "traces": [],
    }
    controller: subprocess.Popen[bytes] | None = None
    log_stream: Any | None = None
    network: Any | None = None
    servers: list[subprocess.Popen[bytes]] = []
    orchestrator: MitigationOrchestrator | None = None
    active_actions: list[str] = []
    try:
        report["environment"] = verify_preconditions()
        ryu_source = os.environ.get("RYU_SOURCE_DIR", "")
        require(bool(ryu_source and Path(ryu_source).is_dir()), "pinned RYU_SOURCE_DIR is required")
        manager = Path(os.environ.get("SDN_STAGE2_RYU_MANAGER", ".venv-ryu/bin/ryu-manager"))
        require(manager.is_file() and os.access(manager, os.X_OK), "Ryu manager is unavailable")
        env = {
            **os.environ,
            "PYTHONPATH": os.pathsep.join(
                (str(ROOT), ryu_source, os.environ.get("PYTHONPATH", ""))
            ),
            "SDN_STAGE2_MONITOR_INTERVAL_SECONDS": "1.0",
            "SDN_STAGE7_GATEWAY_PORT": str(GATEWAY_PORT),
            "SDN_STAGE7_FLOW_MOD_VERIFIED": "true",
        }
        log_path = Path("/tmp/stage7-detection-enforcement-ryu.log")
        log_stream = log_path.open("wb")
        controller = subprocess.Popen(
            [
                str(manager),
                "--ofp-tcp-listen-port",
                str(CONTROLLER_PORT),
                "networking.ryu.stage2_controller",
                "networking.ryu.stage7_gateway",
            ],
            cwd=ROOT,
            env=env,
            stdout=log_stream,
            stderr=subprocess.STDOUT,
        )
        wait_for(
            lambda: _tcp_open("127.0.0.1", CONTROLLER_PORT), 15, "Ryu OpenFlow listener failed"
        )
        wait_for(lambda: _tcp_open("127.0.0.1", GATEWAY_PORT), 15, "Ryu action gateway failed")

        from networking.mininet.config import TopologyConfig
        from networking.mininet.stage2_topology import create_network

        network = create_network(TopologyConfig("127.0.0.1", CONTROLLER_PORT))
        h1, h2, h3 = network.get("h1"), network.get("h2"), network.get("h3")
        protocols = run(["ovs-vsctl", "get", "bridge", BRIDGE, "protocols"])
        controller_target = run(["ovs-vsctl", "get-controller", BRIDGE])
        dpid_result = run(["ovs-vsctl", "get", "bridge", BRIDGE, "datapath_id"])
        require(
            protocols.returncode == 0 and "OpenFlow13" in protocols.stdout,
            "OpenFlow 1.3 not active",
        )
        require(
            controller_target.returncode == 0 and "127.0.0.1:6653" in controller_target.stdout,
            "OVS target mismatch",
        )
        require(dpid_result.returncode == 0, f"cannot read DPID: {dpid_result.stderr}")
        datapath_id = dpid_result.stdout.strip().strip('"').removeprefix("0x").zfill(16)
        log_text = Path(log_path).read_text(errors="replace")
        wait_for(
            lambda: (
                '"datapath_id": "' + datapath_id + '"' in Path(log_path).read_text(errors="replace")
                and "stage7_datapath_connected" in Path(log_path).read_text(errors="replace")
            ),
            10,
            "Ryu did not discover the expected datapath",
        )
        report["environment"].update(
            {
                "bridge": BRIDGE,
                "controller": controller_target.stdout.strip(),
                "openflow_protocol": protocols.stdout.strip(),
                "datapath_id": datapath_id,
                "ryu_log": str(log_path),
                "discovery_log_seen": "stage7_datapath_connected" in log_text,
            }
        )

        servers.extend((udp_server(h2, 18081), udp_server(h2, 18082), udp_server(h3, 18081)))
        sleep(0.25)
        require(udp_probe(h1, "10.0.0.2", 18081, expect_reply=True), "baseline h1→h2 failed")
        require(udp_probe(h1, "10.0.0.3", 18081, expect_reply=True), "baseline h1→h3 failed")
        require(udp_probe(h1, "10.0.0.2", 18082, expect_reply=True), "baseline non-target failed")

        verifier = OvsFlowVerifier(BRIDGE)
        adapter = SocketRyuMitigationAdapter(port=GATEWAY_PORT, flow_mod_support_verified=True)
        orchestrator = MitigationOrchestrator(adapter, verifier, config=OrchestrationConfig(3.0))
        service = DetectionEnforcementService(_make_policy(), orchestrator, adapter.capabilities)

        protected_now = datetime.now(UTC)
        protected_result = make_synthetic_detection(
            SyntheticCase.VERY_HIGH_ATTACK,
            event_id="synthetic-protected-scope",
            observed_at=protected_now,
            datapath_id=datapath_id,
        )
        require(protected_result.scope is not None, "protected fixture lacks scope")
        protected_before = _mitigation_cookies(verifier.dump_flows())
        protected_trace = service.process(
            protected_result,
            now=protected_now,
            mode=PolicyMode.RISK_AWARE_REVERSIBLE,
            protected_flows=(ProtectedFlow(protected_result.scope, "synthetic protected flow"),),
        )
        protected_after = _mitigation_cookies(verifier.dump_flows())
        require(
            protected_trace.decision.action is ActionType.MONITOR,
            "protected result was not monitored",
        )
        require(protected_trace.action is None, "protected result created an action")
        require(protected_before == protected_after, "protected result installed a mitigation rule")
        report["traces"].append(_trace_dict(protected_trace))

        result_now = datetime.now(UTC)
        result = make_synthetic_detection(
            SyntheticCase.VERY_HIGH_ATTACK,
            event_id="synthetic-live-very-high",
            observed_at=result_now,
            datapath_id=datapath_id,
        )
        trace = service.process(
            result,
            now=result_now,
            mode=PolicyMode.RISK_AWARE_REVERSIBLE,
        )
        require(trace.action is not None, "high-risk synthetic result created no action")
        action = trace.action
        require(trace.decision.action is ActionType.BLOCK, "synthetic fixture did not reach BLOCK")
        require(
            trace.enforcement_events[-1].status is EnforcementStatus.CONFIRMED,
            "OVS did not confirm block",
        )
        require(
            trace.enforcement_events[-1].observed_present is True,
            "confirmation lacks observed-present state",
        )
        active_actions.append(action.action_id)
        require(
            udp_probe(h1, "10.0.0.2", 18081, expect_reply=False), "target traffic was not blocked"
        )
        require(
            udp_probe(h1, "10.0.0.2", 18082, expect_reply=True), "non-target h2 flow was disrupted"
        )
        require(udp_probe(h1, "10.0.0.3", 18081, expect_reply=True), "h3 flow was disrupted")
        report["traces"].append(_trace_dict(trace))
        report["checks"].update(
            {
                "baseline_h1_h2": "PASS",
                "baseline_h1_h3": "PASS",
                "synthetic_detection_to_decision_to_action": "PASS",
                "action_submitted_and_ovs_confirmed": "PASS",
                "target_traffic_blocked": "PASS",
                "unrelated_traffic_preserved": "PASS",
                "protected_scope_safe_monitor": "PASS",
            }
        )

        rollback_event = orchestrator.rollback(
            action.action_id, reason="synthetic integration rollback"
        )
        active_actions.remove(action.action_id)
        require(
            rollback_event.status is EnforcementStatus.ROLLED_BACK,
            "rollback was not independently confirmed",
        )
        require(rollback_event.observed_present is False, "rollback lacks OVS absence evidence")
        require(udp_probe(h1, "10.0.0.2", 18081, expect_reply=True), "target flow did not recover")
        require(
            udp_probe(h1, "10.0.0.3", 18081, expect_reply=True), "unrelated flow did not recover"
        )
        report["rollback_event"] = rollback_event.to_dict()
        report["checks"].update(
            {"rollback_confirmed_absent_in_ovs": "PASS", "traffic_recovered": "PASS"}
        )

        ttl_result = make_synthetic_detection(
            SyntheticCase.VERY_HIGH_ATTACK,
            event_id="synthetic-live-ttl",
            observed_at=datetime.now(UTC),
            datapath_id=datapath_id,
        )
        ttl_trace = service.process(
            ttl_result,
            now=ttl_result.observed_at,
            mode=PolicyMode.RISK_AWARE_REVERSIBLE,
        )
        require(ttl_trace.action is not None, "TTL fixture created no action")
        require(
            ttl_trace.enforcement_events[-1].status is EnforcementStatus.CONFIRMED,
            "TTL action not confirmed",
        )
        ttl_action = ttl_trace.action
        active_actions.append(ttl_action.action_id)
        require(
            udp_probe(h1, "10.0.0.2", 18081, expect_reply=False), "TTL action did not block target"
        )
        delay = max(0.0, (ttl_action.expires_at - datetime.now(UTC)).total_seconds()) + 0.15
        sleep(delay)
        ttl_event = orchestrator.expire(ttl_action.action_id, now=datetime.now(UTC))
        active_actions.remove(ttl_action.action_id)
        require(ttl_event.status is EnforcementStatus.ROLLED_BACK, "TTL rollback not confirmed")
        require(ttl_event.observed_present is False, "TTL rollback lacks OVS absence evidence")
        require(
            udp_probe(h1, "10.0.0.2", 18081, expect_reply=True), "traffic did not recover after TTL"
        )
        report["traces"].append(_trace_dict(ttl_trace))
        report["ttl_events"] = [
            event.to_dict()
            for event in orchestrator.events
            if event.action_id == ttl_action.action_id
        ]
        report["checks"]["ttl_expiry_rollback_and_recovery"] = "PASS"
        report["result"] = "PASS"
        return 0
    except Exception as error:
        report["result"] = "FAIL"
        report["failure"] = f"{type(error).__name__}: {error}"
        return 1
    finally:
        for server in servers:
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=2)
        if orchestrator is not None:
            for action_id in tuple(active_actions):
                try:
                    orchestrator.rollback(action_id, reason="failure cleanup")
                except Exception as error:
                    report.setdefault("cleanup_errors", []).append(str(error))
        if network is not None:
            try:
                network.stop()
            except Exception as error:
                report.setdefault("cleanup_errors", []).append(f"Mininet cleanup: {error}")
        if controller is not None and controller.poll() is None:
            controller.send_signal(signal.SIGINT)
            try:
                controller.wait(timeout=10)
            except subprocess.TimeoutExpired:
                controller.terminate()
                try:
                    controller.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    controller.kill()
                    controller.wait(timeout=3)
        if log_stream is not None:
            log_stream.close()
        report["finished_at"] = datetime.now(UTC).isoformat()
        REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        REPORT_PATH.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"Stage 7 detection integration {report['result']}: {REPORT_PATH}")


if __name__ == "__main__":
    sys.exit(main())
