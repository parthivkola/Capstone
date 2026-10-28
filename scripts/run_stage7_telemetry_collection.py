"""Collect one local benign and one bounded port-scan telemetry run.

Run this script as root from the project root on the Fedora SDN development host.
It starts only the local Stage 2 Ryu controller and the fixed isolated Mininet
topology. No Stage 7 gateway, policy, mitigation, detector, or model is loaded.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from networking.mininet.config import TopologyConfig  # noqa: E402
from networking.mininet.stage3_config import Scenario  # noqa: E402
from networking.mininet.stage3_scenarios import _write_experiment_context  # noqa: E402
from networking.ryu.packet_evidence import PacketEvidencePolicy  # noqa: E402
from src.sdn_defense.telemetry import ScenarioRunMetadata  # noqa: E402
from src.sdn_defense.telemetry_io import validate_telemetry_jsonl  # noqa: E402

H3_IP = "10.0.0.3"
PACKET_EVIDENCE_COOKIE = PacketEvidencePolicy().flow_cookie
WORKER_WALL_TIMEOUT_SECONDS = 180.0
INTERRUPT_GRACE_SECONDS = 5.0
TERMINATE_GRACE_SECONDS = 3.0
KILL_GRACE_SECONDS = 3.0
PORT_SCAN_TIMEOUT_SECONDS = 25.0


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _ensure_prerequisites() -> None:
    if os.geteuid() != 0:
        raise PermissionError("local telemetry collection requires root for Mininet/OVS")
    for executable in ("mn", "ovs-vsctl", "ovs-ofctl"):
        if shutil.which(executable) is None:
            raise RuntimeError(f"required executable is unavailable: {executable}")
    service = subprocess.run(
        ["systemctl", "is-active", "--quiet", "openvswitch"], check=False, timeout=5
    )
    if service.returncode:
        raise RuntimeError("Open vSwitch service must already be active")
    if subprocess.run(["ovs-vsctl", "br-exists", "s1"], check=False, timeout=5).returncode == 0:
        raise RuntimeError("refusing to run: bridge s1 already exists")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.2)
        try:
            probe.connect(("127.0.0.1", 6653))
        except OSError:
            pass
        else:
            raise RuntimeError("refusing to run: a process already listens on 127.0.0.1:6653")


def _wait_controller(process: subprocess.Popen[bytes], timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Ryu exited before readiness (status {process.returncode})")
        try:
            with socket.create_connection(("127.0.0.1", 6653), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError("Ryu did not listen on 127.0.0.1:6653 within 20 seconds")


def _assert_controller_alive(process: subprocess.Popen[bytes], phase: str) -> None:
    return_code = process.poll()
    if return_code is not None:
        raise RuntimeError(f"Ryu exited during {phase} (status {return_code})")


def _proc_usage(pid: int) -> dict[str, float | int] | None:
    """Read approximate child CPU and kernel high-water RSS from procfs."""

    try:
        status = Path(f"/proc/{pid}/status").read_text(encoding="ascii")
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except OSError:
        return None
    fields = stat.rsplit(")", 1)[-1].split()
    if len(fields) < 13:
        return None
    clock_ticks = os.sysconf("SC_CLK_TCK")
    cpu_seconds = (int(fields[11]) + int(fields[12])) / clock_ticks
    vm_hwm = re.search(r"^VmHWM:\s+(\d+)\s+kB$", status, re.MULTILINE)
    rss_high_water_kib = int(vm_hwm.group(1)) if vm_hwm else 0
    return {"cpu_seconds": cpu_seconds, "rss_high_water_kib": rss_high_water_kib}


def _journal_packet_evidence_rule_check(journal_path: Path) -> dict[str, object]:
    """Independently inspect the switch's before/after flow dumps from the run journal."""

    dumps: dict[str, str] = {}
    for line in journal_path.read_text(encoding="utf-8").splitlines():
        parsed = json.loads(line)
        if not isinstance(parsed, dict):
            continue
        item: dict[str, Any] = parsed
        if item.get("event_type") == "switch_observation":
            label = item.get("label")
            if isinstance(label, str) and isinstance(item.get("flow_dump"), str):
                dumps[label] = item["flow_dump"]
    expected_cookie = f"cookie=0x{PACKET_EVIDENCE_COOKIE:x}"
    before = [line for line in dumps.get("before", "").splitlines() if expected_cookie in line]
    after = [line for line in dumps.get("after", "").splitlines() if expected_cookie in line]
    expected_rule_count = len(PacketEvidencePolicy().destination_ports)
    if len(before) != expected_rule_count or len(after) != expected_rule_count:
        raise RuntimeError(
            f"expected {expected_rule_count} packet-evidence rules before/after probes; "
            f"observed {len(before)}/{len(after)}"
        )
    expected_controller_action = f"CONTROLLER:{PacketEvidencePolicy().controller_copy_max_bytes}"
    if any(
        expected_controller_action not in line or "output:3" not in line or "tcp_flags" in line
        for line in before
    ):
        raise RuntimeError("packet-evidence rule did not preserve the fixed h3 output action")
    return {
        "cookie": f"0x{PACKET_EVIDENCE_COOKIE:x}",
        "rules_before": len(before),
        "rules_after": len(after),
        "matched_packets_after": sum(
            int(match.group(1))
            for line in after
            if (match := re.search(r"n_packets=(\d+)", line)) is not None
        ),
        "tcp_flags_match_absent": True,
        "controller_output_and_h3_output_verified": True,
    }


def _wait_packet_evidence_rules(timeout_seconds: float = 5.0) -> dict[str, object]:
    """Wait for the exact opt-in observer rule set and verify its bounded actions."""

    cookie = f"cookie=0x{PACKET_EVIDENCE_COOKIE:x}"
    deadline = time.monotonic() + timeout_seconds
    observed: list[str] = []
    while time.monotonic() < deadline:
        result = subprocess.run(
            ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s1"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        observed = [line for line in result.stdout.splitlines() if cookie in line]
        if len(observed) == len(PacketEvidencePolicy().destination_ports):
            break
        time.sleep(0.05)
    if len(observed) != len(PacketEvidencePolicy().destination_ports):
        raise RuntimeError(f"expected eight bounded packet-evidence rules, found {len(observed)}")
    controller_action = f"CONTROLLER:{PacketEvidencePolicy().controller_copy_max_bytes}"
    if any(controller_action not in line or "output:3" not in line for line in observed):
        raise RuntimeError("observer rules do not copy bounded headers and preserve h3 output")
    return {
        "cookie": f"0x{PACKET_EVIDENCE_COOKIE:x}",
        "rules_observed": len(observed),
        "controller_output_and_h3_output_verified": True,
    }


def _packet_evidence_run_summary(path: Path, run_id: str) -> dict[str, object]:
    observations: list[dict[str, object]] = []
    coverage: dict[str, object] | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        parsed: object = json.loads(line)
        if not isinstance(parsed, dict):
            continue
        item: dict[str, Any] = parsed
        if item.get("record_type") == "telemetry_observation":
            observation = item.get("observation", {})
            if (
                isinstance(observation, dict)
                and observation.get("run_id") == run_id
                and observation.get("source") == "ryu_openflow_bounded_packet_copy"
            ):
                observations.append(observation)
        elif item.get("record_type") == "packet_evidence_coverage" and item.get("run_id") == run_id:
            coverage = item
    payloads: list[dict[str, Any]] = []
    for observation in observations:
        payload = observation.get("payload")
        if isinstance(payload, dict):
            payloads.append(payload)
    tuples = {
        (
            payload.get("src_ip"),
            payload.get("dst_ip"),
            payload.get("src_port"),
            payload.get("dst_port"),
        )
        for payload in payloads
    }
    def integer_values(key: str) -> list[int]:
        values: set[int] = set()
        for payload in payloads:
            value = payload.get(key)
            if isinstance(value, int):
                values.add(value)
        return sorted(values)

    return {
        "run_id": run_id,
        "accepted_packet_observations": len(observations),
        "unique_source_destination_tuples": len(tuples),
        "unique_destination_ports": integer_values("dst_port"),
        "tcp_flag_values": integer_values("tcp_bits"),
        "coverage": coverage,
    }


def _split_telemetry_by_run(
    source: Path, run_ids: dict[str, str], output_dir: Path
) -> dict[str, Path]:
    """Copy raw records into run-scoped views using only recorded lineage."""
    destinations = {
        scenario: output_dir / f"telemetry-{scenario}.jsonl" for scenario in run_ids
    }
    streams = {
        scenario: path.open("w", encoding="utf-8", newline="\n")
        for scenario, path in destinations.items()
    }
    try:
        for line_number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"invalid raw telemetry JSON at line {line_number}") from error
            if not isinstance(record, dict):
                raise ValueError(f"raw telemetry line {line_number} is not an object")
            if record.get("record_type") == "recorder_metadata":
                for stream in streams.values():
                    stream.write(line + "\n")
                continue
            run_id = record.get("run_id")
            if run_id is None and record.get("record_type") in {
                "telemetry_observation",
                "observation_window",
            }:
                nested = record.get("observation") or record.get("observation_window")
                if isinstance(nested, dict):
                    run_id = nested.get("run_id")
            matching = [scenario for scenario, candidate in run_ids.items() if candidate == run_id]
            if len(matching) == 1:
                streams[matching[0]].write(line + "\n")
    finally:
        for stream in streams.values():
            stream.close()
    return destinations


def _benign_metadata(run_id: str, config: TopologyConfig) -> ScenarioRunMetadata:
    now = _utc_now()
    config_payload = {
        "topology": "stage2-three-host-s1-v1",
        "controller_host": config.controller_host,
        "controller_port": config.controller_port,
        "scenario_id": "controlled-connectivity-observation",
        "ports": [],
    }
    topology_config_id = hashlib.sha256(
        json.dumps(config_payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return ScenarioRunMetadata(
        run_id=run_id,
        scenario_id="controlled-connectivity-observation",
        start_at=now,
        end_at=None,
        topology_config_id=topology_config_id,
        source_scope=(("host", "h1"), ("ip", "10.0.0.1")),
        destination_scope=(("host", "h3"), ("ip", H3_IP)),
        protocol="ICMP",
        ports=(),
    )


def _run_benign(
    config: TopologyConfig,
    context_path: Path,
    journal_path: Path,
    run_id: str,
    *,
    packet_evidence_enabled: bool,
) -> None:
    metadata = _benign_metadata(run_id, config)
    context_path.parent.mkdir(parents=True, exist_ok=True)
    _write_experiment_context(context_path, metadata, active=True)
    journal_path.write_text(
        json.dumps(
            {
                "record_type": "run_metadata",
                "schema_version": 1,
                "run_id": run_id,
                "metadata": metadata.to_dict(),
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    network: Any | None = None
    completed = False
    try:
        from networking.mininet.stage2_topology import create_network

        network = create_network(config)
        if packet_evidence_enabled:
            rule_state = _wait_packet_evidence_rules()
            with journal_path.open("a", encoding="utf-8") as stream:
                stream.write(
                    json.dumps(
                        {
                            "record_type": "packet_evidence_rules",
                            "state": "active",
                            "timestamp": _utc_now().isoformat(),
                            **rule_state,
                        },
                        sort_keys=True,
                    )
                    + "\n"
                )
        h1 = network.get("h1")
        warmup = h1.cmd(f"timeout --signal=TERM --kill-after=1s 5s ping -c 1 -W 1 {H3_IP}")
        with journal_path.open("a", encoding="utf-8") as stream:
            stream.write(
                json.dumps(
                    {
                        "record_type": "connectivity_warmup",
                        "run_id": run_id,
                        "result": warmup.strip()[-2000:],
                        "may_include_initial_arp_resolution": True,
                    },
                    sort_keys=True,
                )
                + "\n"
            )
        for sequence in range(1, 7):
            result = h1.cmd(f"timeout --signal=TERM --kill-after=1s 5s ping -c 1 -W 1 {H3_IP}")
            with journal_path.open("a", encoding="utf-8") as stream:
                stream.write(
                    json.dumps(
                        {
                            "record_type": "connectivity_observation",
                            "run_id": run_id,
                            "sequence": sequence,
                            "result": result.strip()[-2000:],
                            "successful": (
                                "1 received" in result or "1 packets received" in result
                            ),
                        },
                        sort_keys=True,
                    )
                    + "\n"
                )
            if "1 received" not in result and "1 packets received" not in result:
                raise RuntimeError(
                    f"bounded h1-to-h3 connectivity observation {sequence} failed; "
                    "inspect benign-run.jsonl"
                )
            time.sleep(1)
        time.sleep(2.5)  # Permit multiple controller polling intervals to complete.
        completed = True
    finally:
        end = _utc_now()
        ended = ScenarioRunMetadata(
            run_id=metadata.run_id,
            scenario_id=metadata.scenario_id,
            start_at=metadata.start_at,
            end_at=end,
            topology_config_id=metadata.topology_config_id,
            source_scope=metadata.source_scope,
            destination_scope=metadata.destination_scope,
            protocol=metadata.protocol,
            ports=metadata.ports,
        )
        try:
            _write_experiment_context(context_path, ended, active=False)
        finally:
            if network is not None:
                network.stop()
                if subprocess.run(["ovs-vsctl", "br-exists", "s1"], check=False).returncode == 0:
                    raise RuntimeError("benign run cleanup left bridge s1 and its flows behind")
                if packet_evidence_enabled:
                    with journal_path.open("a", encoding="utf-8") as stream:
                        stream.write(
                            json.dumps(
                                {
                                    "record_type": "packet_evidence_rules",
                                    "state": "removed_with_topology",
                                    "timestamp": _utc_now().isoformat(),
                                    "bridge_absent": True,
                                },
                                sort_keys=True,
                            )
                            + "\n"
                        )
            with journal_path.open("a", encoding="utf-8") as stream:
                stream.write(
                    json.dumps(
                        {
                            "record_type": "run_boundary",
                            "schema_version": 1,
                            "run_id": run_id,
                            "state": "ended",
                            "timestamp": end.isoformat(),
                            "run_status": "complete" if completed else "incomplete",
                        },
                        sort_keys=True,
                    )
                    + "\n"
                )


def _run_port_scan(
    config: TopologyConfig,
    context_path: Path,
    journal_path: Path,
    run_id: str,
) -> None:
    environment = os.environ.copy()
    environment["SDN_OBSERVATION_CONTEXT_FILE"] = str(context_path)
    environment["SDN_STAGE2_CONTROLLER_HOST"] = config.controller_host
    environment["SDN_STAGE2_CONTROLLER_PORT"] = str(config.controller_port)
    command = [
        sys.executable,
        "-m",
        "networking.mininet.stage3_scenarios",
        Scenario.PORT_SCAN.value,
        "--duration",
        "8",
        "--rate",
        "1",
        "--run-id",
        run_id,
        "--log-file",
        str(journal_path),
    ]
    process = subprocess.Popen(
        command,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=PORT_SCAN_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=2)
    evidence = {
        "argv": command,
        "pid": process.pid,
        "return_code": process.returncode,
        "timeout": timed_out,
        "timeout_seconds": PORT_SCAN_TIMEOUT_SECONDS,
        "stdout": stdout[-4000:],
        "stderr": stderr[-4000:],
    }
    journal_path.with_name("port-scan-process.json").write_text(
        json.dumps(evidence, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    if timed_out:
        raise TimeoutError(f"port scan exceeded {PORT_SCAN_TIMEOUT_SECONDS:g}s")
    if process.returncode != 0:
        raise RuntimeError(f"port scan exited {process.returncode}; see port-scan-process.json")


def _run_collection_worker(
    output_dir: Path, ryu_manager: Path, *, packet_evidence_enabled: bool = False
) -> dict[str, object]:
    _ensure_prerequisites()
    output_dir = output_dir.resolve()
    ryu_manager = ryu_manager.resolve()
    if not ryu_manager.is_file() or not os.access(ryu_manager, os.X_OK):
        raise RuntimeError(f"Ryu manager is not executable: {ryu_manager}")
    output_dir.mkdir(parents=True, exist_ok=True)
    context_path = output_dir / "active-run-context.json"
    telemetry_path = output_dir / "telemetry.jsonl"
    ryu_log_path = output_dir / "ryu.log"
    config = TopologyConfig.from_environment()
    config.validate()
    environment = os.environ.copy()
    environment["SDN_OBSERVATION_CONTEXT_FILE"] = str(context_path)
    environment["SDN_TELEMETRY_JSONL"] = str(telemetry_path)
    environment["SDN_STAGE2_RUN_TELEMETRY_DIR"] = str(output_dir / "live-stream")
    environment["SDN_STAGE2_INSTALL_TEST_RULE"] = "false"
    environment["SDN_STAGE2_RECORD_PACKETIN_TELEMETRY"] = "false"
    environment["SDN_STAGE2_PACKET_EVIDENCE_ENABLED"] = (
        "true" if packet_evidence_enabled else "false"
    )
    root = Path(__file__).resolve().parents[1]
    existing_pythonpath = environment.get("PYTHONPATH", "")
    environment["PYTHONPATH"] = str(root) + (
        os.pathsep + existing_pythonpath if existing_pythonpath else ""
    )
    with ryu_log_path.open("wb") as log_stream:
        controller_command = [
            str(ryu_manager),
            "--ofp-tcp-listen-port",
            "6653",
            "networking.ryu.stage2_controller",
        ]
        controller = subprocess.Popen(
            controller_command,
            cwd=root,
            env=environment,
            stdout=log_stream,
            stderr=subprocess.STDOUT,
        )
        start_usage = _proc_usage(controller.pid)
        after_benign_usage: dict[str, float | int] | None = None
        after_scan_usage: dict[str, float | int] | None = None
        try:
            _wait_controller(controller)
            benign_id = str(uuid.uuid4())
            _run_benign(
                config,
                context_path,
                output_dir / "benign-run.jsonl",
                benign_id,
                packet_evidence_enabled=packet_evidence_enabled,
            )
            after_benign_usage = _proc_usage(controller.pid)
            _assert_controller_alive(controller, "benign collection")
            scan_id = str(uuid.uuid4())
            _run_port_scan(
                config,
                context_path,
                output_dir / "port-scan-run.jsonl",
                scan_id,
            )
            after_scan_usage = _proc_usage(controller.pid)
            _assert_controller_alive(controller, "port-scan collection")
            time.sleep(2.5)
        finally:
            if controller.poll() is None:
                controller.send_signal(signal.SIGINT)
                try:
                    controller.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    controller.terminate()
                    try:
                        controller.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        controller.kill()
                        controller.wait(timeout=3)
        if controller.poll() is None:
            raise RuntimeError("Ryu process did not stop after the bounded collection")
    if subprocess.run(["ovs-vsctl", "br-exists", "s1"], check=False).returncode == 0:
        raise RuntimeError("Mininet cleanup left bridge s1 behind")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.2)
        try:
            probe.connect((config.controller_host, config.controller_port))
        except OSError:
            pass
        else:
            raise RuntimeError("Ryu controller listener remains after cleanup")
    counts = validate_telemetry_jsonl(telemetry_path)
    telemetry_files = _split_telemetry_by_run(
        telemetry_path,
        {"controlled-connectivity-observation": benign_id, "port-scan": scan_id},
        output_dir,
    )
    scoped_counts = {
        scenario: validate_telemetry_jsonl(path)
        for scenario, path in telemetry_files.items()
    }
    packet_evidence: dict[str, object] = {
        "enabled": packet_evidence_enabled,
        "benign": _packet_evidence_run_summary(telemetry_path, benign_id)
        if packet_evidence_enabled
        else None,
        "port_scan": _packet_evidence_run_summary(telemetry_path, scan_id)
        if packet_evidence_enabled
        else None,
    }
    port_scan_rules = (
        _journal_packet_evidence_rule_check(output_dir / "port-scan-run.jsonl")
        if packet_evidence_enabled
        else None
    )
    final_usage = after_scan_usage
    resource_usage = {
        "measurement_source": "/proc/<ryu-pid>/stat and status",
        "sampling_overhead": "read-only procfs snapshots after each run",
        "start": start_usage,
        "after_benign_run": after_benign_usage,
        "after_port_scan_run": after_scan_usage,
        "cpu_seconds_change_total": (
            float(final_usage["cpu_seconds"]) - float(start_usage["cpu_seconds"])
            if final_usage is not None and start_usage is not None
            else None
        ),
        "peak_rss_kib_observed": max(
            (
                int(sample["rss_high_water_kib"])
                for sample in (start_usage, after_benign_usage, after_scan_usage)
                if sample is not None
            ),
            default=None,
        ),
    }
    log_text = ryu_log_path.read_text(encoding="utf-8", errors="replace")
    summary: dict[str, object] = {
        "schema_version": 1,
        "collection_id": os.environ.get("SDN_STAGE7_COLLECTION_ID"),
        "telemetry_file": telemetry_path.name,
        "telemetry_files": {key: value.name for key, value in telemetry_files.items()},
        "live_stream_directory": "live-stream",
        "scenario_journals": ["benign-run.jsonl", "port-scan-run.jsonl"],
        "run_ids": {"controlled-connectivity-observation": benign_id, "port-scan": scan_id},
        "record_counts": counts,
        "run_scoped_record_counts": scoped_counts,
        "packet_evidence": packet_evidence,
        "packet_evidence_rules": port_scan_rules,
        "controller_resource_usage": resource_usage,
        "eventlet_unpatched_rlock_warning": "RLock(s) were not greened" in log_text,
        "collection_only": True,
        "detection_or_mitigation": False,
    }
    (output_dir / "collection-summary.json").write_text(
        json.dumps(summary, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    return summary


def _interpreter_has_mininet(executable: str) -> bool:
    try:
        result = subprocess.run(
            [executable, "-c", "import mininet"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _select_mininet_interpreter() -> str:
    """Use the active Python when it owns Mininet, else the host Mininet Python."""
    candidates = list(dict.fromkeys((sys.executable, "/usr/bin/python3")))
    for candidate in candidates:
        if _interpreter_has_mininet(candidate):
            return candidate
    raise RuntimeError(
        "Mininet Python package is unavailable to the active interpreter and /usr/bin/python3; "
        "install/use the host interpreter that owns the installed Mininet package. "
        "No substitute module is used."
    )


def _run_isolation_preflight(interpreter: str, controller_port: int = 6653) -> dict[str, Any]:
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [
            interpreter,
            str(root / "scripts/preflight_stage7_lab.py"),
            "--json",
            "--ack-isolated-lab",
            "--controller-port",
            str(controller_port),
        ],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"lab preflight returned invalid JSON (exit {result.returncode}): "
            f"{result.stderr.strip() or result.stdout.strip()}"
        ) from error
    if not isinstance(payload, dict) or payload.get("status") != "PASS" or result.returncode != 0:
        blockers = payload.get("blockers", []) if isinstance(payload, dict) else []
        raise RuntimeError(f"isolated lab preflight failed: {blockers or result.stderr.strip()}")
    return payload


def _process_group_exists(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_process_group_exit(process_group_id: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _process_group_exists(process_group_id):
            return True
        time.sleep(0.05)
    return not _process_group_exists(process_group_id)


def _terminate_owned_group(process: subprocess.Popen[bytes]) -> bool:
    """Escalate only within this run's fresh process group and verify it exited."""
    for signal_number, grace in (
        (signal.SIGINT, INTERRUPT_GRACE_SECONDS),
        (signal.SIGTERM, TERMINATE_GRACE_SECONDS),
        (signal.SIGKILL, KILL_GRACE_SECONDS),
    ):
        if not _process_group_exists(process.pid):
            break
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal_number)
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=grace)
        if _wait_process_group_exit(process.pid, grace):
            break
    if process.poll() is None:
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=KILL_GRACE_SECONDS)
    return process.poll() is not None and not _process_group_exists(process.pid)


@contextmanager
def _ignore_parent_signals() -> Iterator[None]:
    previous = {item: signal.getsignal(item) for item in (signal.SIGINT, signal.SIGTERM)}
    try:
        for item in previous:
            signal.signal(item, signal.SIG_IGN)
        yield
    finally:
        for item, handler in previous.items():
            signal.signal(item, handler)


def _verify_owned_resources_absent(controller_host: str, controller_port: int) -> dict[str, Any]:
    bridge = subprocess.run(
        ["ovs-vsctl", "br-exists", "s1"],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    if bridge.returncode == 0:
        raise RuntimeError("owned topology bridge s1 remains after collection")
    if bridge.returncode != 2 or any(
        phrase in bridge.stderr.lower()
        for phrase in ("permission denied", "connection failed", "not responding", "refused")
    ):
        raise RuntimeError(f"OVS cleanup could not be verified: {bridge.stderr.strip()}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.3)
        try:
            probe.connect((controller_host, controller_port))
        except ConnectionRefusedError:
            pass
        except OSError as error:
            raise RuntimeError(f"controller cleanup could not be verified: {error}") from error
        else:
            raise RuntimeError("controller listener remains after collection")
    return {"bridge_s1_absent": True, "controller_listener_absent": True}


def _validate_scenario_journal(path: Path, *, run_id: str, scenario_id: str) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                raise RuntimeError(
                    f"invalid scenario journal JSON at line {line_number}"
                ) from error
            if isinstance(value, dict):
                events.append(value)
    if scenario_id == "port-scan":
        start = next(
            (event for event in events if event.get("event_type") == "scenario_started"), None
        )
        complete = next(
            (event for event in reversed(events) if event.get("event_type") == "run_completed"),
            None,
        )
        if (
            start is None
            or start.get("run_id") != run_id
            or start.get("scenario") != "port-scan"
            or start.get("target_id") != "h3"
            or start.get("duration_seconds") != 8.0
            or start.get("rate_per_second") != 1.0
            or complete is None
            or complete.get("run_id") != run_id
            or complete.get("scenario_id") != scenario_id
            or complete.get("run_status") != "complete"
        ):
            raise RuntimeError("port-scan scenario journal does not verify the bounded h3 workload")
        return {
            "run_id": run_id,
            "scenario_id": scenario_id,
            "verified_target": "h3 / 10.0.0.3",
            "duration_seconds": 8.0,
            "rate_per_second": 1.0,
            "completed": True,
        }
    started = next((event for event in events if event.get("record_type") == "run_metadata"), None)
    ended = next(
        (
            event
            for event in reversed(events)
            if event.get("record_type") == "run_boundary" and event.get("state") == "ended"
        ),
        None,
    )
    if (
        started is None
        or started.get("run_id") != run_id
        or ended is None
        or ended.get("run_id") != run_id
        or ended.get("run_status") != "complete"
    ):
        raise RuntimeError("benign scenario journal does not verify a completed run")
    return {"run_id": run_id, "scenario_id": scenario_id, "completed": True}


def _write_failure_manifest(
    path: Path,
    *,
    run_id: str,
    interpreter: str,
    worker_pid: int | None,
    exit_code: int | None,
    timeout: bool,
    cleanup: dict[str, Any] | None,
    error: str,
) -> None:
    payload = {
        "schema_version": 1,
        "collection_id": run_id,
        "state": "FAILED",
        "source_type": "LIVE",
        "interpreter": interpreter,
        "worker_pid": worker_pid,
        "worker_exit_code": exit_code,
        "timeout": timeout,
        "cleanup_verified": cleanup is not None,
        "cleanup_evidence": cleanup,
        "error": error,
        "artifact_files": sorted(item.name for item in path.iterdir() if item.is_file()),
        "recorded_at": _utc_now().isoformat(),
    }
    (path / "run-manifest.json").write_text(
        json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )


def run_supervised(
    output_dir: Path,
    ryu_manager: Path,
    *,
    packet_evidence_enabled: bool = False,
    wall_timeout_seconds: float = WORKER_WALL_TIMEOUT_SECONDS,
) -> dict[str, object]:
    """Preflight, supervise the full topology worker, audit output, and verify cleanup."""
    if not math.isfinite(wall_timeout_seconds) or wall_timeout_seconds <= 0:
        raise ValueError("wall timeout must be finite and positive")
    if packet_evidence_enabled:
        raise ValueError(
            "PacketIn/header-copy evidence is disabled for this rule-counter collector"
        )
    if os.path.lexists(output_dir):
        raise FileExistsError(f"refusing to reuse collection output directory: {output_dir}")
    output_dir = Path(os.path.abspath(output_dir))
    interpreter = _select_mininet_interpreter()
    config = TopologyConfig.from_environment()
    config.validate()
    if config.controller_port != 6653:
        raise ValueError("Stage 7 telemetry collection requires the established loopback port 6653")
    preflight = _run_isolation_preflight(interpreter, config.controller_port)
    manager = ryu_manager.resolve()
    if not manager.is_file() or not os.access(manager, os.X_OK):
        raise RuntimeError(f"Ryu manager is not executable: {manager}")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(exist_ok=False)
    collection_id = str(uuid.uuid4())
    started_at = _utc_now().isoformat()
    (output_dir / "run-manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "collection_id": collection_id,
                "state": "RUNNING",
                "source_type": "LIVE",
                "interpreter": interpreter,
                "started_at": started_at,
                "preflight": preflight,
                "packet_evidence_enabled": packet_evidence_enabled,
            },
            sort_keys=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    worker_log = output_dir / "supervisor.log"
    command = [
        interpreter,
        str(Path(__file__).resolve()),
        "--internal-worker",
        "--output-dir",
        str(output_dir),
        "--ryu-manager",
        str(manager),
        "--collection-id",
        collection_id,
    ]
    worker: subprocess.Popen[bytes] | None = None
    cleanup: dict[str, Any] | None = None
    timeout = False
    exit_code: int | None = None
    error_message = "collection failed"
    try:
        with worker_log.open("wb") as log:
            worker_environment = os.environ.copy()
            worker_environment["SDN_STAGE7_COLLECTION_ID"] = collection_id
            worker = subprocess.Popen(
                command,
                cwd=Path(__file__).resolve().parents[1],
                env=worker_environment,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                exit_code = worker.wait(timeout=wall_timeout_seconds)
            except subprocess.TimeoutExpired as timeout_error:
                timeout = True
                error_message = (
                    f"collection exceeded {wall_timeout_seconds:g}s parent wall deadline"
                )
                with _ignore_parent_signals():
                    if not _terminate_owned_group(worker):
                        raise RuntimeError(
                            "owned worker process group survived bounded termination"
                        ) from timeout_error
            except KeyboardInterrupt as interrupt_error:
                error_message = "operator interrupted collection"
                with _ignore_parent_signals():
                    if not _terminate_owned_group(worker):
                        raise RuntimeError(
                            "owned worker process group survived interrupt cleanup"
                        ) from interrupt_error
                raise
        if worker.poll() is not None:
            exit_code = worker.returncode
        if _process_group_exists(worker.pid):
            with _ignore_parent_signals():
                if not _terminate_owned_group(worker):
                    raise RuntimeError("worker exited but owned descendants remain")
            raise RuntimeError("worker exited with descendant processes; terminated owned group")
        cleanup = _verify_owned_resources_absent(config.controller_host, config.controller_port)
        if timeout:
            raise TimeoutError(error_message)
        if exit_code != 0:
            raise RuntimeError(
                f"worker exited {exit_code}; cleanup verified; "
                f"inspect {worker_log} for captured stdout/stderr"
            )
        from src.sdn_defense.live_anomaly import read_telemetry_windows
        from src.sdn_defense.telemetry_audit import audit_telemetry_jsonl

        summary_path = output_dir / "collection-summary.json"
        telemetry_path = output_dir / "telemetry.jsonl"
        if not summary_path.is_file() or not telemetry_path.is_file():
            raise RuntimeError("worker did not produce both collection summary and telemetry")
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        if not isinstance(summary, dict):
            raise RuntimeError("collection summary is not a JSON object")
        run_ids = summary.get("run_ids")
        if not isinstance(run_ids, dict):
            raise RuntimeError("collection summary is missing scenario run identifiers")
        scenarios = {
            "controlled-connectivity-observation": _validate_scenario_journal(
                output_dir / "benign-run.jsonl",
                run_id=str(run_ids.get("controlled-connectivity-observation", "")),
                scenario_id="controlled-connectivity-observation",
            ),
            "port-scan": _validate_scenario_journal(
                output_dir / "port-scan-run.jsonl",
                run_id=str(run_ids.get("port-scan", "")),
                scenario_id="port-scan",
            ),
        }
        telemetry_files = summary.get("telemetry_files")
        if not isinstance(telemetry_files, dict):
            raise RuntimeError("collection summary is missing run-scoped telemetry files")
        audits: dict[str, dict[str, Any]] = {}
        eligible_by_scenario: dict[str, int] = {}
        for scenario, evidence in scenarios.items():
            filename = telemetry_files.get(scenario)
            if not isinstance(filename, str) or Path(filename).name != filename:
                raise RuntimeError(f"invalid telemetry filename for scenario {scenario}")
            scoped_path = output_dir / filename
            if not scoped_path.is_file():
                raise RuntimeError(f"run-scoped telemetry is missing for {scenario}")
            audit = audit_telemetry_jsonl(scoped_path)
            audits[scenario] = audit
            if audit.get("status") != "AUDIT_COMPLETE":
                raise RuntimeError(
                    f"telemetry lineage audit failed for {scenario}: {audit.get('issues')}"
                )
            windows, _ = read_telemetry_windows(
                scoped_path,
                max_gap_seconds=float(os.getenv("SDN_STAGE2_MAX_FEATURE_GAP_SECONDS", "30")),
            )
            eligible_by_scenario[scenario] = sum(
                window.run_id == evidence["run_id"] for window in windows
            )
        if any(eligible_by_scenario[scenario] == 0 for scenario in scenarios):
            raise RuntimeError(
                f"audited telemetry contains no eligible feature window for every scenario: "
                f"{eligible_by_scenario}"
            )
        now = _utc_now().isoformat()
        manifest = {
            "schema_version": 1,
            "collection_id": collection_id,
            "state": "VERIFIED_FOR_RESEARCH_DATASET",
            "source_type": "LIVE",
            "interpreter": interpreter,
            "worker_pid": worker.pid,
            "worker_argv": command,
            "worker_exit_code": exit_code,
            "timeout": False,
            "started_at": started_at,
            "finished_at": now,
            "preflight": preflight,
            "scenario_evidence": scenarios,
            "scenario_audits": {
                scenario: {
                    "status": audit.get("status"),
                    "issues": audit.get("issues"),
                    "counts": audit.get("counts"),
                    "telemetry_file": telemetry_files[scenario],
                    "telemetry_sha256": hashlib.sha256(
                        (output_dir / telemetry_files[scenario]).read_bytes()
                    ).hexdigest(),
                }
                for scenario, audit in audits.items()
            },
            "eligible_windows_by_scenario": eligible_by_scenario,
            "audit_status": audit.get("status"),
            "audit_counts": audit.get("counts"),
            "telemetry_sha256": hashlib.sha256(telemetry_path.read_bytes()).hexdigest(),
            "cleanup_verified": True,
            "cleanup_evidence": cleanup,
            "packet_evidence_enabled": packet_evidence_enabled,
        }
        summary["audit_status"] = manifest["audit_status"]
        summary["audit_counts"] = manifest["audit_counts"]
        summary["eligible_windows_by_scenario"] = eligible_by_scenario
        summary["cleanup_verified"] = True
        summary_path.write_text(
            json.dumps(summary, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        manifest["summary_sha256"] = hashlib.sha256(summary_path.read_bytes()).hexdigest()
        (output_dir / "run-manifest.json").write_text(
            json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        return summary
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            error_message = f"{type(error).__name__}: {error_message}"
        else:
            error_message = f"{type(error).__name__}: {error}"
        if worker is not None and (_process_group_exists(worker.pid) or worker.poll() is None):
            with _ignore_parent_signals():
                terminated = _terminate_owned_group(worker)
            if not terminated:
                error_message += "; owned process group termination failed"
        if cleanup is None:
            try:
                cleanup = _verify_owned_resources_absent(
                    config.controller_host, config.controller_port
                )
            except (OSError, RuntimeError, subprocess.SubprocessError) as cleanup_error:
                error_message += f"; cleanup verification failed: {cleanup_error}"
        _write_failure_manifest(
            output_dir,
            run_id=collection_id,
            interpreter=interpreter,
            worker_pid=worker.pid if worker is not None else None,
            exit_code=worker.returncode if worker is not None else None,
            timeout=timeout,
            cleanup=cleanup,
            error=error_message,
        )
        raise


def run(
    output_dir: Path, ryu_manager: Path, *, packet_evidence_enabled: bool = False
) -> dict[str, object]:
    return run_supervised(output_dir, ryu_manager, packet_evidence_enabled=packet_evidence_enabled)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument(
        "--ryu-manager",
        type=Path,
        default=Path(".venv-ryu/bin/ryu-manager"),
    )
    parser.add_argument("--wall-timeout-seconds", type=float, default=WORKER_WALL_TIMEOUT_SECONDS)
    parser.add_argument("--internal-worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--collection-id", help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    if arguments.internal_worker:
        if not arguments.collection_id:
            parser.error("internal worker requires a supervisor collection ID")
        os.environ["SDN_STAGE7_COLLECTION_ID"] = arguments.collection_id
        result = _run_collection_worker(arguments.output_dir, arguments.ryu_manager)
    else:
        if arguments.collection_id:
            parser.error("--collection-id is reserved for the supervisor")
        result = run_supervised(
            arguments.output_dir,
            arguments.ryu_manager,
            wall_timeout_seconds=arguments.wall_timeout_seconds,
        )
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
