"""Run one bounded benign Stage 7 rule-counter telemetry collection.

This entry point is intentionally separate from the mixed benign/port-scan
runner. It uses ordinary Stage 2 forwarding and collects OpenFlow rule
counters only. Table-miss PacketIns may still reach Ryu for L2 learning, but
PacketIn-derived telemetry recording is disabled for this run.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
import platform
import shutil
import signal
import socket
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from networking.mininet.config import TopologyConfig  # noqa: E402
from src.sdn_defense.telemetry import ScenarioRunMetadata  # noqa: E402
from src.sdn_defense.telemetry_io import validate_telemetry_jsonl  # noqa: E402

H3_IP = "10.0.0.3"
PING_COUNT = 6
PING_INTERVAL_SECONDS = 1.0
FINAL_COLLECTION_WAIT_SECONDS = 2.5
HOST_COMMAND_TIMEOUT_SECONDS = 5
WORKER_WALL_TIMEOUT_SECONDS = 120
WORKER_INTERRUPT_GRACE_SECONDS = 5
WORKER_TERMINATE_GRACE_SECONDS = 3
WORKER_KILL_GRACE_SECONDS = 3


def build_ryu_command(ryu_manager: Path, controller_port: int) -> list[str]:
    """Build the explicit Ryu startup argv without launching a process."""

    if not 1 <= controller_port <= 65535:
        raise ValueError("controller port must be between 1 and 65535")
    return [
        str(ryu_manager),
        "--ofp-tcp-listen-port",
        str(controller_port),
        "networking.ryu.stage2_controller",
    ]


def build_controller_environment(
    base: Mapping[str, str], *, root: Path, context_path: Path, telemetry_path: Path
) -> dict[str, str]:
    """Return isolated controller settings for rule-counter-only collection."""

    environment = dict(base)
    environment.update(
        {
            "SDN_OBSERVATION_CONTEXT_FILE": str(context_path),
            "SDN_TELEMETRY_JSONL": str(telemetry_path),
            "SDN_STAGE2_INSTALL_TEST_RULE": "false",
            "SDN_STAGE2_PACKET_EVIDENCE_ENABLED": "false",
            "SDN_STAGE2_RECORD_PACKETIN_TELEMETRY": "false",
            "SDN_RYU_STATUS_FILE": str(root / "var/runtime/ryu-status.json"),
        }
    )
    try:
        maximum_gap = float(environment.get("SDN_STAGE2_MAX_FEATURE_GAP_SECONDS", "30.0"))
    except ValueError as error:
        raise ValueError("SDN_STAGE2_MAX_FEATURE_GAP_SECONDS must be numeric") from error
    if not math.isfinite(maximum_gap) or maximum_gap <= 0:
        raise ValueError("SDN_STAGE2_MAX_FEATURE_GAP_SECONDS must be finite and positive")
    environment["SDN_STAGE2_MAX_FEATURE_GAP_SECONDS"] = str(maximum_gap)
    existing = environment.get("PYTHONPATH", "")
    environment["PYTHONPATH"] = str(root) + (os.pathsep + existing if existing else "")
    return environment


def create_fresh_output_directory(path: Path) -> Path:
    """Create a new output directory and refuse any pre-existing path."""

    # mkdir(exist_ok=False) rejects ordinary files, directories, and dangling
    # symlinks atomically. Resolving first would follow a dangling symlink and
    # could create its target while leaving the caller's path occupied.
    path.mkdir(parents=True, exist_ok=False)
    return path.resolve()


def _ensure_mininet_python_module() -> None:
    if importlib.util.find_spec("mininet") is None:
        raise RuntimeError(
            "Mininet Python module is unavailable to this runner interpreter; "
            "use the interpreter that owns the installed Mininet package"
        )


def _ensure_prerequisites(controller_port: int) -> None:
    _ensure_mininet_python_module()
    if os.geteuid() != 0:
        raise PermissionError("local Mininet/OVS telemetry collection requires root")
    for executable in ("mn", "ovs-vsctl", "ovs-ofctl"):
        if shutil.which(executable) is None:
            raise RuntimeError(f"required executable is unavailable: {executable}")
    if subprocess.run(
        ["systemctl", "is-active", "--quiet", "openvswitch"], check=False, timeout=5
    ).returncode:
        raise RuntimeError("Open vSwitch service must already be active")
    if subprocess.run(["ovs-vsctl", "br-exists", "s1"], check=False, timeout=5).returncode == 0:
        raise RuntimeError("refusing to run: bridge s1 already exists")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.2)
        try:
            probe.connect(("127.0.0.1", controller_port))
        except OSError:
            return
    raise RuntimeError(f"refusing to run: a process already listens on 127.0.0.1:{controller_port}")


def _wait_controller(process: subprocess.Popen[bytes], port: int, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Ryu exited before readiness (status {process.returncode})")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"Ryu did not listen on 127.0.0.1:{port} within {timeout:g} seconds")


def _verify_network_resources_absent(port: int) -> None:
    """Verify the owned test bridge and controller listener are absent."""
    bridge_result = subprocess.run(
        ["ovs-vsctl", "br-exists", "s1"],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    if bridge_result.returncode == 0:
        raise RuntimeError("Mininet cleanup left bridge s1 behind")
    if bridge_result.returncode != 2 or any(
        phrase in str(getattr(bridge_result, "stderr", "")).lower()
        for phrase in (
            "connection refused",
            "connection failed",
            "failed to connect",
            "database connection",
            "not responding",
        )
    ):
        raise RuntimeError("could not independently verify OVS bridge cleanup")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.2)
        try:
            probe.connect(("127.0.0.1", port))
        except ConnectionRefusedError:
            return
        except OSError as error:
            raise RuntimeError(
                "could not independently verify controller listener cleanup"
            ) from error
    raise RuntimeError("Ryu controller listener remains after cleanup")


def _verify_cleanup(controller: subprocess.Popen[bytes] | None, port: int) -> None:
    """Raise unless the owned controller, test bridge, and listener are gone."""
    if controller is None or controller.poll() is None:
        raise RuntimeError("Ryu process did not stop after collection")
    _verify_network_resources_absent(port)


def _run_id() -> str:
    return str(uuid.uuid4())


def topology_config_identity(config: TopologyConfig) -> str:
    """Return a deterministic identity for the fixed Stage 2 benign topology."""

    document = {
        "topology": "stage2-three-host-s1-v1",
        "controller_host": config.controller_host,
        "controller_port": config.controller_port,
        "scenario_id": "controlled-connectivity-observation",
        "ports": [],
    }
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _capture_version(command: list[str]) -> str:
    """Read a bounded tool version string without starting a network service."""

    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    if result.returncode != 0:
        raise RuntimeError(f"version query failed for {command[0]} (status {result.returncode})")
    version = (result.stdout or result.stderr).strip()
    if not version:
        raise RuntimeError(f"version query returned no version text for {command[0]}")
    return version[:512]


def _capture_environment_versions(ryu_manager: Path) -> dict[str, str]:
    """Capture the relevant local runtime versions as argv-only queries."""

    commands = {
        "ryu_manager": [str(ryu_manager), "--version"],
        "mininet": ["mn", "--version"],
        "ovs_vsctl": ["ovs-vsctl", "--version"],
        "ovs_ofctl": ["ovs-ofctl", "--version"],
    }
    return {name: _capture_version(command) for name, command in commands.items()}


def _source_hashes(root: Path) -> dict[str, str]:
    """Hash the code that defines this runner's collection and audit contract."""

    relative_paths = (
        "scripts/run_stage7_rule_counter_validation.py",
        "scripts/audit_stage7_rule_counter_telemetry.py",
        "networking/ryu/config.py",
        "networking/ryu/stage2_controller.py",
        "src/sdn_defense/telemetry.py",
        "src/sdn_defense/telemetry_io.py",
        "src/sdn_defense/live_provenance.py",
        "src/sdn_defense/live_features.py",
        "src/sdn_defense/live_anomaly.py",
        "src/sdn_defense/telemetry_audit.py",
        "src/sdn_defense/controller_status.py",
    )
    hashes: dict[str, str] = {}
    for relative_path in relative_paths:
        digest = hashlib.sha256((root / relative_path).read_bytes()).hexdigest()
        hashes[relative_path] = digest
    return hashes


def _write_context(path: Path, metadata: ScenarioRunMetadata, *, active: bool) -> None:
    from networking.mininet.stage3_scenarios import _write_experiment_context

    _write_experiment_context(path, metadata, active=active)


def _run_worker(
    output_dir: Path,
    ryu_manager: Path,
    *,
    run_id: str | None = None,
    output_reserved: bool = False,
) -> dict[str, object]:
    """Worker body for one benign run; CLI parent applies a hard deadline."""

    # The parent rejects existing paths before Popen and reserves a new path.
    # Direct worker calls retain the same fail-before-preflight guard.
    if output_reserved:
        if not output_dir.is_dir():
            raise RuntimeError("supervisor-reserved output directory disappeared")
    elif os.path.lexists(output_dir):
        raise FileExistsError(f"refusing to reuse telemetry output directory: {output_dir}")
    run_id = run_id or _run_id()
    config = TopologyConfig.from_environment()
    config.validate()
    if config.controller_port != 6653:
        raise RuntimeError("rule-counter validation requires the established Stage 2 port 6653")
    _ensure_prerequisites(config.controller_port)
    root = ROOT
    manager = ryu_manager.resolve()
    if not manager.is_file() or not os.access(manager, os.X_OK):
        raise RuntimeError(f"Ryu manager is not executable: {manager}")
    tool_versions = _capture_environment_versions(manager)
    source_hashes = _source_hashes(root)
    if not output_reserved:
        output_dir = create_fresh_output_directory(output_dir)

    context_path = output_dir / "active-run-context.json"
    telemetry_path = output_dir / "telemetry.jsonl"
    journal_path = output_dir / "benign-run.jsonl"
    log_path = output_dir / "ryu.log"
    controller_env = build_controller_environment(
        os.environ, root=root, context_path=context_path, telemetry_path=telemetry_path
    )
    network: Any | None = None
    controller: subprocess.Popen[bytes] | None = None
    metadata: ScenarioRunMetadata | None = None
    completed = False
    with log_path.open("wb") as log_stream:
        try:
            controller = subprocess.Popen(
                build_ryu_command(manager, config.controller_port),
                cwd=root,
                env=controller_env,
                stdout=log_stream,
                stderr=subprocess.STDOUT,
            )
            _wait_controller(controller, config.controller_port)
            now = datetime.now(UTC)
            metadata = ScenarioRunMetadata(
                run_id=run_id,
                scenario_id="controlled-connectivity-observation",
                start_at=now,
                end_at=None,
                topology_config_id=topology_config_identity(config),
                source_scope=(("host", "h1"), ("ip", "10.0.0.1")),
                destination_scope=(("host", "h3"), ("ip", H3_IP)),
                protocol="ICMP",
                ports=(),
            )
            _write_context(context_path, metadata, active=True)
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
            with journal_path.open("a", encoding="utf-8") as journal:
                journal.write(
                    json.dumps(
                        {
                            "record_type": "run_boundary",
                            "schema_version": 1,
                            "run_id": run_id,
                            "state": "started",
                            "timestamp": now.isoformat(),
                        },
                        sort_keys=True,
                    )
                    + "\n"
                )
            from networking.mininet.stage2_topology import create_network

            network = create_network(config)
            h1 = network.get("h1")
            for _ in range(PING_COUNT):
                response = h1.cmd(
                    f"timeout --signal=TERM --kill-after=1s {HOST_COMMAND_TIMEOUT_SECONDS}s "
                    f"ping -c 1 -W 1 {H3_IP}"
                )
                if "1 received" not in response and "1 packets received" not in response:
                    raise RuntimeError("bounded h1-to-h3 connectivity observation failed")
                time.sleep(PING_INTERVAL_SECONDS)
            time.sleep(FINAL_COLLECTION_WAIT_SECONDS)
            completed = True
        finally:
            end = datetime.now(UTC)
            try:
                if context_path.exists() and metadata is not None:
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
                    _write_context(context_path, ended, active=False)
            finally:
                try:
                    if network is not None:
                        network.stop()
                finally:
                    try:
                        if journal_path.exists():
                            with journal_path.open("a", encoding="utf-8") as journal:
                                journal.write(
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
                    finally:
                        if controller is not None and controller.poll() is None:
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

    _verify_cleanup(controller, config.controller_port)
    counts = validate_telemetry_jsonl(telemetry_path)
    summary = {
        "schema_version": 1,
        "run_id": run_id,
        "scenario_id": metadata.scenario_id,
        "run_started_at": metadata.start_at.isoformat(),
        "run_ended_at": end.isoformat(),
        "workload": {
            "source_host": "h1",
            "source_ip": "10.0.0.1",
            "destination_host": "h3",
            "destination_ip": H3_IP,
            "protocol": "ICMP",
            "ping_count": PING_COUNT,
            "ping_interval_seconds": PING_INTERVAL_SECONDS,
            "final_collection_wait_seconds": FINAL_COLLECTION_WAIT_SECONDS,
        },
        "environment": {
            "python_version": sys.version,
            "platform": platform.platform(),
            "tool_versions": tool_versions,
            "ryu_manager_path": str(manager),
            "controller_pid": controller.pid,
            "controller_argv": build_ryu_command(manager, config.controller_port),
            "controller_port": config.controller_port,
            "monitor_interval_seconds": os.environ.get(
                "SDN_STAGE2_MONITOR_INTERVAL_SECONDS", "2.0"
            ),
            "install_explicit_test_rule": False,
            "packet_evidence_enabled": False,
            "record_packetin_telemetry": False,
            "multipart_timeout_seconds": 5.0,
            "counter_engine_runtime_gap_seconds": float(
                controller_env["SDN_STAGE2_MAX_FEATURE_GAP_SECONDS"]
            ),
            "source_sha256": source_hashes,
        },
        "telemetry_file": telemetry_path.name,
        "scenario_journal": journal_path.name,
        "record_counts": counts,
        "packetin_telemetry_recording": False,
        "ordinary_packetins_may_reach_ryu_for_forwarding": True,
        "cleanup_verified": True,
        "detector_or_mitigation": False,
    }
    (output_dir / "collection-summary.json").write_text(
        json.dumps(summary, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    return summary


def _process_group_exists(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_group_exit(process_group_id: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _process_group_exists(process_group_id):
            return True
        time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
    return not _process_group_exists(process_group_id)


def _terminate_worker_group(
    process: subprocess.Popen[bytes],
    *,
    interrupt_grace: float,
    terminate_grace: float,
    kill_grace: float,
) -> None:
    """Bound graceful, terminate, and forced shutdown of the isolated worker group."""
    process_group_id = process.pid
    stages = (
        (signal.SIGINT, interrupt_grace),
        (signal.SIGTERM, terminate_grace),
        (signal.SIGKILL, kill_grace),
    )
    for signal_number, grace in stages:
        if not _process_group_exists(process_group_id):
            break
        try:
            os.killpg(process_group_id, signal_number)
        except ProcessLookupError:
            break
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=grace)
        if _wait_group_exit(process_group_id, grace):
            break
    if process.poll() is None:
        try:
            process.wait(timeout=kill_grace)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("worker process survived bounded SIGKILL wait") from error
    if _process_group_exists(process_group_id):
        raise RuntimeError("worker descendants remain after bounded SIGKILL")


def _log_tail(path: Path, limit: int = 4000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[-limit:]
    except OSError:
        return "worker log unavailable"


@contextmanager
def _ignore_parent_interrupts() -> Iterator[None]:
    """Prevent repeated terminal signals from interrupting bounded cleanup."""
    previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        for number in previous:
            signal.signal(number, signal.SIG_IGN)
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def run_supervised(
    output_dir: Path,
    ryu_manager: Path,
    *,
    wall_timeout: float = WORKER_WALL_TIMEOUT_SECONDS,
    interrupt_grace: float = WORKER_INTERRUPT_GRACE_SECONDS,
    terminate_grace: float = WORKER_TERMINATE_GRACE_SECONDS,
    kill_grace: float = WORKER_KILL_GRACE_SECONDS,
) -> dict[str, object]:
    """Supervise the worker and convert parent SIGINT/SIGTERM into cleanup paths."""
    previous_handlers = {
        number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)
    }

    def request_cleanup(number: int, _frame: object) -> None:
        raise KeyboardInterrupt(f"received signal {number}; stopping supervised worker")

    try:
        for number in previous_handlers:
            signal.signal(number, request_cleanup)
        return _run_supervised_worker(
            output_dir,
            ryu_manager,
            wall_timeout=wall_timeout,
            interrupt_grace=interrupt_grace,
            terminate_grace=terminate_grace,
            kill_grace=kill_grace,
        )
    finally:
        for number, handler in previous_handlers.items():
            signal.signal(number, handler)


def _run_supervised_worker(
    output_dir: Path,
    ryu_manager: Path,
    *,
    wall_timeout: float = WORKER_WALL_TIMEOUT_SECONDS,
    interrupt_grace: float = WORKER_INTERRUPT_GRACE_SECONDS,
    terminate_grace: float = WORKER_TERMINATE_GRACE_SECONDS,
    kill_grace: float = WORKER_KILL_GRACE_SECONDS,
) -> dict[str, object]:
    """Run the full Mininet operation in an isolated process group with hard deadlines."""
    if min(wall_timeout, interrupt_grace, terminate_grace, kill_grace) <= 0:
        raise ValueError("all supervisor deadlines must be positive")
    if os.path.lexists(output_dir):
        raise FileExistsError(f"refusing to reuse telemetry output directory: {output_dir}")
    run_id = _run_id()
    reserved_output = create_fresh_output_directory(output_dir)
    root = ROOT
    manager = ryu_manager.resolve()
    log_path = reserved_output / "supervisor.log"
    worker_command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--internal-worker",
        "--output-dir",
        str(reserved_output),
        "--ryu-manager",
        str(manager),
        "--run-id",
        run_id,
    ]
    with log_path.open("wb") as log_stream:
        process = subprocess.Popen(
            worker_command,
            cwd=root,
            stdout=log_stream,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            return_code = process.wait(timeout=wall_timeout)
        except subprocess.TimeoutExpired as timeout_error:
            try:
                with _ignore_parent_interrupts():
                    _terminate_worker_group(
                        process,
                        interrupt_grace=interrupt_grace,
                        terminate_grace=terminate_grace,
                        kill_grace=kill_grace,
                    )
                    _verify_network_resources_absent(6653)
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as cleanup_error:
                raise RuntimeError(
                    f"worker exceeded {wall_timeout:g}s and cleanup could not be verified; "
                    f"inspect {log_path}: {cleanup_error}"
                ) from cleanup_error
            raise TimeoutError(
                f"worker exceeded {wall_timeout:g}s; process group and owned network "
                f"resources were verified absent; inspect {log_path}"
            ) from timeout_error
        except BaseException as parent_error:
            try:
                with _ignore_parent_interrupts():
                    _terminate_worker_group(
                        process,
                        interrupt_grace=interrupt_grace,
                        terminate_grace=terminate_grace,
                        kill_grace=kill_grace,
                    )
                    _verify_network_resources_absent(6653)
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as cleanup_error:
                raise RuntimeError(
                    f"parent interrupted worker; cleanup could not be verified: {cleanup_error}"
                ) from parent_error
            raise

        if _process_group_exists(process.pid):
            try:
                with _ignore_parent_interrupts():
                    _terminate_worker_group(
                        process,
                        interrupt_grace=interrupt_grace,
                        terminate_grace=terminate_grace,
                        kill_grace=kill_grace,
                    )
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as cleanup_error:
                raise RuntimeError(
                    f"worker exited but child cleanup failed: {cleanup_error}"
                ) from cleanup_error
            raise RuntimeError("worker exited while descendants remained; descendants terminated")
        if return_code != 0:
            try:
                _verify_network_resources_absent(6653)
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as cleanup_error:
                raise RuntimeError(
                    f"worker exited {return_code}; cleanup could not be verified: {cleanup_error}; "
                    f"inspect {log_path}"
                ) from cleanup_error
            raise RuntimeError(
                f"worker exited {return_code}; network cleanup verified; "
                f"inspect {log_path}: {_log_tail(log_path)}"
            )

    summary_path = reserved_output / "collection-summary.json"
    if not summary_path.is_file():
        raise RuntimeError(f"worker exited successfully without summary: {summary_path}")
    summary_value = json.loads(summary_path.read_text(encoding="utf-8"))
    if not isinstance(summary_value, dict):
        raise RuntimeError(f"worker summary is not a JSON object: {summary_path}")
    summary: dict[str, object] = summary_value
    if summary.get("cleanup_verified") is not True:
        raise RuntimeError(f"worker summary lacks verified cleanup: {summary_path}")
    return summary


def run(output_dir: Path, ryu_manager: Path) -> dict[str, object]:
    """Public runner entry point; all uninterruptible Mininet work is supervised."""
    return run_supervised(output_dir, ryu_manager)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--ryu-manager", type=Path, default=Path(".venv-ryu/bin/ryu-manager"))
    parser.add_argument("--wall-timeout-seconds", type=float, default=WORKER_WALL_TIMEOUT_SECONDS)
    parser.add_argument("--internal-worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--run-id", help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    if arguments.internal_worker:
        if not arguments.run_id:
            parser.error("internal worker requires a supervisor-provided run ID")
        result = _run_worker(
            arguments.output_dir,
            arguments.ryu_manager,
            run_id=arguments.run_id,
            output_reserved=True,
        )
    else:
        if arguments.run_id:
            parser.error("--run-id is reserved for the internal worker")
        result = run_supervised(
            arguments.output_dir,
            arguments.ryu_manager,
            wall_timeout=arguments.wall_timeout_seconds,
        )
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
