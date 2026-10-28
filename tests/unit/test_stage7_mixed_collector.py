"""Offline regression tests for the parent-supervised mixed collection runner."""

from __future__ import annotations

import json
import signal
import subprocess
from pathlib import Path

import pytest

from networking.mininet.config import TopologyConfig
from scripts import run_stage7_telemetry_collection as collector


def test_help_does_not_import_mininet() -> None:
    result = subprocess.run(
        [".venv/bin/python", "scripts/run_stage7_telemetry_collection.py", "--help"],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0
    assert "--wall-timeout-seconds" in result.stdout


def test_interpreter_selects_host_mininet_python(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        collector,
        "_interpreter_has_mininet",
        lambda name: name == "/usr/bin/python3",
    )
    assert collector._select_mininet_interpreter() == "/usr/bin/python3"


def test_missing_mininet_is_reported_without_fallback_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(collector, "_interpreter_has_mininet", lambda _name: False)
    with pytest.raises(RuntimeError, match="Mininet Python package is unavailable"):
        collector._select_mininet_interpreter()


def test_existing_output_rejected_before_preflight_or_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "existing"
    output.mkdir()
    monkeypatch.setattr(
        collector,
        "_select_mininet_interpreter",
        lambda: pytest.fail("must reject existing output before any subprocess checks"),
    )
    with pytest.raises(FileExistsError):
        collector.run_supervised(output, tmp_path / "ryu")


def test_failed_isolation_preflight_creates_no_output_or_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "rejected"
    monkeypatch.setattr(collector, "_select_mininet_interpreter", lambda: "/usr/bin/python3")
    monkeypatch.setattr(
        collector,
        "_run_isolation_preflight",
        lambda *_: (_ for _ in ()).throw(
            RuntimeError("isolated lab preflight failed: bridge inventory unavailable")
        ),
    )
    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("preflight must happen before worker startup"),
    )
    with pytest.raises(RuntimeError, match="preflight failed"):
        collector.run_supervised(output, tmp_path / "ryu")
    assert not output.exists()


class _FakeWorker:
    pid = 812341

    def __init__(self, outcome: str, output: Path | None = None) -> None:
        self.outcome = outcome
        self.returncode: int | None = None
        self.output = output

    def wait(self, timeout: float) -> int:
        if self.outcome == "timeout":
            raise subprocess.TimeoutExpired("worker", timeout)
        if self.outcome == "interrupt":
            raise KeyboardInterrupt
        if self.outcome == "partial-failure" and self.output is not None:
            (self.output / "telemetry.jsonl").write_text("partial evidence\n", encoding="utf-8")
        self.returncode = 0 if self.outcome == "success" else 1
        return self.returncode

    def poll(self) -> int | None:
        return self.returncode


def _mock_parent_preflight(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(collector, "_select_mininet_interpreter", lambda: "/usr/bin/python3")
    monkeypatch.setattr(
        collector,
        "_run_isolation_preflight",
        lambda *_: {"status": "PASS", "read_only": True, "ovs_bridges": {}},
    )
    monkeypatch.setattr(
        collector,
        "_verify_owned_resources_absent",
        lambda *_: {"bridge_s1_absent": True, "controller_listener_absent": True},
    )


def _fake_manager(tmp_path: Path) -> Path:
    manager = tmp_path / "ryu-manager"
    manager.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    manager.chmod(0o755)
    return manager


@pytest.mark.parametrize("outcome", ["timeout", "partial-failure"])
def test_timeout_and_worker_failure_keep_a_failed_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    _mock_parent_preflight(monkeypatch)
    output = tmp_path / outcome
    manager = _fake_manager(tmp_path)
    worker = _FakeWorker(outcome, output)
    monkeypatch.setattr(subprocess, "Popen", lambda *_args, **_kwargs: worker)
    monkeypatch.setattr(collector, "_terminate_owned_group", lambda _worker: True)
    monkeypatch.setattr(collector, "_process_group_exists", lambda _pid: False)
    expected = TimeoutError if outcome == "timeout" else RuntimeError
    with pytest.raises(expected):
        collector.run_supervised(output, manager, wall_timeout_seconds=0.01)
    manifest = json.loads((output / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["state"] == "FAILED"
    assert manifest["cleanup_verified"] is True
    assert manifest["timeout"] is (outcome == "timeout")
    if outcome == "partial-failure":
        assert "telemetry.jsonl" in manifest["artifact_files"]


def test_cleanup_failure_is_never_reported_as_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _mock_parent_preflight(monkeypatch)
    output = tmp_path / "cleanup-failure"
    manager = _fake_manager(tmp_path)
    worker = _FakeWorker("success", output)
    monkeypatch.setattr(subprocess, "Popen", lambda *_args, **_kwargs: worker)
    monkeypatch.setattr(collector, "_process_group_exists", lambda _pid: False)

    def failed_cleanup(*_args: object) -> dict[str, object]:
        raise RuntimeError("OVS bridge state unavailable")

    monkeypatch.setattr(collector, "_verify_owned_resources_absent", failed_cleanup)
    with pytest.raises(RuntimeError, match="OVS bridge state unavailable"):
        collector.run_supervised(output, manager)
    manifest = json.loads((output / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["state"] == "FAILED"
    assert manifest["cleanup_verified"] is False


def test_keyboard_interrupt_preserves_failure_and_attempts_owned_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _mock_parent_preflight(monkeypatch)
    output = tmp_path / "interrupted"
    worker = _FakeWorker("interrupt", output)
    monkeypatch.setattr(subprocess, "Popen", lambda *_args, **_kwargs: worker)
    terminated: list[int] = []

    def terminate(process: _FakeWorker) -> bool:
        terminated.append(process.pid)
        return True

    monkeypatch.setattr(
        collector,
        "_terminate_owned_group",
        terminate,
    )
    monkeypatch.setattr(collector, "_process_group_exists", lambda _pid: False)
    with pytest.raises(KeyboardInterrupt):
        collector.run_supervised(output, _fake_manager(tmp_path))
    assert terminated == [worker.pid, worker.pid]
    manifest = json.loads((output / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["state"] == "FAILED"
    assert manifest["cleanup_verified"] is True
    assert "KeyboardInterrupt" in manifest["error"]


def test_owned_worker_with_stale_descendant_group_is_not_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _mock_parent_preflight(monkeypatch)
    output = tmp_path / "stale-descendant"
    worker = _FakeWorker("success", output)
    monkeypatch.setattr(subprocess, "Popen", lambda *_args, **_kwargs: worker)
    group_checks = iter((True, False))
    monkeypatch.setattr(collector, "_process_group_exists", lambda _pid: next(group_checks))
    terminated: list[int] = []

    def terminate(process: _FakeWorker) -> bool:
        terminated.append(process.pid)
        return True

    monkeypatch.setattr(
        collector,
        "_terminate_owned_group",
        terminate,
    )
    with pytest.raises(RuntimeError, match="descendant processes"):
        collector.run_supervised(output, _fake_manager(tmp_path))
    assert terminated == [worker.pid]
    manifest = json.loads((output / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["state"] == "FAILED"
    assert manifest["cleanup_verified"] is True


def test_port_scan_timeout_is_recorded_and_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeProcess:
        pid = 991
        returncode = -int(signal.SIGTERM)

        def __init__(self) -> None:
            self.calls = 0

        def communicate(self, timeout: float) -> tuple[str, str]:
            self.calls += 1
            if self.calls == 1:
                raise subprocess.TimeoutExpired("port-scan", timeout)
            return "partial stdout", "partial stderr"

        def terminate(self) -> None:
            pass

        def kill(self) -> None:
            pass

    process = FakeProcess()
    monkeypatch.setattr(subprocess, "Popen", lambda *_args, **_kwargs: process)
    journal = tmp_path / "scan.jsonl"
    with pytest.raises(TimeoutError, match="port scan exceeded"):
        collector._run_port_scan(
            TopologyConfig("127.0.0.1", 6653),
            tmp_path / "context.json",
            journal,
            "scan-run",
        )
    evidence = json.loads((tmp_path / "port-scan-process.json").read_text(encoding="utf-8"))
    assert evidence["timeout"] is True
    assert evidence["pid"] == 991
    assert evidence["stdout"] == "partial stdout"


def test_controller_crash_is_reported_in_phase() -> None:
    class Crashed:
        def poll(self) -> int:
            return 7

    with pytest.raises(RuntimeError, match="Ryu exited during port-scan collection"):
        collector._assert_controller_alive(Crashed(), "port-scan collection")  # type: ignore[arg-type]


def test_raw_stream_is_partitioned_only_by_recorded_run_ids(tmp_path: Path) -> None:
    source = tmp_path / "raw.jsonl"
    source.write_text(
        "\n".join(
            json.dumps(item)
            for item in (
                {"record_type": "recorder_metadata", "schema_version": 1},
                {"record_type": "flow_collection", "run_id": "run-a", "state": "requested"},
                {"record_type": "flow_collection", "run_id": "run-b", "state": "requested"},
                {
                    "record_type": "telemetry_observation",
                    "observation": {"run_id": "run-b", "observation_id": "obs-b"},
                },
                {"record_type": "connection_boundary", "timestamp": "no-run-id"},
            )
        )
        + "\n",
        encoding="utf-8",
    )
    original = source.read_bytes()
    views = collector._split_telemetry_by_run(
        source,
        {"benign": "run-a", "port-scan": "run-b"},
        tmp_path,
    )
    assert source.read_bytes() == original
    benign = [json.loads(line) for line in views["benign"].read_text().splitlines()]
    scan = [json.loads(line) for line in views["port-scan"].read_text().splitlines()]
    assert [item["record_type"] for item in benign] == ["recorder_metadata", "flow_collection"]
    assert [item["record_type"] for item in scan] == [
        "recorder_metadata",
        "flow_collection",
        "telemetry_observation",
    ]
    assert all(item.get("run_id") != "run-b" for item in benign)
