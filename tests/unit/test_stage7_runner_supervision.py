"""Offline tests for the benign runner's parent watchdog and child cleanup."""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from scripts import run_stage7_rule_counter_validation as runner


class FakeProcess:
    def __init__(self, pid: int = 987654) -> None:
        self.pid = pid
        self.returncode: int | None = 0

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        return cast(int, self.returncode)

    def poll(self) -> int | None:
        return self.returncode


def test_existing_output_rejected_before_supervisor_subprocess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    existing = tmp_path / "used"
    existing.mkdir()
    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("Popen must not run for existing output"),
    )
    with pytest.raises(FileExistsError):
        runner.run_supervised(existing, tmp_path / "ryu-manager")


def test_controller_readiness_deadline_uses_bounded_probes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = FakeProcess()
    process.returncode = None
    ticks = iter((0.0, 0.5, 1.0))
    probes: list[tuple[str, int]] = []

    def unavailable(address: tuple[str, int], *, timeout: float) -> object:
        assert timeout == 0.2
        probes.append(address)
        raise ConnectionRefusedError

    monkeypatch.setattr(time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(socket, "create_connection", unavailable)
    monkeypatch.setattr(time, "sleep", lambda _seconds: None)
    with pytest.raises(TimeoutError, match="within 1 seconds"):
        runner._wait_controller(cast(subprocess.Popen[bytes], process), 6653, timeout=1)
    assert probes == [("127.0.0.1", 6653)]


def test_parent_passes_run_id_and_uses_new_process_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "fresh"
    monkeypatch.setattr(runner, "_run_id", lambda: "stable-supervisor-run-id")
    monkeypatch.setattr(runner, "_process_group_exists", lambda _pgid: False)
    captured: dict[str, Any] = {}

    def fake_popen(command: list[str], **kwargs: Any) -> FakeProcess:
        captured["command"] = command
        captured["kwargs"] = kwargs
        reserved = Path(command[command.index("--output-dir") + 1])
        (reserved / "collection-summary.json").write_text(
            json.dumps({"run_id": "stable-supervisor-run-id", "cleanup_verified": True}),
            encoding="utf-8",
        )
        return FakeProcess()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    result = runner.run_supervised(output, tmp_path / "manager")
    assert result["run_id"] == "stable-supervisor-run-id"
    assert "--internal-worker" in captured["command"]
    assert captured["command"][-1] == "stable-supervisor-run-id"
    assert captured["kwargs"]["start_new_session"] is True


def test_worker_group_escalates_with_finite_sigint_term_kill_graces(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = FakeProcess()
    process.returncode = None
    sent: list[int] = []
    group_states = iter((True, True, True, False))
    wait_states = iter((False, False, True))

    def fake_killpg(_group: int, signal_number: int) -> None:
        sent.append(signal_number)
        if signal_number == signal.SIGKILL:
            process.returncode = -signal.SIGKILL

    def fake_wait(timeout: float | None = None) -> int:
        del timeout
        if process.returncode is None:
            raise subprocess.TimeoutExpired("worker", 1)
        return process.returncode

    monkeypatch.setattr(cast(Any, process), "wait", fake_wait)
    monkeypatch.setattr(os, "killpg", fake_killpg)
    monkeypatch.setattr(runner, "_process_group_exists", lambda _group: next(group_states))
    monkeypatch.setattr(runner, "_wait_group_exit", lambda _group, _timeout: next(wait_states))

    runner._terminate_worker_group(
        cast(subprocess.Popen[bytes], process),
        interrupt_grace=0.1,
        terminate_grace=0.2,
        kill_grace=0.3,
    )
    assert sent == [signal.SIGINT, signal.SIGTERM, signal.SIGKILL]


def test_wall_timeout_reports_only_after_network_cleanup_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = FakeProcess()
    process.returncode = None
    verified: list[int] = []
    monkeypatch.setattr(runner, "_run_id", lambda: "timeout-run-id")
    monkeypatch.setattr(runner, "_process_group_exists", lambda _pgid: False)
    monkeypatch.setattr(subprocess, "Popen", lambda *_args, **_kwargs: process)

    def timeout_wait(*, timeout: float) -> int:
        assert timeout == 0.01
        raise subprocess.TimeoutExpired("worker", timeout)

    monkeypatch.setattr(cast(Any, process), "wait", timeout_wait)

    def terminate(_process: subprocess.Popen[bytes], **_kwargs: float) -> None:
        process.returncode = -signal.SIGINT

    monkeypatch.setattr(runner, "_terminate_worker_group", terminate)
    monkeypatch.setattr(runner, "_verify_network_resources_absent", verified.append)
    with pytest.raises(TimeoutError, match="resources were verified absent"):
        runner.run_supervised(tmp_path / "timeout", tmp_path / "manager", wall_timeout=0.01)
    assert verified == [6653]


def test_timeout_cleanup_failure_is_not_reported_as_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = FakeProcess()
    process.returncode = None
    monkeypatch.setattr(runner, "_run_id", lambda: "cleanup-fail-run")
    monkeypatch.setattr(runner, "_process_group_exists", lambda _pgid: False)
    monkeypatch.setattr(subprocess, "Popen", lambda *_args, **_kwargs: process)

    def always_timeout(*, timeout: float) -> int:
        raise subprocess.TimeoutExpired("worker", timeout)

    monkeypatch.setattr(cast(Any, process), "wait", always_timeout)
    monkeypatch.setattr(runner, "_terminate_worker_group", lambda *_args, **_kwargs: None)

    def fail_verification(_port: int) -> None:
        raise RuntimeError("bridge s1 remains")

    monkeypatch.setattr(runner, "_verify_network_resources_absent", fail_verification)
    with pytest.raises(RuntimeError, match="cleanup could not be verified"):
        runner.run_supervised(tmp_path / "cleanup-failure", tmp_path / "manager", wall_timeout=0.01)


def test_parent_sigterm_uses_bounded_worker_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = FakeProcess()
    process.returncode = None
    terminated: list[int] = []
    verified: list[int] = []
    monkeypatch.setattr(runner, "_run_id", lambda: "parent-signal-run")
    monkeypatch.setattr(runner, "_process_group_exists", lambda _pgid: False)
    monkeypatch.setattr(subprocess, "Popen", lambda *_args, **_kwargs: process)

    def signal_wait(*, timeout: float) -> int:
        assert timeout > 0
        handler = signal.getsignal(signal.SIGTERM)
        assert callable(handler)
        handler(signal.SIGTERM, None)
        raise AssertionError("the parent signal handler should unwind the wait")

    monkeypatch.setattr(cast(Any, process), "wait", signal_wait)

    def terminate(_process: subprocess.Popen[bytes], **_kwargs: float) -> None:
        terminated.append(process.pid)
        process.returncode = -signal.SIGTERM

    monkeypatch.setattr(runner, "_terminate_worker_group", terminate)
    monkeypatch.setattr(runner, "_verify_network_resources_absent", verified.append)
    with pytest.raises(KeyboardInterrupt, match="received signal"):
        runner.run_supervised(tmp_path / "parent-signal", tmp_path / "manager")
    assert terminated == [process.pid]
    assert verified == [6653]


def test_cleanup_verifier_requires_ovs_no_bridge_status_and_refused_listener(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class RefusedSocket:
        def __enter__(self) -> RefusedSocket:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def settimeout(self, _timeout: float) -> None:
            return None

        def connect(self, _address: tuple[str, int]) -> None:
            raise ConnectionRefusedError

    monkeypatch.setattr(subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(returncode=2))
    monkeypatch.setattr(socket, "socket", lambda *_args, **_kwargs: RefusedSocket())
    runner._verify_network_resources_absent(6653)

    monkeypatch.setattr(subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(returncode=1))
    with pytest.raises(RuntimeError, match="could not independently verify OVS"):
        runner._verify_network_resources_absent(6653)
