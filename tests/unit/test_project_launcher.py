from __future__ import annotations

import signal
import subprocess
from pathlib import Path
from typing import Any

import pytest

from apps import project_launcher as launcher


def test_default_launcher_configuration_uses_review_ports(monkeypatch: Any) -> None:
    monkeypatch.delenv("SDN_DEMO_PORT", raising=False)
    monkeypatch.delenv("SDN_DASHBOARD_PORT", raising=False)
    args = launcher.parse_args([])
    config = launcher.config_from_args(args)
    assert config.api_port == 18000
    assert config.dashboard_port == 5173
    assert "api=http%3A%2F%2F127.0.0.1%3A18000%2Fapi" in config.review_url


def test_launcher_model_readiness_is_truthful_and_keeps_live_disabled() -> None:
    message = launcher.offline_model_readiness()
    assert "Offline inference model:" in message
    assert "not live eligible" in message or "./scripts/train_application_model.py" in message


def test_launcher_rejects_external_bind_and_same_or_invalid_ports() -> None:
    with pytest.raises(ValueError, match="loopback-only"):
        launcher.config_from_args(launcher.parse_args(["--host", "0.0.0.0"]))
    with pytest.raises(ValueError, match="different"):
        launcher.config_from_args(
            launcher.parse_args(["--api-port", "18000", "--dashboard-port", "18000"])
        )
    with pytest.raises(ValueError, match="between 1 and 65535"):
        launcher.config_from_args(launcher.parse_args(["--api-port", "0"]))


def test_preflight_reports_an_occupied_port_without_process_kill(monkeypatch: Any) -> None:
    config = launcher.config_from_args(launcher.parse_args([]))
    monkeypatch.setattr(launcher, "available_port", lambda _host, port: port != config.api_port)
    monkeypatch.setattr(
        "apps.project_launcher.subprocess.run",
        lambda *_a, **_kw: subprocess.CompletedProcess([], 0),
    )
    errors = launcher.preflight(config)
    assert any("API port 18000 is already occupied" in error for error in errors)


def test_readiness_timeout_is_bounded_and_reports_timeout(monkeypatch: Any) -> None:
    class Process:
        returncode = None

        def poll(self) -> None:
            return None

    ticks = iter([0.0, 0.2, 0.4, 0.6])
    monkeypatch.setattr("apps.project_launcher.time.monotonic", lambda: next(ticks, 0.6))
    monkeypatch.setattr("apps.project_launcher.time.sleep", lambda _seconds: None)
    monkeypatch.setattr(launcher, "_ready_json", lambda _url: None)
    monkeypatch.setattr(launcher, "_ready_html", lambda _url: False)
    config = launcher.config_from_args(launcher.parse_args([]))
    with pytest.raises(TimeoutError, match="readiness timed out"):
        launcher.wait_for_readiness(Process(), Process(), config, timeout=0.5)  # type: ignore[arg-type]


def test_owned_process_cleanup_escalates_and_verifies(monkeypatch: Any) -> None:
    calls: list[int] = []

    class FakeProcess:
        pid = 4321

        def __init__(self) -> None:
            self.wait_calls = 0

        def poll(self) -> None:
            return None

        def wait(self, timeout: float) -> int:
            self.wait_calls += 1
            if self.wait_calls == 1:
                raise subprocess.TimeoutExpired("owned", timeout)
            return 0

    process = FakeProcess()
    group_states = iter([False])
    monkeypatch.setattr("apps.project_launcher.os.killpg", lambda _pid, sig: calls.append(sig))
    monkeypatch.setattr(launcher, "_port_group_exists", lambda _pgid: next(group_states, False))
    monkeypatch.setattr(launcher, "_wait_group_gone", lambda _pgid, _duration: False)
    launcher.stop_owned_process(process, "test")  # type: ignore[arg-type]
    assert calls == [signal.SIGTERM, signal.SIGKILL]


def test_owned_process_cleanup_failure_is_reported(monkeypatch: Any) -> None:
    class FakeProcess:
        pid = 4322
        returncode = None

        def poll(self) -> None:
            return None

        def wait(self, timeout: float) -> int:
            raise subprocess.TimeoutExpired("owned", timeout)

    monkeypatch.setattr("apps.project_launcher.os.killpg", lambda *_args: None)
    monkeypatch.setattr(launcher, "_port_group_exists", lambda _pgid: True)
    monkeypatch.setattr(launcher, "_wait_group_gone", lambda _pgid, _duration: False)
    with pytest.raises(RuntimeError, match="survived bounded SIGKILL"):
        launcher.stop_owned_process(FakeProcess(), "stuck")  # type: ignore[arg-type]


def test_setup_never_recreates_an_existing_environment(tmp_path: Path, monkeypatch: Any) -> None:
    existing = tmp_path / ".venv"
    existing.mkdir()
    monkeypatch.setattr(launcher, "ROOT", tmp_path)
    with pytest.raises(RuntimeError, match="Python executable is missing"):
        launcher._setup_venv()
    assert existing.is_dir()


def test_launcher_script_is_executable_and_path_independent() -> None:
    script = Path(__file__).resolve().parents[2] / "scripts" / "run_project.sh"
    assert script.stat().st_mode & 0o111
