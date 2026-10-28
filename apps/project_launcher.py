"""Bounded local launcher for the loopback review application."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
import uuid
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_API_PORT = 18000
DEFAULT_DASHBOARD_PORT = 5173
STARTUP_TIMEOUT_SECONDS = 10.0
REQUEST_TIMEOUT_SECONDS = 0.5
TERM_TIMEOUT_SECONDS = 3.0
KILL_TIMEOUT_SECONDS = 2.0
REQUIRED_FILES = (
    "apps/api/demo_app.py",
    "apps/api/project_data.py",
    "apps/frontend/index.html",
    "apps/frontend/package.json",
    "apps/frontend/package-lock.json",
    "apps/frontend/src/main.tsx",
)


@dataclass(frozen=True)
class LaunchConfig:
    host: str
    api_port: int
    dashboard_port: int
    database: Path

    @property
    def api_url(self) -> str:
        return f"http://{self.host}:{self.api_port}"

    @property
    def dashboard_url(self) -> str:
        return f"http://{self.host}:{self.dashboard_port}"

    @property
    def review_url(self) -> str:
        return f"{self.dashboard_url}/?api={quote(self.api_url + '/api', safe='')}"


def _env_port(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer port") from error
    return value


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Start the local Sentinel review API and dashboard on loopback."
    )
    parser.add_argument("--host", default=os.environ.get("SDN_DEMO_HOST", "127.0.0.1"))
    parser.add_argument(
        "--api-port", type=int, default=_env_port("SDN_DEMO_PORT", DEFAULT_API_PORT)
    )
    parser.add_argument(
        "--dashboard-port",
        type=int,
        default=_env_port("SDN_DASHBOARD_PORT", DEFAULT_DASHBOARD_PORT),
    )
    parser.add_argument(
        "--database",
        type=Path,
        default=Path(os.environ.get("SDN_DEMO_DATABASE", "var/demo.sqlite3")),
    )
    parser.add_argument(
        "--check", action="store_true", help="check files, interpreter, and port availability"
    )
    parser.add_argument(
        "--setup", action="store_true", help="create .venv only if absent, then install [dev]"
    )
    parser.add_argument(
        "--smoke", action="store_true", help="run the bounded HTTP demo smoke test and exit"
    )
    return parser.parse_args(argv)


def config_from_args(arguments: argparse.Namespace) -> LaunchConfig:
    if arguments.host != "127.0.0.1":
        raise ValueError("the review application is loopback-only; --host must be 127.0.0.1")
    for name, port in (("API", arguments.api_port), ("dashboard", arguments.dashboard_port)):
        if not 1 <= port <= 65535:
            raise ValueError(f"{name} port must be between 1 and 65535")
    if arguments.api_port == arguments.dashboard_port:
        raise ValueError("API and dashboard must use different ports")
    database = arguments.database
    if not database.is_absolute():
        database = ROOT / database
    return LaunchConfig(arguments.host, arguments.api_port, arguments.dashboard_port, database)


def available_port(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind((host, port))
        except OSError:
            return False
    return True


def preflight(config: LaunchConfig, python: str = sys.executable) -> list[str]:
    errors: list[str] = []
    if sys.version_info < (3, 11):  # noqa: UP036 - runtime executable is independently selected.
        errors.append("Python 3.11 or later is required")
    for relative_path in REQUIRED_FILES:
        if not (ROOT / relative_path).is_file():
            errors.append(f"required file missing: {relative_path}")
    node, npm = shutil.which("node"), shutil.which("npm")
    if node is None or npm is None:
        errors.append("Node.js 20.19+ and npm are required for the React/Vite dashboard")
    else:
        try:
            node_result = subprocess.run(
                [node, "-p", "process.versions.node"],
                capture_output=True,
                text=True,
                check=True,
                timeout=3,
            )
            npm_result = subprocess.run(
                [npm, "--version"], capture_output=True, text=True, check=True, timeout=3
            )
            node_text = node_result.stdout or ""
            npm_text = npm_result.stdout or ""
            version = tuple(int(part) for part in node_text.strip().split(".")[:2])
            node_ok = len(version) == 2 and (
                (version[0] == 20 and version[1] >= 19)
                or (version[0] >= 22 and (version[0] > 22 or version[1] >= 12))
            )
            if not node_ok:
                errors.append(
                    f"Node.js {node_text.strip() or 'version unavailable'} is unsupported; "
                    "require 20.19+ or 22.12+"
                )
            if not npm_text.strip():
                errors.append("npm version check returned no version")
        except (
            OSError,
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
            ValueError,
        ) as error:
            errors.append(f"could not verify Node/npm versions: {error}")
        if not (ROOT / "apps/frontend/node_modules/.bin/vite").is_file():
            errors.append(
                "frontend dependencies missing; run ./scripts/run_project.sh --setup "
                "or (cd apps/frontend && npm ci)"
            )
    if config.api_port == config.dashboard_port:
        errors.append("API and dashboard ports must be different")
    for port, label in (
        (config.api_port, "API"),
        (config.dashboard_port, "dashboard"),
    ):
        if not available_port(config.host, port):
            errors.append(
                f"{label} port {port} is already occupied; no existing process was stopped"
            )
    try:
        probe = subprocess.run(
            [python, "-c", "import apps.api.demo_app, apps.api.project_data"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if probe.returncode:
            errors.append(f"demo runtime imports failed: {(probe.stderr or probe.stdout).strip()}")
    except (OSError, subprocess.TimeoutExpired) as error:
        errors.append(f"could not verify Python runtime imports: {error}")
    return errors


def offline_model_readiness() -> str:
    """Describe the configured offline artifact without loading arbitrary files."""
    from apps.api.model_registry import ModelRegistry
    from ml.models.application_linear import MODEL_ID

    model = ModelRegistry(ROOT).get_model(MODEL_ID)
    if model and model.get("inference_enabled") and model.get("status") == "LOADABLE":
        return (
            f"Offline inference model: LOADABLE {model.get('model_id')} "
            f"v{model.get('version')} (sha256 {model.get('artifact_sha256')}); "
            "offline only, not live eligible"
        )
    reason = model.get("reason") if model else "model registry entry is missing"
    return (
        f"Offline inference model: UNAVAILABLE ({reason}). If prepared data and ML "
        "dependencies are available, create the optional application model with "
        "./scripts/train_application_model.py; training is never automatic."
    )


def live_model_readiness() -> str:
    """Report whether a compatible provisional calibration artifact is installed."""
    from apps.api.model_registry import ModelRegistry
    from src.sdn_defense.live_anomaly import LIVE_ANOMALY_MODEL_ID

    entry = ModelRegistry(ROOT).get_model(LIVE_ANOMALY_MODEL_ID)
    if entry and entry.get("inference_enabled"):
        return (
            f"Live scoring baseline: INSTALLED {entry.get('model_id')} "
            f"v{entry.get('version')} (sha256 {entry.get('artifact_sha256')}); "
            "provisional benign anomaly scoring only, not attack classification"
        )
    reason = entry.get("reason") if entry else "registry entry is missing"
    return (
        f"Live scoring baseline: UNAVAILABLE ({reason}). Calibrate only from a "
        "source-audited benign run using scripts/calibrate_live_baseline.py."
    )


def _port_group_exists(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_group_gone(process_group_id: int, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not _port_group_exists(process_group_id):
            return True
        time.sleep(0.05)
    return not _port_group_exists(process_group_id)


def stop_owned_process(process: subprocess.Popen[bytes], label: str) -> None:
    """Bound TERM/KILL shutdown and verify the owned process group is gone."""
    process_group_id = process.pid
    if process.poll() is not None and not _port_group_exists(process_group_id):
        return
    with suppress(ProcessLookupError):
        os.killpg(process_group_id, signal.SIGTERM)
    with suppress(subprocess.TimeoutExpired):
        process.wait(timeout=TERM_TIMEOUT_SECONDS)
    if not _wait_group_gone(process_group_id, TERM_TIMEOUT_SECONDS):
        with suppress(ProcessLookupError):
            os.killpg(process_group_id, signal.SIGKILL)
        try:
            process.wait(timeout=KILL_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(f"{label} process survived bounded SIGKILL wait") from error
    if _port_group_exists(process_group_id):
        raise RuntimeError(f"{label} process group remains after bounded shutdown")


def _ready_json(url: str) -> dict[str, Any] | None:
    try:
        with urlopen(url, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            if response.status != 200:
                return None
            value = json.load(response)
            return value if isinstance(value, dict) else None
    except (OSError, ValueError, json.JSONDecodeError):
        return None


def _ready_html(url: str) -> bool:
    try:
        with urlopen(url, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            body = response.read(65536).decode("utf-8")
            return response.status == 200 and 'id="root"' in body and "Sentinel" in body
    except (OSError, UnicodeDecodeError):
        return False


def wait_for_readiness(
    api: subprocess.Popen[bytes],
    dashboard: subprocess.Popen[bytes],
    config: LaunchConfig,
    timeout: float = STARTUP_TIMEOUT_SECONDS,
) -> None:
    deadline = time.monotonic() + timeout
    health_url = config.api_url + "/health"
    while time.monotonic() < deadline:
        if api.poll() is not None:
            raise RuntimeError(
                f"API process exited early with status {api.returncode}; inspect api.log"
            )
        if dashboard.poll() is not None:
            raise RuntimeError(
                "dashboard process exited early with status "
                f"{dashboard.returncode}; inspect dashboard.log"
            )
        health = _ready_json(health_url)
        page_ready = _ready_html(config.dashboard_url + "/")
        if (
            health is not None
            and health.get("status") == "ready"
            and health.get("mode") == "DEMO"
            and page_ready
        ):
            return
        time.sleep(0.1)
    raise TimeoutError(f"application readiness timed out after {timeout:g}s")


def _run_smoke(python: str, api_port: int, dashboard_port: int) -> int:
    try:
        subprocess.run(
            [
                python,
                "scripts/smoke_demo.py",
                "--api-port",
                str(api_port),
                "--dashboard-port",
                str(dashboard_port),
            ],
            cwd=ROOT,
            check=True,
            timeout=60,
        )
    except subprocess.CalledProcessError as error:
        return error.returncode
    except (OSError, subprocess.TimeoutExpired) as error:
        print(f"Smoke test could not complete: {error}", file=sys.stderr)
        return 1
    return 0


def _setup_venv() -> str:
    environment = ROOT / ".venv"
    executable = environment / "bin/python"
    if not environment.exists():
        subprocess.run([sys.executable, "-m", "venv", str(environment)], check=True, timeout=120)
    elif not executable.is_file():
        raise RuntimeError(".venv exists but its Python executable is missing; it was not modified")
    subprocess.run(
        [str(executable), "-m", "pip", "install", "-e", ".[dev,ml]"],
        cwd=ROOT,
        check=True,
        timeout=300,
    )
    subprocess.run(["npm", "ci"], cwd=ROOT / "apps" / "frontend", check=True, timeout=600)
    return str(executable)


def launch(config: LaunchConfig, python: str = sys.executable) -> int:
    errors = preflight(config, python)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(
            "Troubleshooting: change SDN_DEMO_PORT / SDN_DASHBOARD_PORT or use "
            "--api-port / --dashboard-port.",
            file=sys.stderr,
        )
        return 1

    if not (ROOT / "apps/frontend/node_modules/.bin/vite").is_file():
        print(
            "ERROR: frontend dependencies are not installed. Run ./scripts/run_project.sh --setup "
            "or (cd apps/frontend && npm ci).",
            file=sys.stderr,
        )
        return 1

    run_directory = (
        ROOT
        / "var"
        / "logs"
        / f"project-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{uuid.uuid4().hex[:8]}"
    )
    run_directory.mkdir(parents=True, exist_ok=False)
    api_log_path = run_directory / "api.log"
    dashboard_log_path = run_directory / "dashboard.log"
    environment = os.environ.copy()
    environment.update(
        {
            "SDN_DEMO_HOST": config.host,
            "SDN_DEMO_PORT": str(config.api_port),
            "SDN_DEMO_DATABASE": str(config.database),
            "SDN_DEMO_CORS_ORIGIN": config.dashboard_url,
            "VITE_API_BASE_URL": f"{config.api_url}/api/v1",
            "PYTHONPATH": str(ROOT)
            + (os.pathsep + environment["PYTHONPATH"] if environment.get("PYTHONPATH") else ""),
        }
    )
    api_process: subprocess.Popen[bytes] | None = None
    dashboard_process: subprocess.Popen[bytes] | None = None
    log_streams: list[Any] = []
    shutdown_errors: list[str] = []
    try:
        api_log = api_log_path.open("ab")
        log_streams.append(api_log)
        api_process = subprocess.Popen(
            [python, "-m", "apps.api.demo_app"],
            cwd=ROOT,
            env=environment,
            stdout=api_log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        dashboard_log = dashboard_log_path.open("ab")
        log_streams.append(dashboard_log)
        dashboard_process = subprocess.Popen(
            [
                "npm",
                "run",
                "dev",
                "--",
                "--host",
                config.host,
                "--port",
                str(config.dashboard_port),
                "--strictPort",
            ],
            cwd=ROOT / "apps/frontend",
            env=environment,
            stdout=dashboard_log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        wait_for_readiness(api_process, dashboard_process, config)
        print("Sentinel review application is ready.", flush=True)
        print(f"Dashboard: {config.dashboard_url}", flush=True)
        print(f"API: {config.api_url}/api/v1", flush=True)
        print(f"API log: {api_log_path}", flush=True)
        print(f"Dashboard log: {dashboard_log_path}", flush=True)
        print("Press Ctrl+C to stop only these two services.", flush=True)
        while True:
            if api_process.poll() is not None:
                raise RuntimeError(
                    f"API exited with status {api_process.returncode}; inspect {api_log_path}"
                )
            if dashboard_process.poll() is not None:
                raise RuntimeError(
                    "dashboard exited with status "
                    f"{dashboard_process.returncode}; inspect {dashboard_log_path}"
                )
            time.sleep(0.2)
    except KeyboardInterrupt:
        print("Shutdown requested; stopping owned services…", flush=True)
        return_code = 0
    except (OSError, RuntimeError, TimeoutError, subprocess.SubprocessError) as error:
        print(f"ERROR: {error}", file=sys.stderr, flush=True)
        print(f"Logs: {run_directory}", file=sys.stderr, flush=True)
        return_code = 1
    finally:
        for process, label in ((dashboard_process, "dashboard"), (api_process, "API")):
            if process is None:
                continue
            try:
                stop_owned_process(process, label)
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                shutdown_errors.append(str(error))
        for stream in log_streams:
            stream.close()
        if shutdown_errors:
            for message in shutdown_errors:
                print(f"CLEANUP ERROR: {message}", file=sys.stderr, flush=True)
            return_code = 1
        else:
            print("Owned API and dashboard processes stopped and verified.", flush=True)
    return return_code


def main(argv: list[str] | None = None) -> int:
    arguments = parse_args(argv)
    python = sys.executable
    if arguments.setup:
        try:
            python = _setup_venv()
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            print(f"Setup failed: {error}", file=sys.stderr)
            return 1
    try:
        config = config_from_args(arguments)
    except ValueError as error:
        print(f"Configuration error: {error}", file=sys.stderr)
        return 2
    if arguments.smoke:
        return _run_smoke(python, arguments.api_port, arguments.dashboard_port)
    errors = preflight(config, python)
    if errors:
        for message in errors:
            print(f"ERROR: {message}", file=sys.stderr)
        install_command = (
            ".venv/bin/python -m pip install -e '.[dev]'"
            if (ROOT / ".venv").exists()
            else "./scripts/run_project.sh --setup"
        )
        print(f"Install/check dependencies with: {install_command}", file=sys.stderr)
        return 1
    if arguments.check:
        print(f"Python: {python} ({sys.version.split()[0]})")
        print(f"API port {config.api_port}: available")
        print(f"Dashboard port {config.dashboard_port}: available")
        print("Required application files and runtime imports: available")
        print(offline_model_readiness())
        print(live_model_readiness())
        print("Live mitigation: DISABLED")
        return 0
    print(offline_model_readiness(), flush=True)
    print(live_model_readiness(), flush=True)
    print("Live mitigation: DISABLED", flush=True)
    previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
    shutdown_requested = False

    def request_shutdown(_number: int, _frame: Any) -> None:
        nonlocal shutdown_requested
        shutdown_requested = True
        raise KeyboardInterrupt

    try:
        signal.signal(signal.SIGINT, request_shutdown)
        signal.signal(signal.SIGTERM, request_shutdown)
        return launch(config, python)
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


if __name__ == "__main__":
    raise SystemExit(main())
