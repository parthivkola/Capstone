"""Bounded HTTP smoke for API persistence and the React/Vite dashboard."""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]


def request_json(url: str, *, method: str = "GET", payload: dict | None = None) -> dict:
    data = json.dumps(payload or {}).encode() if method == "POST" else None
    request = Request(url, data=data, method=method)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    with urlopen(request, timeout=1.0) as response:
        return json.load(response)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-port", type=int, default=18000)
    parser.add_argument("--dashboard-port", type=int, default=5173)
    args = parser.parse_args()
    api = f"http://127.0.0.1:{args.api_port}"
    dashboard = f"http://127.0.0.1:{args.dashboard_port}"
    processes: list[subprocess.Popen] = []
    with tempfile.TemporaryDirectory(prefix="sentinel-smoke-") as directory:
        env = os.environ.copy()
        env.update(
            {
                "SDN_DEMO_HOST": "127.0.0.1",
                "SDN_DEMO_PORT": str(args.api_port),
                "SDN_DEMO_DATABASE": str(Path(directory) / "smoke.sqlite3"),
                "SDN_DEMO_CORS_ORIGIN": dashboard,
                "VITE_API_BASE_URL": f"{api}/api/v1",
                "PYTHONPATH": str(ROOT) + os.pathsep + env.get("PYTHONPATH", ""),
            }
        )

        def start(command: list[str], cwd: Path) -> subprocess.Popen:
            proc = subprocess.Popen(
                command,
                cwd=cwd,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            processes.append(proc)
            return proc

        def stop(proc: subprocess.Popen) -> None:
            if proc.poll() is not None:
                return
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=2)

        try:
            api_proc = start([sys.executable, "-m", "apps.api.demo_app"], ROOT)
            front_proc = start(
                [
                    "npm",
                    "run",
                    "dev",
                    "--",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(args.dashboard_port),
                    "--strictPort",
                ],
                ROOT / "apps/frontend",
            )
            deadline = time.monotonic() + 12
            health = None
            while time.monotonic() < deadline:
                if api_proc.poll() is not None or front_proc.poll() is not None:
                    raise RuntimeError("API or frontend exited during startup")
                try:
                    health = request_json(api + "/health")
                    with urlopen(dashboard, timeout=0.5) as response:
                        page = response.read().decode()
                    if health.get("status") == "ready" and 'id="root"' in page:
                        break
                except (OSError, URLError, ValueError):
                    time.sleep(0.1)
            else:
                raise TimeoutError("API/frontend readiness timed out")
            with urlopen(dashboard + "/src/api.mjs", timeout=1.0) as response:
                transformed_client = response.read().decode()
            assert f'"{api}/api/v1"' in transformed_client

            status = request_json(api + "/api/v1/status")
            assert status["mode"] == "DEMO"
            assert status["controller"] in {
                "CONNECTED",
                "DISCONNECTED",
                "NOT_MONITORED",
                "STALE",
                "INVALID",
            }
            assert status["live_detection"] == "UNAVAILABLE"
            inference_id = None
            registry = request_json(api + "/api/v1/models")
            offline = next(
                (
                    model
                    for model in registry["models"]
                    if model.get("family") == "OFFLINE_APPLICATION_BASELINE"
                ),
                None,
            )
            if offline and offline.get("inference_enabled"):
                catalog = request_json(api + "/api/v1/datasets")["prepared_dataset"]
                source_file = next(
                    item["file_id"] for item in catalog["files"] if item["available"]
                )
                preview = request_json(
                    api
                    + f"/api/v1/datasets/cse-cic-ids2018-stage5d/preview?file={source_file}&limit=1"
                )
                row = preview["records"][0]
                schema = request_json(api + "/api/v1/inference/schema")["models"][0]
                inference = request_json(
                    api + "/api/v1/inference/predict",
                    method="POST",
                    payload={
                        "model_id": offline["model_id"],
                        "feature_schema": schema["feature_schema_id"],
                        "feature_order": schema["feature_order"],
                        "features": {key: float(value) for key, value in row["features"].items()},
                        "source": {
                            "source_type": "LABELED_DATA",
                            "dataset_id": "cse-cic-ids2018-stage5d",
                            "file_id": source_file,
                            "row_number": row["row_number"],
                        },
                    },
                )
                assert inference["predicted_label"] in {"BENIGN", "INTRUSION"}
                assert inference["ground_truth_label"] == row["source_label"]
                inference_id = inference["id"]
                print(
                    "Offline inference verified: "
                    f"{inference['predicted_label']} (ground truth "
                    f"{inference['ground_truth_label']}), raw score "
                    f"{inference['confidence']:.6f}; "
                    f"{inference['source_artifact']} row "
                    f"{inference['source_row_number']} SHA-256 "
                    f"{inference['source_sha256']}"
                )
                explanation = inference.get("explanation", {})
                contributions = explanation.get("top_features", [])
                rendered = "; ".join(
                    f"{item['feature']}={item['value']} "
                    f"(toward-prediction log-odds contribution "
                    f"{item['log_odds_contribution_toward_prediction']:.6f})"
                    for item in contributions[:3]
                )
                print(
                    f"Explanation method: {explanation.get('method')}; "
                    f"top contributions: {rendered}"
                )
            created = request_json(api + "/api/v1/sessions", method="POST")
            session_id = created["id"]
            assert len(request_json(api + f"/api/v1/sessions/{session_id}/events")["items"]) == 6
            export = request_json(api + f"/api/v1/sessions/{session_id}/export")
            assert export["session"]["id"] == session_id and export["synthetic"] is True
            stopped = request_json(api + f"/api/v1/sessions/{session_id}/stop", method="POST")
            assert stopped["status"] == "STOPPED"
            assert request_json(api + "/api/v1/audit")["items"]
            stop(api_proc)
            processes.remove(api_proc)
            api_proc = start([sys.executable, "-m", "apps.api.demo_app"], ROOT)
            restart_deadline = time.monotonic() + 5
            while time.monotonic() < restart_deadline:
                if api_proc.poll() is not None:
                    raise RuntimeError("API exited during persistence restart")
                try:
                    persisted = request_json(api + f"/api/v1/sessions/{session_id}")
                    if persisted["status"] == "STOPPED":
                        break
                except (OSError, URLError, ValueError):
                    time.sleep(0.1)
            else:
                raise TimeoutError("API did not return persisted session after restart")
            if inference_id:
                assert request_json(api + "/api/v1/detections")["items"][0]["id"] == inference_id
            print(
                f"HTTP smoke passed: API={api}/health, frontend={dashboard}, session={session_id}"
            )
            print("API and React entrypoint were exercised; no browser automation was run.")
            return 0
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=2)


if __name__ == "__main__":
    raise SystemExit(main())
