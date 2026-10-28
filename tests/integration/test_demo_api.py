"""Offline integration coverage for the local synthetic demo appliance."""

from __future__ import annotations

import hashlib
import io
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit
from wsgiref.types import StartResponse

import pytest

from apps.api.demo_app import DemoApplication, DemoStore
from apps.api.model_registry import MODEL_MANIFEST, PRELIMINARY_LIVE_MODEL_DIR, ModelRegistry
from ml.models.application_linear import FEATURE_SCHEMA_ID, MODEL_ARTIFACT_FORMAT, MODEL_ID
from src.sdn_defense.controller_status import ControllerStatusReader


def call_api(
    app: DemoApplication,
    path: str,
    *,
    method: str = "GET",
    body: bytes = b"",
    origin: str | None = None,
    content_type: str | None = None,
) -> tuple[int, dict[str, Any]]:
    captured: dict[str, Any] = {}
    parsed_path = urlsplit(path)

    def start_response(status: str, headers: list[tuple[str, str]]) -> None:
        captured["status"] = int(status.split()[0])
        captured["headers"] = dict(headers)

    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": parsed_path.path,
        "QUERY_STRING": parsed_path.query,
        "CONTENT_LENGTH": str(len(body)),
        "CONTENT_TYPE": content_type or ("application/json" if body else ""),
        "wsgi.input": io.BytesIO(body),
    }
    if origin:
        environ["HTTP_ORIGIN"] = origin
    result = b"".join(app(environ, cast(StartResponse, start_response)))
    return captured["status"], json.loads(result) if result else {}


def test_demo_records_are_synthetic_and_persisted(tmp_path: Path) -> None:
    app = DemoApplication(
        DemoStore(tmp_path / "demo.sqlite3"),
        controller_status=ControllerStatusReader(tmp_path / "no-controller-status.json"),
    )
    status, status_body = call_api(app, "/api/status")
    assert status == 200
    assert status_body["controller"] == "NOT_MONITORED"
    assert "No Ryu status artifact" in status_body["controller_reason"]
    assert status_body["live_network_enabled"] is False

    status, session = call_api(app, "/api/demo/sessions", method="POST", body=b"{}")
    assert status == 201
    assert session["synthetic"] is True
    assert session["status"] == "RUNNING"
    assert len(session["events"]) == 6
    assert {event["classification"] for event in session["events"]} == {"UNAVAILABLE"}
    assert {event["confidence"] for event in session["events"]} == {None}
    assert {event["feature_schema"] for event in session["events"]} == {None}
    assert datetime.fromisoformat(session["created_at"]).tzinfo is not None
    assert [event["scenario"] for event in session["events"]] == [
        "ARP spoofing",
        "DHCP starvation",
        "Port scan",
        "SYN flood",
        "Rogue-device link-toggle simulation",
        "DNS anomaly",
    ]

    status, runs = call_api(app, "/api/runs")
    assert status == 200
    assert runs["items"][0]["id"] == session["id"]
    status, events = call_api(app, "/api/events")
    assert status == 200
    assert all(item["synthetic"] is True for item in events["items"])
    status, audit = call_api(app, "/api/audit")
    assert status == 200
    assert audit["items"][0]["event_type"] == "DEMO_SESSION_CREATED"
    status, retrieved = call_api(app, f"/api/demo/sessions/{session['id']}")
    assert status == 200
    assert len(retrieved["events"]) == 6
    status, stopped = call_api(app, f"/api/demo/sessions/{session['id']}/stop", method="POST")
    assert status == 200
    assert stopped["status"] == "STOPPED"
    assert call_api(app, f"/api/demo/sessions/{session['id']}")[1]["status"] == "STOPPED"
    reopened_app = DemoApplication(DemoStore(tmp_path / "demo.sqlite3"))
    assert call_api(reopened_app, f"/api/demo/sessions/{session['id']}")[1]["status"] == "STOPPED"


def test_session_export_is_valid_json_and_contains_only_its_own_audit(tmp_path: Path) -> None:
    app = DemoApplication(DemoStore(tmp_path / "export.sqlite3"))
    _first_status, first = call_api(app, "/api/demo/sessions", method="POST", body=b"{}")
    _second_status, _second = call_api(app, "/api/demo/sessions", method="POST", body=b"{}")
    stop_status, _stopped = call_api(app, f"/api/demo/sessions/{first['id']}/stop", method="POST")
    assert stop_status == 200
    status, report = call_api(app, f"/api/demo/sessions/{first['id']}/export")
    assert status == 200
    encoded = json.dumps(report, allow_nan=False)
    decoded = json.loads(encoded)
    assert decoded["mode"] == "DEMO" and decoded["synthetic"] is True
    assert decoded["session"]["id"] == first["id"]
    assert decoded["session"]["created_at"] == first["created_at"]
    assert len(decoded["events"]) == 6
    assert all(event["run_id"] == first["id"] for event in decoded["events"])
    assert all(
        event["confidence"] is None and "features" not in event for event in decoded["events"]
    )
    assert {entry["event_type"] for entry in decoded["audit"]} == {
        "DEMO_SESSION_CREATED",
        "DEMO_SESSION_STOPPED",
    }
    assert all(entry["run_id"] == first["id"] for entry in decoded["audit"])
    assert datetime.fromisoformat(decoded["exported_at"]).tzinfo is not None
    assert call_api(app, f"/api/demo/sessions/{'0' * 36}/export")[0] == 404


def test_live_capability_is_unavailable_and_requests_are_restricted(tmp_path: Path) -> None:
    app = DemoApplication(DemoStore(tmp_path / "demo.sqlite3"))
    status, model = call_api(app, "/api/models")
    assert status == 200
    assert model["live"]["status"] == "UNAVAILABLE"
    assert model["live"]["artifact"] is None
    assert call_api(app, "/api/mitigations", method="POST", body=b"{}")[0] == 404
    assert (
        call_api(app, "/api/demo/sessions", method="POST", body=b'{"scenario":"arbitrary"}')[0]
        == 400
    )


def test_preliminary_live_model_is_hash_checked_but_never_approved(tmp_path: Path) -> None:
    model_dir = tmp_path / PRELIMINARY_LIVE_MODEL_DIR
    model_dir.mkdir(parents=True)
    artifact = model_dir / "model.joblib"
    artifact.write_bytes(b"trusted-local-test-model-artifact")
    order = [
        "rule_packet_delta",
        "rule_byte_delta",
        "rule_packet_rate_per_second",
        "rule_byte_rate_per_second",
    ]
    (model_dir / "manifest.json").write_text(
        json.dumps(
            {
                "model_id": "stage7-live-logistic-preliminary",
                "model_version": "0.1.0",
                "status": "TRAINED_UNAPPROVED_PRELIMINARY",
                "feature_schema_id": "stage7-live-rule-window-v1",
                "feature_order": order,
                "artifact": "model.joblib",
                "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
        ),
        encoding="utf-8",
    )
    entry = next(
        item
        for item in ModelRegistry(tmp_path).list_models()["models"]
        if item["model_id"] == "stage7-live-logistic-preliminary"
    )
    assert entry["status"] == "TRAINED_UNAPPROVED_PRELIMINARY"
    assert entry["inference_enabled"] is False
    assert entry["live_eligible"] is False
    artifact.write_bytes(b"tampered")
    entry = next(
        item
        for item in ModelRegistry(tmp_path).list_models()["models"]
        if item["model_id"] == "stage7-live-logistic-preliminary"
    )
    assert entry["status"] == "INCOMPATIBLE"
    assert "hash mismatch" in entry["reason"]


def test_empty_database_has_no_fabricated_live_events(tmp_path: Path) -> None:
    app = DemoApplication(DemoStore(tmp_path / "demo.sqlite3"))
    assert call_api(app, "/api/events") == (200, {"items": []})


def test_concurrent_sessions_commit_complete_run_event_audit_sets(tmp_path: Path) -> None:
    database = tmp_path / "parallel.sqlite3"
    app = DemoApplication(DemoStore(database))
    with ThreadPoolExecutor(max_workers=8) as executor:
        responses = list(
            executor.map(
                lambda _index: call_api(app, "/api/demo/sessions", method="POST", body=b"{}"),
                range(8),
            )
        )
    assert all(status == 201 for status, _body in responses)
    assert len({body["id"] for _status, body in responses}) == 8
    assert len(app.store.runs()) == 8
    assert len(app.store.events()) == 48
    assert len(app.store.audit()) == 8
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT version FROM schema_version").fetchall() == [(3,)]


def test_v1_route_contract_and_persisted_demo_lifecycle(tmp_path: Path) -> None:
    app = DemoApplication(
        DemoStore(tmp_path / "v1.sqlite3"),
        controller_status=ControllerStatusReader(tmp_path / "no-controller-status.json"),
    )
    assert call_api(app, "/health")[0] == 200
    status, state = call_api(app, "/api/v1/status")
    assert status == 200
    assert state["controller"] == "NOT_MONITORED"
    assert state["live_detection"] == "UNAVAILABLE"
    created_status, created = call_api(app, "/api/v1/sessions", method="POST", body=b"{}")
    assert created_status == 201
    assert call_api(app, "/api/v1/sessions", method="POST", body=b'{"label":"ignored"}')[0] == 400
    session_id = created["id"]
    assert call_api(app, "/api/v1/sessions")[1]["items"][0]["id"] == session_id
    assert call_api(app, f"/api/v1/sessions/{session_id}")[0] == 200
    assert len(call_api(app, f"/api/v1/sessions/{session_id}/events")[1]["items"]) == 6
    assert call_api(app, f"/api/v1/sessions/{session_id}/audit")[0] == 200
    assert call_api(app, f"/api/v1/sessions/{session_id}/export")[1]["session"]["id"] == session_id
    stopped_status, stopped = call_api(app, f"/api/v1/sessions/{session_id}/stop", method="POST")
    assert stopped_status == 200 and stopped["status"] == "STOPPED"
    assert call_api(app, "/api/v1/detections")[1]["items"] == []
    assert call_api(app, "/api/v1/datasets")[0] == 200
    assert call_api(app, "/api/v1/experiments")[0] == 200
    assert call_api(app, "/api/v1/telemetry/audits")[0] == 200
    assert call_api(app, "/api/v1/models")[0] == 200
    live_status_code, live_status = call_api(app, "/api/v1/live/status")
    assert live_status_code == 200
    assert live_status["controller"] == "NOT_MONITORED"
    assert live_status["live_detection"] == "UNAVAILABLE"
    assert live_status["mitigation"] == "DISABLED"
    assert call_api(app, "/api/v1/live/detections")[1]["items"] == []
    assert call_api(app, "/api/v1/live/ledger")[1]["items"] == []
    assert call_api(app, "/api/v1/inference/schema")[0] == 200
    assert call_api(app, "/api/v1/audit")[0] == 200
    assert call_api(app, "/api/v1/not-a-route")[0] == 404


def test_combined_audit_api_pages_all_session_and_inference_events(tmp_path: Path) -> None:
    app = DemoApplication(DemoStore(tmp_path / "audit-pages.sqlite3"))
    status, session = call_api(app, "/api/v1/sessions", method="POST", body=b"{}")
    assert status == 201
    app.store.save_prediction(
        {
            "prediction_timestamp": "2026-10-28T12:00:00+00:00",
            "model_id": MODEL_ID,
            "model_version": "test",
            "predicted_label": "BENIGN",
        },
        request_id="audit-test-request",
        source={"source_type": "LABELED_DATA"},
    )

    status, first = call_api(app, "/api/v1/audit?limit=1&offset=0")
    assert status == 200
    status, second = call_api(app, "/api/v1/audit?limit=1&offset=1")
    assert status == 200
    combined = first["items"] + second["items"]
    assert first["page"]["total"] == second["page"]["total"] == 2
    assert {item["event_type"] for item in combined} == {
        "DEMO_SESSION_CREATED",
        "OFFLINE_PREDICTION_RECORDED",
    }
    assert {item["source_type"] for item in combined} == {
        "SYNTHETIC_FIXTURE",
        "MODEL_PREDICTION",
    }
    assert (
        call_api(app, f"/api/v1/sessions/{session['id']}/audit")[1]["items"][0]["event_type"]
        == "DEMO_SESSION_CREATED"
    )


def test_v1_inference_unavailable_is_explicit_and_schema_mismatch_rejected(tmp_path: Path) -> None:
    app = DemoApplication(DemoStore(tmp_path / "v1-inference.sqlite3"))
    schema_status, schema = call_api(app, "/api/v1/inference/schema")
    assert schema_status == 200
    live_contract = next(
        item
        for item in schema["models"]
        if item["feature_schema_id"] == "stage7-live-rule-window-v1"
    )
    assert live_contract["status"] in {"PROVISIONAL_BENIGN_CALIBRATION", "UNAVAILABLE"}
    assert "direct live inference requests are not supported" in live_contract["reason"]
    request = {
        "model_id": "stage7-live-rule-counter",
        "feature_schema": "stage7-live-rule-window-v1",
        "feature_order": [
            "rule_packet_delta",
            "rule_byte_delta",
            "rule_packet_rate_per_second",
            "rule_byte_rate_per_second",
        ],
        "features": {
            "rule_packet_delta": 1,
            "rule_byte_delta": 2,
            "rule_packet_rate_per_second": 1.0,
            "rule_byte_rate_per_second": 2.0,
        },
    }
    status, body = call_api(
        app, "/api/v1/inference/predict", method="POST", body=json.dumps(request).encode()
    )
    assert status == 503
    assert body["error"]["code"] == "MODEL_UNAVAILABLE"
    assert call_api(app, "/api/v1/inference/predict", method="POST", body=b"not-json")[0] == 422


def test_labeled_inference_coerces_string_features_and_exposes_shap(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    artifact = (
        root
        / "data/processed/stage5d/cse-cic-ids2018"
        / "Friday-02-03-2018_TrafficForML_CICFlowMeter.model-ready.csv.gz"
    )
    if not artifact.is_file() or not (
        root / "var/models/cse-cicflowmeter-binary-logistic-v1/model.json"
    ).is_file():
        pytest.skip("prepared CSE artifact or offline model unavailable in this checkout")

    app = DemoApplication(DemoStore(tmp_path / "labeled-inference.sqlite3"))
    status, preview = call_api(
        app,
        "/api/v1/datasets/cse-cic-ids2018-stage5d/preview"
        "?file=Friday-02-03-2018_TrafficForML_CICFlowMeter.csv&limit=1",
    )
    assert status == 200
    row = preview["records"][0]
    assert isinstance(next(iter(row["features"].values())), float)
    schema = call_api(app, "/api/v1/inference/schema")[1]["models"][0]
    # Echo features as strings, matching a browser JSON path that skipped Number().
    string_features = {name: str(value) for name, value in row["features"].items()}
    payload = {
        "model_id": MODEL_ID,
        "feature_schema": schema["feature_schema_id"],
        "feature_order": schema["feature_order"],
        "features": string_features,
        "source": {
            "source_type": "LABELED_DATA",
            "dataset_id": "cse-cic-ids2018-stage5d",
            "file_id": "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv",
            "row_number": 1,
        },
    }
    status, prediction = call_api(
        app, "/api/v1/inference/predict", method="POST", body=json.dumps(payload).encode()
    )
    assert status == 200
    assert prediction["predicted_label"] in {"BENIGN", "INTRUSION"}
    assert prediction["ground_truth_label"] == row["source_label"]
    assert prediction["explanation"]["shap_compatible"] is True
    assert prediction["explanation"]["top_features"][0]["shap_value"] is not None


def test_real_safe_json_inference_is_persisted_without_raw_features(tmp_path: Path) -> None:
    root = tmp_path / "registry-root"
    artifact_dir = root / MODEL_MANIFEST.parent
    artifact_dir.mkdir(parents=True)
    names = [f"feature_{index}" for index in range(77)]
    coefficients = [0.0] * 77
    coefficients[0] = 1.0
    artifact = {
        "artifact_format": MODEL_ARTIFACT_FORMAT,
        "model_id": MODEL_ID,
        "version": "test-1",
        "feature_schema_id": FEATURE_SCHEMA_ID,
        "feature_names": names,
        "mean": [0.0] * 77,
        "scale": [1.0] * 77,
        "classes": ["BENIGN", "INTRUSION"],
        "coefficients": coefficients,
        "intercept": 0.0,
    }
    artifact_bytes = (json.dumps(artifact, sort_keys=True) + "\n").encode()
    (artifact_dir / "model.json").write_bytes(artifact_bytes)
    manifest = {
        "model_id": MODEL_ID,
        "version": "test-1",
        "artifact_format": MODEL_ARTIFACT_FORMAT,
        "artifact": "model.json",
        "artifact_sha256": hashlib.sha256(artifact_bytes).hexdigest(),
        "feature_schema_id": FEATURE_SCHEMA_ID,
        "feature_names": names,
        "live_eligible": False,
    }
    (artifact_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    app = DemoApplication(DemoStore(tmp_path / "inference.sqlite3"))
    app.models = ModelRegistry(root)
    payload = {
        "model_id": MODEL_ID,
        "feature_schema": FEATURE_SCHEMA_ID,
        "feature_order": names,
        "features": {**dict.fromkeys(names, 0.0), names[0]: 2.0},
        "source": {"source_type": "UNSPECIFIED"},
    }
    status, prediction = call_api(
        app, "/api/v1/inference/predict", method="POST", body=json.dumps(payload).encode()
    )
    assert status == 200
    assert prediction["predicted_label"] == "INTRUSION"
    assert prediction["feature_schema_id"] == FEATURE_SCHEMA_ID
    assert prediction["source_type"] == "UNSPECIFIED"
    assert "features" not in prediction
    assert call_api(app, "/api/v1/detections")[1]["page"]["total"] == 1
    audit = call_api(app, "/api/v1/audit")[1]["items"]
    assert audit[0]["event_type"] == "OFFLINE_PREDICTION_RECORDED"
    assert audit[0]["payload"]["raw_feature_values_stored"] is False


def test_cors_is_limited_to_the_dashboard_origin(tmp_path: Path) -> None:
    app = DemoApplication(DemoStore(tmp_path / "cors.sqlite3"))
    captured: dict[str, Any] = {}

    def start_response(status: str, headers: list[tuple[str, str]]) -> None:
        captured["status"] = status
        captured["headers"] = dict(headers)

    environ = {
        "REQUEST_METHOD": "OPTIONS",
        "PATH_INFO": "/api/status",
        "QUERY_STRING": "",
        "HTTP_ORIGIN": "http://127.0.0.1:5173",
        "wsgi.input": io.BytesIO(),
    }
    response = b"".join(app(environ, cast(Any, start_response)))
    assert response == b""
    assert captured["status"].startswith("204")
    assert captured["headers"]["Access-Control-Allow-Origin"] == "http://127.0.0.1:5173"
    assert "DELETE" not in captured["headers"]["Access-Control-Allow-Methods"]

    # Browsers often open the printed port via localhost; treat it as the same
    # loopback dashboard twin so fetch is not blocked after a successful start.
    environ["HTTP_ORIGIN"] = "http://localhost:5173"
    localhost = b"".join(app(environ, cast(Any, start_response)))
    assert localhost == b""
    assert captured["status"].startswith("204")
    assert captured["headers"]["Access-Control-Allow-Origin"] == "http://localhost:5173"

    status, body = call_api(app, "/api/v1/status", origin="http://localhost:5173")
    assert status == 200
    assert body["mode"] == "DEMO"
    # call_api captures the final headers through the CORS wrapper
    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/api/v1/status",
        "QUERY_STRING": "",
        "HTTP_ORIGIN": "http://localhost:5173",
        "wsgi.input": io.BytesIO(),
    }
    b"".join(app(environ, cast(Any, start_response)))
    assert captured["headers"]["Access-Control-Allow-Origin"] == "http://localhost:5173"

    environ["REQUEST_METHOD"] = "OPTIONS"
    environ["PATH_INFO"] = "/api/status"
    environ["HTTP_ORIGIN"] = "https://untrusted.example"
    denied = b"".join(app(environ, cast(Any, start_response)))
    assert json.loads(denied)["error"] == "not found"
    assert captured["status"].startswith("404")
    assert "Access-Control-Allow-Origin" not in captured["headers"]


def test_dashboard_route_contract_and_missing_route_are_not_hidden(tmp_path: Path) -> None:
    app = DemoApplication(DemoStore(tmp_path / "routes.sqlite3"))
    # These are the data routes used by the current dashboard. A 404 here must
    # remain a failure; the browser client must not turn it into empty data.
    for route in (
        "/api/health",
        "/api/status",
        "/api/runs",
        "/api/events",
        "/api/audit",
        "/api/models",
        "/api/data-sources",
        "/api/historical-results",
        "/api/dataset-sources",
        "/api/telemetry-runs",
    ):
        status, _body = call_api(app, route)
        assert status == 200, route
    assert call_api(app, "/api/definitely-not-a-route")[0] == 404
    assert call_api(app, "/api/dataset-preview?bad=true")[0] == 400


def test_historical_and_telemetry_routes_preserve_real_artifact_status(tmp_path: Path) -> None:
    app = DemoApplication(DemoStore(tmp_path / "sources.sqlite3"))
    status, historical = call_api(app, "/api/historical-results")
    assert status == 200
    unsw = next(
        row
        for row in historical["records"]
        if row["source_id"] == "unsw-stage5b-baselines" and row["model"] == "random_forest"
    )
    assert unsw["historical_only"] is True
    assert unsw["metrics"]["accuracy"] == 0.6741242773162318
    assert unsw["artifact_sha256"]

    status, prepared = call_api(app, "/api/dataset-sources")
    assert status == 200 and len(prepared["files"]) == 7
    assert all(item["available"] for item in prepared["files"])

    status, telemetry = call_api(app, "/api/telemetry-runs")
    assert status == 200 and telemetry["runs"]
    assert telemetry["available_valid_runs"] == 3
    verified = next(
        item
        for item in telemetry["runs"]
        if item["source_id"] == "live-2026-10-28-first-verified-benign-03"
    )
    assert verified["provenance_status"] == "AUDIT_COMPLETE"
    assert verified["complete"] is True
    assert verified["artifact_sha256"]
    assert verified["usable_as_detection_evidence"] is False
    assert all(
        not item["usable_as_detection_evidence"]
        for item in telemetry["runs"]
        if item["source_id"] != "live-2026-10-28-first-verified-benign-03"
    )


def test_invalid_cors_origin_fails_before_database_creation(
    tmp_path: Path, monkeypatch: Any
) -> None:
    database = tmp_path / "must-not-exist.sqlite3"
    monkeypatch.setenv("SDN_DEMO_DATABASE", str(database))
    monkeypatch.setenv("SDN_DEMO_CORS_ORIGIN", "https://untrusted.example")
    try:
        DemoApplication()
    except ValueError as error:
        assert "SDN_DEMO_CORS_ORIGIN" in str(error)
    else:
        raise AssertionError("non-loopback CORS origin should be rejected")
    assert not database.exists()


def test_malformed_utf8_is_a_client_error_and_storage_errors_are_503(tmp_path: Path) -> None:
    app = DemoApplication(DemoStore(tmp_path / "errors.sqlite3"))
    assert (
        call_api(
            app,
            "/api/demo/sessions",
            method="POST",
            body=b"\xff",
            content_type="application/json",
        )[0]
        == 400
    )
    assert (
        call_api(
            app,
            "/api/demo/sessions",
            method="POST",
            body=b"{}",
            content_type="text/plain",
        )[0]
        == 415
    )
    assert (
        call_api(
            app,
            "/api/demo/sessions",
            method="POST",
            body=b"null",
            content_type="application/json",
        )[0]
        == 400
    )

    class FailingStore(DemoStore):
        def runs(self) -> list[dict[str, Any]]:
            raise sqlite3.OperationalError("private database path should not leak")

    status, body = call_api(DemoApplication(FailingStore(tmp_path / "broken.sqlite3")), "/api/runs")
    assert status == 503
    assert body == {"error": "demo storage unavailable"}
