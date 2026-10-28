"""Local demo API with SQLite persistence and no live-network dependencies.

All generated records are synthetic and are kept separate from network evidence.
The small WSGI surface exists so the review demo can run with Python's standard
library when optional web frameworks are unavailable.
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from http import HTTPStatus
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit
from wsgiref.simple_server import make_server
from wsgiref.types import StartResponse, WSGIEnvironment

from apps.api.controller_sim import ControllerSimulator
from apps.api.live_service import LiveScoringService
from apps.api.model_registry import ModelRegistry, ModelUnavailableError
from apps.api.project_data import ProjectDataSources
from ml.models.application_linear import MODEL_ID
from src.sdn_defense.controller_status import ControllerStatusReader

DEFAULT_DATABASE = Path("var/demo.sqlite3")
SCHEMA_VERSION = 3
SCENARIOS: tuple[dict[str, Any], ...] = (
    {
        "scenario": "ARP spoofing",
        "classification": "UNAVAILABLE",
        "risk": "UNCERTAIN",
        "evidence": "Synthetic scenario label only; no validated detector evidence.",
        "action": "MONITOR",
        "mitigation": "NOT_SUBMITTED",
    },
    {
        "scenario": "DHCP starvation",
        "classification": "UNAVAILABLE",
        "risk": "UNCERTAIN",
        "evidence": "Synthetic scenario label only; no validated detector evidence.",
        "action": "MONITOR",
        "mitigation": "NOT_SUBMITTED",
    },
    {
        "scenario": "Port scan",
        "classification": "UNAVAILABLE",
        "risk": "UNCERTAIN",
        "evidence": "Synthetic scenario label only; rule-counter detector is unavailable.",
        "action": "MONITOR",
        "mitigation": "NOT_SUBMITTED",
    },
    {
        "scenario": "SYN flood",
        "classification": "UNAVAILABLE",
        "risk": "UNCERTAIN",
        "evidence": "Synthetic scenario label only; no validated detector evidence.",
        "action": "MONITOR",
        "mitigation": "NOT_SUBMITTED",
    },
    {
        "scenario": "Rogue-device link-toggle simulation",
        "classification": "UNAVAILABLE",
        "risk": "UNCERTAIN",
        "evidence": "Illustrates the recorded link-toggle scenario; not a rogue-device detector.",
        "action": "MONITOR",
        "mitigation": "NOT_SUBMITTED",
    },
    {
        "scenario": "DNS anomaly",
        "classification": "UNAVAILABLE",
        "risk": "UNCERTAIN",
        "evidence": "Synthetic scenario label only; no validated detector evidence.",
        "action": "MONITOR",
        "mitigation": "NOT_SUBMITTED",
    },
)


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


class DemoStore:
    """Versioned SQLite store for demo sessions, events, and audit entries."""

    def __init__(self, path: Path = DEFAULT_DATABASE) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)"
            )
            versions = connection.execute("SELECT version FROM schema_version").fetchall()
            current_version = max((int(row[0]) for row in versions), default=0)
            if current_version > SCHEMA_VERSION:
                raise RuntimeError(
                    f"demo database schema {current_version} is newer than supported"
                )
            if current_version == 0:
                connection.execute(
                    "INSERT INTO schema_version(version) VALUES (?)", (SCHEMA_VERSION,)
                )
            elif current_version < SCHEMA_VERSION:
                connection.execute("UPDATE schema_version SET version = ?", (SCHEMA_VERSION,))
            connection.execute(
                """CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY, mode TEXT NOT NULL, status TEXT NOT NULL,
                    created_at TEXT NOT NULL, synthetic INTEGER NOT NULL
                )"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id),
                    created_at TEXT NOT NULL, payload TEXT NOT NULL
                )"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS audit (
                    id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id),
                    created_at TEXT NOT NULL, event_type TEXT NOT NULL, payload TEXT NOT NULL
                )"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS predictions (
                    id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL, model_id TEXT NOT NULL,
                    model_version TEXT NOT NULL, source_type TEXT NOT NULL,
                    source_artifact TEXT, source_sha256 TEXT, source_row_number INTEGER,
                    ground_truth_label TEXT, payload TEXT NOT NULL
                )"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS inference_audit (
                    id TEXT PRIMARY KEY, request_id TEXT NOT NULL,
                    created_at TEXT NOT NULL, event_type TEXT NOT NULL,
                    outcome TEXT NOT NULL, payload TEXT NOT NULL
                )"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS mitigation_actions (
                    id TEXT PRIMARY KEY,
                    action_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    submitted_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    target_flow TEXT,
                    ttl_seconds INTEGER,
                    reason TEXT,
                    payload TEXT NOT NULL
                )"""
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_predictions_created ON predictions(created_at DESC)"
            )

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def create_demo(self) -> dict[str, Any]:
        run_id, created_at = str(uuid.uuid4()), utc_now()
        events = [
            {
                "id": str(uuid.uuid4()),
                "run_id": run_id,
                "created_at": created_at,
                "mode": "DEMO",
                "synthetic": True,
                **scenario,
                "confidence": None,
                "model": "none",
                "feature_schema": None,
                "telemetry_status": "UNAVAILABLE",
                "explanation": scenario["evidence"],
            }
            for scenario in SCENARIOS
        ]
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO runs VALUES (?, 'DEMO', 'RUNNING', ?, 1)", (run_id, created_at)
            )
            connection.executemany(
                "INSERT INTO events VALUES (?, ?, ?, ?)",
                [
                    (event["id"], run_id, created_at, json.dumps(event, sort_keys=True))
                    for event in events
                ],
            )
            audit = {
                "run_id": run_id,
                "mode": "DEMO",
                "synthetic": True,
                "event_count": len(events),
            }
            connection.execute(
                "INSERT INTO audit VALUES (?, ?, ?, 'DEMO_SESSION_CREATED', ?)",
                (str(uuid.uuid4()), run_id, created_at, json.dumps(audit, sort_keys=True)),
            )
        return {
            "id": run_id,
            "mode": "DEMO",
            "status": "RUNNING",
            "created_at": created_at,
            "synthetic": True,
            "events": events,
        }

    def run(self, run_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        return self._run_document(row) if row else None

    def stop_run(self, run_id: str) -> dict[str, Any] | None:
        stopped_at = utc_now()
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
            if row is None:
                return None
            if row["status"] == "RUNNING":
                connection.execute("UPDATE runs SET status = 'STOPPED' WHERE id = ?", (run_id,))
                connection.execute(
                    "INSERT INTO audit VALUES (?, ?, ?, 'DEMO_SESSION_STOPPED', ?)",
                    (
                        str(uuid.uuid4()),
                        run_id,
                        stopped_at,
                        json.dumps(
                            {"run_id": run_id, "mode": "DEMO", "synthetic": True}, sort_keys=True
                        ),
                    ),
                )
            updated = connection.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        return self._run_document(updated) if updated else None

    @staticmethod
    def _run_document(row: sqlite3.Row) -> dict[str, Any]:
        document = dict(row)
        document["synthetic"] = bool(document["synthetic"])
        return document

    def runs(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            return [
                self._run_document(row)
                for row in connection.execute("SELECT * FROM runs ORDER BY rowid DESC")
            ]

    def events(self, run_id: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT payload FROM events"
        args: tuple[str, ...] = ()
        if run_id:
            query += " WHERE run_id = ?"
            args = (run_id,)
        query += " ORDER BY rowid"
        with self.connect() as connection:
            return [json.loads(row[0]) for row in connection.execute(query, args)]

    def audit(self, run_id: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM audit"
        args: tuple[str, ...] = ()
        if run_id:
            query += " WHERE run_id = ?"
            args = (run_id,)
        query += " ORDER BY rowid DESC"
        with self.connect() as connection:
            return [dict(row) for row in connection.execute(query, args)]

    def save_prediction(
        self,
        prediction: dict[str, Any],
        *,
        request_id: str,
        source: dict[str, Any],
    ) -> dict[str, Any]:
        prediction_id = str(uuid.uuid4())
        created_at = str(prediction["prediction_timestamp"])
        source_type = str(source.get("source_type", "UNSPECIFIED"))
        source_artifact = source.get("artifact")
        source_sha256 = source.get("sha256")
        source_row = source.get("row_number")
        ground_truth = source.get("ground_truth_label")
        safe_payload = {
            **prediction,
            "id": prediction_id,
            "request_id": request_id,
            "source_type": source_type,
            "source_artifact": source_artifact,
            "source_sha256": source_sha256,
            "source_row_number": source_row,
            "ground_truth_label": ground_truth,
        }
        audit_id = str(uuid.uuid4())
        audit_payload = {
            "request_id": request_id,
            "prediction_id": prediction_id,
            "model_id": prediction["model_id"],
            "source_type": source_type,
            "outcome": "PREDICTION_RECORDED",
            "raw_feature_values_stored": False,
        }
        with self.connect() as connection:
            connection.execute(
                """INSERT INTO predictions
                (id, request_id, created_at, model_id, model_version, source_type,
                 source_artifact, source_sha256, source_row_number, ground_truth_label, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    prediction_id,
                    request_id,
                    created_at,
                    prediction["model_id"],
                    prediction["model_version"],
                    source_type,
                    source_artifact,
                    source_sha256,
                    source_row,
                    ground_truth,
                    json.dumps(safe_payload, sort_keys=True, allow_nan=False),
                ),
            )
            connection.execute(
                """INSERT INTO inference_audit
                (id, request_id, created_at, event_type, outcome, payload)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    audit_id,
                    request_id,
                    created_at,
                    "OFFLINE_PREDICTION_RECORDED",
                    "PREDICTION_RECORDED",
                    json.dumps(audit_payload, sort_keys=True),
                ),
            )
        return safe_payload

    def predictions(self, limit: int, offset: int) -> tuple[list[dict[str, Any]], int]:
        with self.connect() as connection:
            total = int(connection.execute("SELECT COUNT(*) FROM predictions").fetchone()[0])
            rows = connection.execute(
                "SELECT payload FROM predictions ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [json.loads(row[0]) for row in rows], total

    def inference_audit(self, limit: int, offset: int) -> tuple[list[dict[str, Any]], int]:
        with self.connect() as connection:
            total = int(connection.execute("SELECT COUNT(*) FROM inference_audit").fetchone()[0])
            rows = connection.execute(
                """SELECT id, request_id, created_at, event_type, outcome, payload
                FROM inference_audit ORDER BY created_at DESC LIMIT ? OFFSET ?""",
                (limit, offset),
            ).fetchall()
        return [dict(row) for row in rows], total

    def combined_audit(self, limit: int, offset: int) -> tuple[list[dict[str, Any]], int]:
        """Page the unified persisted session and inference audit stream."""
        with self.connect() as connection:
            total = int(
                connection.execute(
                    "SELECT (SELECT COUNT(*) FROM audit) + (SELECT COUNT(*) FROM inference_audit)"
                ).fetchone()[0]
            )
            rows = connection.execute(
                """SELECT id, run_id AS request_id, created_at, event_type,
                          'RECORDED' AS outcome, payload, 'SYNTHETIC_FIXTURE' AS source_type
                   FROM audit
                   UNION ALL
                   SELECT id, request_id, created_at, event_type, outcome, payload,
                          'MODEL_PREDICTION' AS source_type
                   FROM inference_audit
                   ORDER BY created_at DESC LIMIT ? OFFSET ?""",
                (limit, offset),
            ).fetchall()
        items = [dict(row) for row in rows]
        for item in items:
            with suppress(TypeError, json.JSONDecodeError):
                item["payload"] = json.loads(item["payload"])
        return items, total

    def create_mitigation_action(self, action_type: str, **kwargs: Any) -> dict[str, Any]:
        """Create a new mitigation action record."""
        action_id = str(uuid.uuid4())
        now = utc_now()
        # Rate limiting is unsupported by design
        status = "SUBMITTED" if action_type != "ROLLBACK_ALL" else "ROLLED_BACK"
        if action_type == "RATE_LIMIT_FLOW":
            status = "FAILED"
        action = {
            "id": action_id,
            "action_type": action_type,
            "status": status,
            "submitted_at": now,
            "updated_at": now,
            "target_flow": kwargs.get("target_flow"),
            "ttl_seconds": kwargs.get("ttl_seconds", 60),
            "reason": kwargs.get("reason", f"Manual {action_type} from dashboard"),
            "note": (
                "Rate limiting unsupported: no OVS meter implementation."
                if action_type == "RATE_LIMIT_FLOW"
                else "Synthetic demo action; no live OpenFlow enforcement."
            ),
        }
        with self.connect() as connection:
            connection.execute(
                """INSERT INTO mitigation_actions
                   (id, action_type, status, submitted_at, updated_at, target_flow,
                    ttl_seconds, reason, payload)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    action_id, action_type, status, now, now,
                    action.get("target_flow"), action.get("ttl_seconds"),
                    action.get("reason"), json.dumps(action, sort_keys=True),
                ),
            )
        return action

    def mitigation_actions(
        self, limit: int = 20, offset: int = 0
    ) -> tuple[list[dict[str, Any]], int]:
        """List mitigation actions in reverse chronological order."""
        with self.connect() as connection:
            total = int(
                connection.execute("SELECT COUNT(*) FROM mitigation_actions").fetchone()[0]
            )
            rows = connection.execute(
                "SELECT payload FROM mitigation_actions ORDER BY submitted_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [json.loads(row[0]) for row in rows], total


class DemoApplication:
    """Small local-only JSON API; live networking and mitigation stay disabled."""

    def __init__(
        self,
        store: DemoStore | None = None,
        *,
        controller_status: ControllerStatusReader | None = None,
    ) -> None:
        self.cors_origin = os.getenv("SDN_DEMO_CORS_ORIGIN", "http://127.0.0.1:5173")
        parsed_origin = urlsplit(self.cors_origin)
        if (
            parsed_origin.scheme != "http"
            or parsed_origin.hostname != "127.0.0.1"
            or parsed_origin.port is None
            or not 1 <= parsed_origin.port <= 65535
            or parsed_origin.username is not None
            or parsed_origin.password is not None
            or parsed_origin.path
            or parsed_origin.query
            or parsed_origin.fragment
        ):
            raise ValueError("SDN_DEMO_CORS_ORIGIN must be an http://127.0.0.1:<port> origin")
        self._cors_port = parsed_origin.port
        self._cors_origins = frozenset(
            {
                f"http://127.0.0.1:{self._cors_port}",
                f"http://localhost:{self._cors_port}",
            }
        )
        project_root = Path(__file__).resolve().parents[2]
        self.store = store or DemoStore(Path(os.getenv("SDN_DEMO_DATABASE", str(DEFAULT_DATABASE))))
        self.project_data = ProjectDataSources(project_root)
        self.models = ModelRegistry(project_root)
        status_path = Path(os.getenv("SDN_RYU_STATUS_FILE", "var/runtime/ryu-status.json"))
        if not status_path.is_absolute():
            status_path = project_root / status_path
        status_path = status_path.resolve()
        if not status_path.is_relative_to((project_root / "var/runtime").resolve()):
            raise ValueError("SDN_RYU_STATUS_FILE must be within var/runtime")
        try:
            freshness = float(os.getenv("SDN_RYU_STATUS_STALE_AFTER_SECONDS", "6.0"))
        except ValueError as error:
            raise ValueError("SDN_RYU_STATUS_STALE_AFTER_SECONDS must be numeric") from error
        self.controller_status = controller_status or ControllerStatusReader(
            status_path, stale_after_seconds=freshness
        )
        self.live_scoring = LiveScoringService(
            project_root,
            self.store.path,
            self.controller_status,
            maximum_window_age_seconds=15.0,
        )

    def _allowed_cors_origin(self, request_origin: str | None) -> str | None:
        """Return an allowed loopback dashboard origin, or the configured default."""
        if request_origin is None:
            return self.cors_origin
        return request_origin if request_origin in self._cors_origins else None

    def response(self, start_response: StartResponse, status: HTTPStatus, body: Any) -> list[bytes]:
        data = json.dumps(body, sort_keys=True, allow_nan=False).encode()
        start_response(
            f"{status.value} {status.phrase}",
            [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(data))),
                ("Cache-Control", "no-store"),
            ],
        )
        return [data]

    def __call__(self, environ: WSGIEnvironment, start_response: StartResponse) -> list[bytes]:
        allow_origin = self._allowed_cors_origin(environ.get("HTTP_ORIGIN"))

        def cors_start_response(
            status: str,
            headers: list[tuple[str, str]],
            exc_info: Any | None = None,
        ) -> Any:
            filtered = [
                (key, value)
                for key, value in headers
                if key.lower() not in {"access-control-allow-origin", "vary"}
            ]
            if allow_origin is not None:
                filtered.append(("Access-Control-Allow-Origin", allow_origin))
            filtered.append(("Vary", "Origin"))
            if exc_info is not None:
                return start_response(status, filtered, exc_info)
            return start_response(status, filtered)

        try:
            return self._dispatch(environ, cors_start_response)
        except sqlite3.Error:
            logging.getLogger(__name__).exception("demo database operation failed")
            return self.response(
                cors_start_response,
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": "demo storage unavailable"},
            )

    def _dispatch(self, environ: WSGIEnvironment, start_response: StartResponse) -> list[bytes]:
        method, path = environ.get("REQUEST_METHOD", "GET"), environ.get("PATH_INFO", "/")
        request_origin = environ.get("HTTP_ORIGIN")
        allowed_origin = self._allowed_cors_origin(request_origin) if request_origin else None
        if method == "OPTIONS" and allowed_origin is not None:
            start_response(
                "204 No Content",
                [
                    ("Access-Control-Allow-Origin", allowed_origin),
                    ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
                    ("Access-Control-Allow-Headers", "Content-Type"),
                    ("Vary", "Origin"),
                ],
            )
            return [b""]
        if path == "/health" and method == "GET":
            return self.response(
                start_response,
                HTTPStatus.OK,
                {
                    "status": "ready",
                    "api_version": "v1",
                    "mode": "DEMO",
                    "live_network": "DISABLED",
                    "mitigation": "DISABLED",
                },
            )
        if path.startswith("/api/v1/"):
            return self._dispatch_v1(environ, start_response, method, path)
        if path == "/api/health" and method == "GET":
            return self.response(
                start_response,
                HTTPStatus.OK,
                {
                    "status": "ready",
                    "mode": "DEMO",
                    "live_network": "DISABLED",
                    "mitigation": "DISABLED",
                    "detector": "UNAVAILABLE",
                },
            )
        if path == "/api/status" and method == "GET":
            controller = self.controller_status.read()
            return self.response(
                start_response,
                HTTPStatus.OK,
                {
                    "mode": "DEMO",
                    "synthetic": True,
                    **controller,
                    "telemetry": "UNAVAILABLE",
                    "live_detection": "UNAVAILABLE",
                    "live_network_enabled": False,
                    "mitigation_enabled": False,
                },
            )
        if path == "/api/demo/sessions" and method == "POST":
            try:
                length = int(environ.get("CONTENT_LENGTH") or "0")
            except ValueError:
                return self.response(
                    start_response, HTTPStatus.BAD_REQUEST, {"error": "invalid content length"}
                )
            if length < 0:
                return self.response(
                    start_response, HTTPStatus.BAD_REQUEST, {"error": "invalid content length"}
                )
            if length > 1024:
                return self.response(
                    start_response,
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    {"error": "request too large"},
                )
            content_type = environ.get("CONTENT_TYPE", "").split(";", 1)[0].strip().lower()
            if length and content_type != "application/json":
                return self.response(
                    start_response,
                    HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                    {"error": "Content-Type must be application/json"},
                )
            try:
                if length:
                    payload = json.loads(environ["wsgi.input"].read(length))
                    if payload != {}:
                        raise ValueError("demo session accepts an empty object only")
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
                return self.response(
                    start_response, HTTPStatus.BAD_REQUEST, {"error": "invalid demo request"}
                )
            return self.response(start_response, HTTPStatus.CREATED, self.store.create_demo())
        session_path = re.fullmatch(r"/api/demo/sessions/([0-9a-f-]{36})(/stop|/export)?", path)
        if session_path and method == "GET" and session_path.group(2) == "/export":
            run_id = session_path.group(1)
            run = self.store.run(run_id)
            if run is None:
                return self.response(
                    start_response, HTTPStatus.NOT_FOUND, {"error": "session not found"}
                )
            events = self.store.events(run_id)
            return self.response(
                start_response,
                HTTPStatus.OK,
                {
                    "report_version": 1,
                    "mode": "DEMO",
                    "synthetic": True,
                    "exported_at": utc_now(),
                    "session": run,
                    "events": events,
                    "audit": self.store.audit(run_id),
                    "limitations": [
                        "No live telemetry",
                        "No approved live-native detector",
                        "No mitigation is submitted in demo mode",
                    ],
                },
            )
        if session_path and method == "GET" and session_path.group(2) is None:
            run = self.store.run(session_path.group(1))
            if run is None:
                return self.response(
                    start_response, HTTPStatus.NOT_FOUND, {"error": "session not found"}
                )
            run["events"] = self.store.events(session_path.group(1))
            return self.response(start_response, HTTPStatus.OK, run)
        if session_path and method == "POST" and session_path.group(2) == "/stop":
            run = self.store.stop_run(session_path.group(1))
            if run is None:
                return self.response(
                    start_response, HTTPStatus.NOT_FOUND, {"error": "session not found"}
                )
            return self.response(start_response, HTTPStatus.OK, run)
        if path == "/api/runs" and method == "GET":
            return self.response(start_response, HTTPStatus.OK, {"items": self.store.runs()})
        if path == "/api/events" and method == "GET":
            query = parse_qs(environ.get("QUERY_STRING", ""))
            return self.response(
                start_response,
                HTTPStatus.OK,
                {"items": self.store.events(query.get("run_id", [None])[0])},
            )
        if path == "/api/audit" and method == "GET":
            return self.response(start_response, HTTPStatus.OK, {"items": self.store.audit()})
        if path == "/api/models" and method == "GET":
            return self.response(
                start_response,
                HTTPStatus.OK,
                {
                    "live": {
                        "status": "UNAVAILABLE",
                        "reason": (
                            "No approved model trained and validated on the live-native schema."
                        ),
                        "schema": "live-rule-counter-v1",
                        "artifact": None,
                    },
                    "offline": {"status": "SEPARATE_PIPELINE"},
                },
            )
        if path == "/api/data-sources" and method == "GET":
            return self._project_data_response(start_response, self.project_data.sources)
        if path == "/api/historical-results" and method == "GET":
            return self._project_data_response(start_response, self.project_data.historical_results)
        if path == "/api/dataset-sources" and method == "GET":
            return self._project_data_response(start_response, self.project_data.dataset_sources)
        if path == "/api/telemetry-runs" and method == "GET":
            return self._project_data_response(start_response, self.project_data.telemetry_runs)
        if path == "/api/dataset-preview" and method == "GET":
            query = parse_qs(environ.get("QUERY_STRING", ""))
            source_id = query.get("source", [""])[0]
            file_id = query.get("file", [""])[0]
            try:
                limit = int(query.get("limit", ["8"])[0])
            except ValueError:
                return self.response(
                    start_response, HTTPStatus.BAD_REQUEST, {"error": "limit must be an integer"}
                )
            if source_id != "cse-cic-ids2018-stage5d" or not file_id:
                return self.response(
                    start_response,
                    HTTPStatus.BAD_REQUEST,
                    {"error": "select a supported prepared dataset source and file"},
                )
            try:
                preview = self.project_data.dataset_preview(file_id, limit)
            except FileNotFoundError as error:
                return self.response(start_response, HTTPStatus.NOT_FOUND, {"error": str(error)})
            except ValueError as error:
                return self.response(start_response, HTTPStatus.BAD_REQUEST, {"error": str(error)})
            except OSError as error:
                logging.getLogger(__name__).exception("prepared dataset read failed")
                return self.response(
                    start_response,
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    {"error": f"prepared dataset unavailable: {error}"},
                )
            return self.response(start_response, HTTPStatus.OK, preview)
        return self.response(start_response, HTTPStatus.NOT_FOUND, {"error": "not found"})

    def _v1_error(
        self,
        start_response: StartResponse,
        status: HTTPStatus,
        code: str,
        message: str,
        request_id: str | None = None,
    ) -> list[bytes]:
        return self.response(
            start_response,
            status,
            {"error": {"code": code, "message": message, "request_id": request_id}},
        )

    @staticmethod
    def _page(query: dict[str, list[str]]) -> tuple[int, int]:
        try:
            limit = int(query.get("limit", ["50"])[0])
            offset = int(query.get("offset", ["0"])[0])
        except ValueError as error:
            raise ValueError("limit and offset must be integers") from error
        if not 1 <= limit <= 200 or offset < 0:
            raise ValueError("limit must be 1..200 and offset must be nonnegative")
        return limit, offset

    @staticmethod
    def _page_body(items: list[Any], total: int, limit: int, offset: int) -> dict[str, Any]:
        return {
            "items": items,
            "page": {
                "limit": limit,
                "offset": offset,
                "total": total,
                "has_more": offset + len(items) < total,
            },
        }

    def _read_json_body(
        self, environ: WSGIEnvironment, maximum_bytes: int = 64 * 1024
    ) -> dict[str, Any]:
        try:
            length = int(environ.get("CONTENT_LENGTH") or "0")
        except ValueError as error:
            raise ValueError("invalid content length") from error
        if length < 0 or length > maximum_bytes:
            raise ValueError(f"request body must be between 0 and {maximum_bytes} bytes")
        if length:
            content_type = environ.get("CONTENT_TYPE", "").split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                raise ValueError("Content-Type must be application/json")
            try:
                value = json.loads(environ["wsgi.input"].read(length))
            except (json.JSONDecodeError, UnicodeDecodeError) as error:
                raise ValueError("request body must be valid JSON") from error
        else:
            value = {}
        if not isinstance(value, dict):
            raise ValueError("request body must be a JSON object")
        return value

    def _dispatch_v1(
        self,
        environ: WSGIEnvironment,
        start_response: StartResponse,
        method: str,
        path: str,
    ) -> list[bytes]:
        query = parse_qs(environ.get("QUERY_STRING", ""))
        try:
            limit, offset = self._page(query)
        except ValueError as error:
            return self._v1_error(
                start_response, HTTPStatus.BAD_REQUEST, "INVALID_PAGINATION", str(error)
            )

        if path == "/api/v1/status" and method == "GET":
            registry = self.models.list_models()
            offline = self.models.get_model(MODEL_ID) or {}
            live_state = self.live_scoring.poll_once()
            controller = {
                "controller": live_state["controller"],
                "controller_reason": live_state["controller_reason"],
                "controller_updated_at": live_state["controller_updated_at"],
                "datapaths": live_state["datapaths"],
            }
            return self.response(
                start_response,
                HTTPStatus.OK,
                {
                    "api_version": "v1",
                    "mode": "DEMO",
                    **controller,
                    "telemetry": live_state["telemetry"],
                    "live_detection": live_state["live_detection"],
                    "live_model_status": live_state["model_status"],
                    "live_readiness_reason": live_state["reason"],
                    "live_accepted_windows": live_state["accepted_windows_total"],
                    "live_network_enabled": False,
                    "mitigation_enabled": False,
                    "offline_inference": offline.get("status", "UNAVAILABLE"),
                    "model_registry_count": len(registry["models"]),
                },
            )

        if path == "/api/v1/live/status" and method == "GET":
            return self.response(start_response, HTTPStatus.OK, self.live_scoring.poll_once())

        if path == "/api/v1/live/detections" and method == "GET":
            items, total = self.live_scoring.scores(limit=limit, offset=offset)
            return self.response(
                start_response, HTTPStatus.OK, self._page_body(items, total, limit, offset)
            )

        if path == "/api/v1/live/ledger" and method == "GET":
            items, total = self.live_scoring.ledger(limit=limit, offset=offset)
            return self.response(
                start_response, HTTPStatus.OK, self._page_body(items, total, limit, offset)
            )

        if path == "/api/v1/sessions" and method == "GET":
            items = self.store.runs()
            return self.response(
                start_response,
                HTTPStatus.OK,
                self._page_body(items[offset : offset + limit], len(items), limit, offset),
            )
        if path == "/api/v1/sessions" and method == "POST":
            try:
                payload = self._read_json_body(environ, maximum_bytes=1024)
                if payload:
                    raise ValueError("demo session request accepts an empty object only")
            except ValueError as error:
                return self._v1_error(
                    start_response, HTTPStatus.BAD_REQUEST, "INVALID_REQUEST", str(error)
                )
            session = self.store.create_demo()
            return self.response(start_response, HTTPStatus.CREATED, session)

        if path == "/api/v1/detections" and method == "GET":
            items, total = self.store.predictions(limit, offset)
            return self.response(
                start_response,
                HTTPStatus.OK,
                self._page_body(items, total, limit, offset),
            )

        if path == "/api/v1/datasets" and method == "GET":
            catalog = self.project_data.sources()
            dataset = self.project_data.dataset_sources()
            return self.response(
                start_response,
                HTTPStatus.OK,
                {
                    "items": catalog["items"],
                    "prepared_dataset": dataset,
                    "page": {"limit": limit, "offset": offset, "total": len(catalog["items"])},
                },
            )
        dataset_match = re.fullmatch(r"/api/v1/datasets/([^/]+)/preview", path)
        if dataset_match and method == "GET":
            dataset_id = dataset_match.group(1)
            if dataset_id != "cse-cic-ids2018-stage5d":
                return self._v1_error(
                    start_response,
                    HTTPStatus.NOT_FOUND,
                    "DATASET_NOT_FOUND",
                    "dataset is not registered",
                )
            file_id = query.get("file", [""])[0]
            mix = query.get("mix", ["prefix"])[0] or "prefix"
            try:
                preview = self.project_data.dataset_preview(
                    file_id, int(query.get("limit", ["8"])[0]), mix=mix
                )
                return self.response(start_response, HTTPStatus.OK, preview)
            except FileNotFoundError as error:
                return self._v1_error(
                    start_response, HTTPStatus.NOT_FOUND, "DATASET_UNAVAILABLE", str(error)
                )
            except (ValueError, OSError) as error:
                return self._v1_error(
                    start_response, HTTPStatus.BAD_REQUEST, "INVALID_DATASET_REQUEST", str(error)
                )

        if path == "/api/v1/experiments" and method == "GET":
            records = self.project_data.historical_results()["records"]
            return self.response(
                start_response,
                HTTPStatus.OK,
                self._page_body(records[offset : offset + limit], len(records), limit, offset),
            )
        experiment_match = re.fullmatch(r"/api/v1/experiments/([^/]+)", path)
        if experiment_match and method == "GET":
            records = self.project_data.historical_results()["records"]
            experiment_id = experiment_match.group(1)
            matches = [
                record
                for record in records
                if str(record.get("experiment_id")) == experiment_id
                or str(record.get("source_id")) == experiment_id
            ]
            if not matches:
                return self._v1_error(
                    start_response,
                    HTTPStatus.NOT_FOUND,
                    "EXPERIMENT_NOT_FOUND",
                    "experiment result was not found",
                )
            return self.response(start_response, HTTPStatus.OK, {"items": matches})

        if path == "/api/v1/telemetry/audits" and method == "GET":
            audits = self.project_data.telemetry_runs()["runs"]
            return self.response(
                start_response,
                HTTPStatus.OK,
                self._page_body(audits[offset : offset + limit], len(audits), limit, offset),
            )

        if path == "/api/v1/models" and method == "GET":
            return self.response(start_response, HTTPStatus.OK, self.models.list_models())
        model_match = re.fullmatch(r"/api/v1/models/([^/]+)(/health)?", path)
        if model_match and method == "GET":
            model_id = model_match.group(1)
            model = (
                self.models.health(model_id)
                if model_match.group(2) == "/health"
                else self.models.get_model(model_id)
            )
            if model is None:
                return self._v1_error(
                    start_response,
                    HTTPStatus.NOT_FOUND,
                    "MODEL_NOT_FOUND",
                    "model is not registered",
                )
            return self.response(start_response, HTTPStatus.OK, model)

        if path == "/api/v1/inference/schema" and method == "GET":
            return self.response(start_response, HTTPStatus.OK, self.models.input_schema())
        if path == "/api/v1/inference/predict" and method == "POST":
            request_id: str | None = None
            try:
                payload = self._read_json_body(environ)
                allowed = {
                    "request_id",
                    "model_id",
                    "feature_schema",
                    "feature_order",
                    "features",
                    "source",
                }
                required = {"model_id", "feature_schema", "feature_order", "features"}
                if set(payload) - allowed or not required.issubset(payload):
                    raise ValueError("request fields do not match the inference schema")
                request_id = payload.get("request_id", str(uuid.uuid4()))
                if not isinstance(request_id, str) or len(request_id) > 64:
                    raise ValueError("request_id must be a string of at most 64 characters")
                if not isinstance(payload["feature_schema"], str):
                    raise ValueError("feature_schema must be a string")
                if not isinstance(payload["feature_order"], list) or any(
                    not isinstance(name, str) for name in payload["feature_order"]
                ):
                    raise ValueError("feature_order must be an ordered list of feature names")
                source = payload.get("source", {"source_type": "UNSPECIFIED"})
                if not isinstance(source, dict):
                    raise ValueError("source must be a provenance object")
                source_type = source.get("source_type", "UNSPECIFIED")
                if source_type not in {"UNSPECIFIED", "LABELED_DATA"}:
                    raise ValueError(
                        "this offline model accepts only labeled CICFlowMeter records "
                        "or unspecified input"
                    )
                if source_type == "UNSPECIFIED" and set(source) != {"source_type"}:
                    raise ValueError("unspecified provenance accepts source_type only")
                if source_type == "LABELED_DATA":
                    expected_source_fields = {
                        "source_type",
                        "dataset_id",
                        "file_id",
                        "row_number",
                    }
                    if set(source) != expected_source_fields:
                        raise ValueError("labeled-data provenance fields are invalid")
                    if source.get("dataset_id") != "cse-cic-ids2018-stage5d":
                        raise ValueError("labeled-data dataset is not a supported source")
                    row_number = source.get("row_number")
                    if (
                        isinstance(row_number, bool)
                        or not isinstance(row_number, int)
                        or row_number < 1
                    ):
                        raise ValueError("source row_number must be a positive integer")
                    actual = self.project_data.dataset_row(
                        str(source.get("file_id")), row_number
                    )
                    provided_features = self._finite_feature_map(payload["features"])
                    actual_features = self._finite_feature_map(actual["features"])
                    if provided_features.keys() != actual_features.keys() or any(
                        not math.isclose(
                            provided_features[name],
                            actual_features[name],
                            rel_tol=0.0,
                            abs_tol=0.0,
                        )
                        for name in actual_features
                    ):
                        raise ValueError(
                            "feature values do not match the cited prepared source row"
                        )
                    # Authoritative values come from the re-read prepared row.
                    payload = {**payload, "features": actual_features}
                    source = {
                        **source,
                        "artifact": actual["source_file"],
                        "sha256": actual["source_sha256"],
                        "ground_truth_label": actual["source_label"],
                    }
                result = self.models.predict(payload)
            except ModelUnavailableError as error:
                return self._v1_error(
                    start_response,
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "MODEL_UNAVAILABLE",
                    str(error),
                    request_id,
                )
            except FileNotFoundError as error:
                return self._v1_error(
                    start_response,
                    HTTPStatus.NOT_FOUND,
                    "SOURCE_UNAVAILABLE",
                    str(error),
                    request_id,
                )
            except (ValueError, OSError) as error:
                return self._v1_error(
                    start_response,
                    HTTPStatus.UNPROCESSABLE_ENTITY,
                    "INVALID_INFERENCE_INPUT",
                    str(error),
                    request_id,
                )
            result["prediction_timestamp"] = utc_now()
            result["request_id"] = request_id
            result["provenance"] = {
                "source_type": source.get("source_type", "UNSPECIFIED"),
                "source_artifact": source.get("artifact"),
                "source_sha256": source.get("sha256"),
                "source_row_number": source.get("row_number"),
                "ground_truth_label": source.get("ground_truth_label"),
            }
            saved = self.store.save_prediction(result, request_id=request_id, source=source)
            return self.response(start_response, HTTPStatus.OK, saved)

        if path == "/api/v1/audit" and method == "GET":
            items, total = self.store.combined_audit(limit, offset)
            return self.response(
                start_response,
                HTTPStatus.OK,
                self._page_body(items, total, limit, offset),
            )

        session_match = re.fullmatch(
            r"/api/v1/sessions/([0-9a-f-]{36})(/stop|/events|/audit|/export)?", path
        )
        if session_match:
            session_id, action = session_match.groups()
            if action == "/stop" and method == "POST":
                stopped_session = self.store.stop_run(session_id)
                if stopped_session is None:
                    return self._v1_error(
                        start_response,
                        HTTPStatus.NOT_FOUND,
                        "SESSION_NOT_FOUND",
                        "session was not found",
                    )
                return self.response(start_response, HTTPStatus.OK, stopped_session)
            if action == "/events" and method == "GET":
                if self.store.run(session_id) is None:
                    return self._v1_error(
                        start_response,
                        HTTPStatus.NOT_FOUND,
                        "SESSION_NOT_FOUND",
                        "session was not found",
                    )
                all_events = self.store.events(session_id)
                return self.response(
                    start_response,
                    HTTPStatus.OK,
                    self._page_body(
                        all_events[offset : offset + limit], len(all_events), limit, offset
                    ),
                )
            if action == "/audit" and method == "GET":
                if self.store.run(session_id) is None:
                    return self._v1_error(
                        start_response,
                        HTTPStatus.NOT_FOUND,
                        "SESSION_NOT_FOUND",
                        "session was not found",
                    )
                items = self.store.audit(session_id)
                for item in items:
                    item["source_type"] = "SYNTHETIC_FIXTURE"
                    with suppress(TypeError, json.JSONDecodeError):
                        item["payload"] = json.loads(item["payload"])
                return self.response(
                    start_response,
                    HTTPStatus.OK,
                    self._page_body(items[offset : offset + limit], len(items), limit, offset),
                )
            if action == "/export" and method == "GET":
                exported_session = self.store.run(session_id)
                if exported_session is None:
                    return self._v1_error(
                        start_response,
                        HTTPStatus.NOT_FOUND,
                        "SESSION_NOT_FOUND",
                        "session was not found",
                    )
                return self.response(
                    start_response,
                    HTTPStatus.OK,
                    {
                        "report_version": 1,
                        "mode": "DEMO",
                        "synthetic": True,
                        "source_type": "SYNTHETIC_FIXTURE",
                        "exported_at": utc_now(),
                        "session": exported_session,
                        "events": self.store.events(session_id),
                        "audit": self.store.audit(session_id),
                    },
                )
            if action is None and method == "GET":
                selected_session = self.store.run(session_id)
                if selected_session is None:
                    return self._v1_error(
                        start_response,
                        HTTPStatus.NOT_FOUND,
                        "SESSION_NOT_FOUND",
                        "session was not found",
                    )
                return self.response(
                    start_response,
                    HTTPStatus.OK,
                    {**selected_session, "events": self.store.events(session_id)},
                )
        mitigation_resp = self._dispatch_mitigation(
            environ, start_response, method, path, limit, offset
        )
        if mitigation_resp is not None:
            return mitigation_resp
        return self._v1_error(
            start_response,
            HTTPStatus.NOT_FOUND,
            "ROUTE_NOT_FOUND",
            "API v1 route was not found",
        )

    def _dispatch_mitigation(
        self,
        environ: WSGIEnvironment,
        start_response: StartResponse,
        method: str,
        path: str,
        limit: int,
        offset: int,
    ) -> list[bytes] | None:
        """Handle /api/v1/mitigation/* routes. Returns None if route not matched."""
        if path == "/api/v1/mitigation/policy" and method == "GET":
            return self.response(
                start_response,
                HTTPStatus.OK,
                {
                    "policy_id": "sentinel-default-v1",
                    "max_false_positive_rate": 0.10,
                    "min_confidence": 0.85,
                    "default_ttl_seconds": 300,
                    "rate_limiting": "UNSUPPORTED",
                    "protected_flows": [],
                    "scope": "flow-scoped exact match only",
                    "note": (
                        "Rate limiting is unsupported: no OVS meter installation. "
                        "All actions are bounded, reversible, and logged. "
                        "Live enforcement requires an active OpenFlow controller."
                    ),
                },
            )
        if path == "/api/v1/mitigation/actions" and method == "GET":
            items, total = self.store.mitigation_actions(limit, offset)
            return self.response(
                start_response, HTTPStatus.OK, self._page_body(items, total, limit, offset)
            )
        if path == "/api/v1/mitigation/actions" and method == "POST":
            try:
                payload = self._read_json_body(environ, maximum_bytes=4096)
                action_type = str(payload.get("action_type", "BLOCK_SOURCE_IP"))
                allowed_types = {
                    "BLOCK_SOURCE_IP", "BLOCK_DEST_PORT", "RATE_LIMIT_FLOW",
                    "ROLLBACK_ALL", "DROP_FLOW",
                }
                if action_type not in allowed_types:
                    raise ValueError(f"action_type must be one of {sorted(allowed_types)}")
                ttl = int(payload.get("ttl_seconds", 60))
                if not 1 <= ttl <= 3600:
                    raise ValueError("ttl_seconds must be between 1 and 3600")
                action = self.store.create_mitigation_action(
                    action_type,
                    target_flow=payload.get("target_flow"),
                    ttl_seconds=ttl,
                    reason=str(payload.get("reason", f"Manual {action_type}"))[:256],
                )
                return self.response(start_response, HTTPStatus.CREATED, action)
            except ValueError as error:
                return self._v1_error(
                    start_response,
                    HTTPStatus.BAD_REQUEST,
                    "INVALID_MITIGATION_REQUEST",
                    str(error),
                )
        return None

    @staticmethod
    def _finite_feature_map(features: object) -> dict[str, float]:
        """Coerce preview/request feature maps to comparable finite floats."""
        if not isinstance(features, dict):
            raise ValueError("features must be an object")
        converted: dict[str, float] = {}
        for name, raw_value in features.items():
            if not isinstance(name, str):
                raise ValueError("feature names must be strings")
            if isinstance(raw_value, bool) or not isinstance(raw_value, (int, float, str)):
                raise ValueError(f"feature {name!r} must be numeric")
            try:
                value = float(raw_value)
            except (TypeError, ValueError) as error:
                raise ValueError(f"feature {name!r} must be numeric") from error
            if not math.isfinite(value):
                raise ValueError(f"feature {name!r} must be finite")
            converted[name] = value
        return converted

    def _project_data_response(self, start_response: StartResponse, loader: Any) -> list[bytes]:
        try:
            return self.response(start_response, HTTPStatus.OK, loader())
        except (OSError, ValueError, json.JSONDecodeError) as error:
            logging.getLogger(__name__).exception("project artifact read failed")
            return self.response(
                start_response,
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": f"project artifact unavailable: {error}"},
            )


def main() -> None:
    host = os.getenv("SDN_DEMO_HOST", "127.0.0.1")
    if host not in {"127.0.0.1", "localhost"}:
        raise SystemExit("demo API only permits loopback bind addresses")
    port = int(os.getenv("SDN_DEMO_PORT", "18000"))

    # Optionally start a simulated controller heartbeat so live scoring activates
    # without requiring a real Ryu/Mininet/OVS stack.
    sim: ControllerSimulator | None = None
    if os.getenv("SDN_CONTROLLER_SIM", "1") not in {"0", "false", "off"}:
        from pathlib import Path as _Path
        sim_path = _Path(os.getenv("SDN_RYU_STATUS_FILE", "var/runtime/ryu-status.json"))
        if not sim_path.is_absolute():
            sim_path = _Path(__file__).resolve().parents[2] / sim_path
        sim = ControllerSimulator(sim_path)
        sim.start()
        print(f"Controller simulator started (epoch={sim.epoch_id[:8]}…)", flush=True)

    application = DemoApplication()
    application.live_scoring.start_background()
    try:
        with make_server(host, port, application) as server:
            print(f"DEMO API: http://{host}:{port}", flush=True)
            print(f"API v1:   http://{host}:{port}/api/v1/status", flush=True)
            server.serve_forever()
    finally:
        if not application.live_scoring.stop_background():
            logging.getLogger(__name__).error(
                "live telemetry poller did not stop within its shutdown bound"
            )
        if sim is not None:
            sim.stop()


if __name__ == "__main__":
    main()
