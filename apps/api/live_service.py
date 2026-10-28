"""Runtime polling, fail-closed scoring, and append-only live evidence ledger."""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.sdn_defense.controller_status import ControllerStatusReader
from src.sdn_defense.live_anomaly import (
    LiveEvidenceError,
    load_calibration,
    read_telemetry_windows,
    score_window,
)


class LiveScoringService:
    """Poll fresh, controller-owned telemetry files and score accepted windows once."""

    def __init__(
        self,
        root: Path,
        database: Path,
        controller_status: ControllerStatusReader,
        *,
        maximum_window_age_seconds: float = 15.0,
    ) -> None:
        self.root = root.resolve()
        self.database = database
        self.controller_status = controller_status
        self.maximum_window_age_seconds = maximum_window_age_seconds
        self.model_directory = self.root / "var/models/stage7-live-robust-v1"
        self._poll_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._background_error: str | None = None
        self._initialize()

    def start_background(self, interval_seconds: float = 2.0) -> None:
        """Start a bounded-interval daemon poller for the local API process."""

        if interval_seconds <= 0 or interval_seconds > 30:
            raise ValueError("poll interval must be in (0, 30] seconds")
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()

        def run() -> None:
            while not self._stop_event.is_set():
                try:
                    self.poll_once()
                    self._background_error = None
                except (OSError, ValueError, sqlite3.Error) as error:
                    self._background_error = type(error).__name__
                self._stop_event.wait(interval_seconds)

        self._thread = threading.Thread(target=run, name="sentinel-live-window-poller", daemon=True)
        self._thread.start()

    def stop_background(self, timeout_seconds: float = 5.0) -> bool:
        """Stop and join the poller within a finite shutdown bound."""

        self._stop_event.set()
        if self._thread is None:
            return True
        self._thread.join(timeout_seconds)
        return not self._thread.is_alive()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def _initialize(self) -> None:
        self.database.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS live_scores (
                    window_id TEXT PRIMARY KEY,
                    rule_identity_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    result TEXT NOT NULL,
                    sustained_state TEXT NOT NULL,
                    payload TEXT NOT NULL
                )"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS live_ledger (
                    event_id TEXT PRIMARY KEY,
                    window_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload TEXT NOT NULL
                )"""
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_live_scores_created ON live_scores(created_at DESC)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_live_ledger_created ON live_ledger(created_at DESC)"
            )

    def _insert_score(self, score: dict[str, Any]) -> bool:
        now = datetime.now(UTC).isoformat()
        with self._connect() as connection:
            if connection.execute(
                "SELECT 1 FROM live_scores WHERE window_id=?", (score["window_id"],)
            ).fetchone():
                return False
            previous = connection.execute(
                """SELECT result FROM live_scores WHERE rule_identity_id=?
                   ORDER BY created_at DESC LIMIT 2""",
                (score["rule_identity_id"],),
            ).fetchall()
            exceedances = sum(row["result"] == "UNUSUAL" for row in previous) + int(
                score["result"] == "UNUSUAL"
            )
            score["sustained_state"] = (
                "SUSTAINED_CHANGE"
                if len(previous) >= 2 and exceedances >= 2
                else "ISOLATED_DEVIATION"
                if score["result"] == "UNUSUAL"
                else "WITHIN_BASELINE"
            )
            score["created_at"] = now
            payload = json.dumps(score, sort_keys=True, allow_nan=False)
            connection.execute(
                """INSERT INTO live_scores(
                       window_id,rule_identity_id,created_at,result,sustained_state,payload
                   )
                   VALUES(?,?,?,?,?,?)""",
                (
                    score["window_id"],
                    score["rule_identity_id"],
                    now,
                    score["result"],
                    score["sustained_state"],
                    payload,
                ),
            )
            connection.execute(
                """INSERT INTO live_ledger(event_id,window_id,created_at,event_type,payload)
                   VALUES(?,?,?,?,?)""",
                (
                    str(uuid.uuid4()),
                    score["window_id"],
                    now,
                    "LIVE_WINDOW_SCORED",
                    payload,
                ),
            )
            if score["sustained_state"] == "SUSTAINED_CHANGE":
                connection.execute(
                    """INSERT INTO live_ledger(event_id,window_id,created_at,event_type,payload)
                       VALUES(?,?,?,?,?)""",
                    (
                        str(uuid.uuid4()),
                        score["window_id"],
                        now,
                        "SUSTAINED_CHANGE_FLAGGED",
                        json.dumps(
                            {
                                "window_id": score["window_id"],
                                "rule_identity_id": score["rule_identity_id"],
                                "score": score["score"],
                                "threshold": score["threshold"],
                                "mitigation_authorized": False,
                            },
                            sort_keys=True,
                        ),
                    ),
                )
        return True

    def poll_once(self) -> dict[str, Any]:
        """Score only fresh windows for currently active, observed datapath epochs."""

        with self._poll_lock:
            controller = self.controller_status.read()
            model: dict[str, Any] | None = None
            model_error: str | None = None
            try:
                model = load_calibration(self.model_directory)
            except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
                model_error = f"Live baseline unavailable: {error}"
            new_count = 0
            rejection_count = 0
            eligible_count = 0
            skipped_training_count = 0
            skipped_epoch_count = 0
            skipped_stale_count = 0
            if controller.get("controller") == "CONNECTED" and model is not None:
                active = {
                    (item.get("datapath_id"), item.get("epoch_id"))
                    for item in controller.get("datapaths", [])
                    if isinstance(item, dict)
                }
                training_run_ids = {item.get("run_id") for item in model.get("training_runs", [])}
                telemetry_root = (self.root / "experiments/stage7-telemetry").resolve()
                now = datetime.now(UTC)
                # The controller writes an append-only run-scoped stream while a
                # scenario is active. Final audited run views are also scanned;
                # persistent window IDs make the post-run scan idempotent.
                paths = sorted(
                    [
                        *telemetry_root.glob("*/live-stream/telemetry-*.jsonl"),
                        *telemetry_root.glob("*/telemetry-*.jsonl"),
                    ]
                )[-100:]
                for path in paths:
                    try:
                        if not path.is_file() or not path.resolve().is_relative_to(telemetry_root):
                            continue
                        if now.timestamp() - path.stat().st_mtime > self.maximum_window_age_seconds:
                            continue
                        windows, _audit = read_telemetry_windows(
                            path,
                            max_gap_seconds=float(model["maximum_gap_seconds"]),
                            allow_open_run=True,
                        )
                        for window in windows:
                            age = (now - datetime.fromisoformat(window.end_at)).total_seconds()
                            if window.run_id in training_run_ids:
                                skipped_training_count += 1
                                continue
                            if age < -1.0 or age > self.maximum_window_age_seconds:
                                skipped_stale_count += 1
                                continue
                            if (window.datapath_id, window.datapath_epoch_id) not in active:
                                skipped_epoch_count += 1
                                continue
                            eligible_count += 1
                            try:
                                score = score_window(model, window)
                            except LiveEvidenceError:
                                rejection_count += 1
                                continue
                            new_count += int(self._insert_score(score))
                    except (OSError, ValueError, json.JSONDecodeError):
                        rejection_count += 1
            scores, total = self.scores(limit=20, offset=0)
            readiness_reason: str | None
            if controller.get("controller") != "CONNECTED":
                readiness_reason = str(controller.get("controller_reason"))
            elif model is None:
                readiness_reason = model_error
            elif not scores:
                readiness_reason = (
                    "Waiting for a fresh, complete feature window from an active datapath epoch."
                )
            else:
                readiness_reason = (
                    "Provisional anomaly scoring is active; results are not attack classifications."
                )
            return {
                "source_type": "LIVE",
                "controller": controller.get("controller"),
                "controller_reason": controller.get("controller_reason"),
                "controller_updated_at": controller.get("controller_updated_at"),
                "datapaths": controller.get("datapaths", []),
                "model_status": model.get("status") if model else "UNAVAILABLE",
                "model_id": model.get("model_id") if model else None,
                "model_version": model.get("version") if model else None,
                "feature_schema_id": model.get("feature_schema_id") if model else None,
                "threshold": model.get("threshold") if model else None,
                "scoring_enabled": (
                    controller.get("controller") == "CONNECTED" and model is not None
                ),
                "live_detection": (
                    "PROVISIONAL_ANOMALY_SCORING"
                    if controller.get("controller") == "CONNECTED" and model
                    else "UNAVAILABLE"
                ),
                "telemetry": (
                    "FRESH_WINDOWS"
                    if eligible_count
                    else "STALE_OR_UNAVAILABLE"
                    if controller.get("controller") != "CONNECTED"
                    else "WAITING_OR_UNAVAILABLE"
                ),
                "eligible_windows_this_poll": eligible_count,
                "accepted_windows_total": total,
                "accepted_windows_this_poll": new_count,
                "rejected_sources_this_poll": rejection_count,
                "skipped_training_windows_this_poll": skipped_training_count,
                "skipped_inactive_epoch_windows_this_poll": skipped_epoch_count,
                "skipped_stale_windows_this_poll": skipped_stale_count,
                "mitigation": "DISABLED",
                "reason": readiness_reason,
                "poller_error": self._background_error,
                "limitations": [
                    "Anomaly score is not an attack label or calibrated probability.",
                    "The baseline was calibrated from benign runs only.",
                    "Live mitigation is disabled.",
                ],
            }

    def scores(self, *, limit: int = 50, offset: int = 0) -> tuple[list[dict[str, Any]], int]:
        with self._connect() as connection:
            total = int(connection.execute("SELECT COUNT(*) FROM live_scores").fetchone()[0])
            rows = connection.execute(
                "SELECT payload FROM live_scores ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [json.loads(row["payload"]) for row in rows], total

    def ledger(self, *, limit: int = 50, offset: int = 0) -> tuple[list[dict[str, Any]], int]:
        with self._connect() as connection:
            total = int(connection.execute("SELECT COUNT(*) FROM live_ledger").fetchone()[0])
            rows = connection.execute(
                """SELECT event_id,window_id,created_at,event_type,payload FROM live_ledger
                   ORDER BY created_at DESC LIMIT ? OFFSET ?""",
                (limit, offset),
            ).fetchall()
        return [
            {
                "event_id": row["event_id"],
                "window_id": row["window_id"],
                "created_at": row["created_at"],
                "event_type": row["event_type"],
                "payload": json.loads(row["payload"]),
            }
            for row in rows
        ], total
