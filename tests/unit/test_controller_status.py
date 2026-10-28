"""Ryu status artifact validation and freshness tests."""

from __future__ import annotations

import io
import json
import time
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit
from wsgiref.types import StartResponse

import pytest

from apps.api.demo_app import DemoApplication, DemoStore
from src.sdn_defense.controller_status import ControllerStatusPublisher, ControllerStatusReader


def test_missing_status_is_not_monitored_not_disconnected(tmp_path: Path) -> None:
    state = ControllerStatusReader(tmp_path / "missing.json").read()
    assert state["controller"] == "NOT_MONITORED"
    assert state["datapaths"] == []


def test_reader_reports_actual_datapaths_and_stale_heartbeat(tmp_path: Path) -> None:
    path = tmp_path / "runtime" / "ryu.json"
    ControllerStatusPublisher(path).publish(
        controller_instance_id="controller-abc",
        datapaths=[{"datapath_id": "0000000000000001", "epoch_id": "epoch-1"}],
    )
    reader = ControllerStatusReader(path)
    fresh = reader.read()
    assert fresh["controller"] == "CONNECTED"
    assert fresh["datapaths"] == [{"datapath_id": "0000000000000001", "epoch_id": "epoch-1"}]
    stale = reader.read(now_monotonic_ns=time.monotonic_ns() + 7_000_000_000)
    assert stale["controller"] == "STALE"
    assert stale["datapaths"] == []


def test_reader_distinguishes_reporting_controller_with_no_datapaths(tmp_path: Path) -> None:
    path = tmp_path / "ryu.json"
    ControllerStatusPublisher(path).publish(controller_instance_id="controller-abc", datapaths=[])
    assert ControllerStatusReader(path).read()["controller"] == "DISCONNECTED"


def test_invalid_status_schema_and_duplicate_dpids_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "ryu.json"
    payload = {
        "schema_version": 1,
        "controller_instance_id": "controller-abc",
        "pid": 123,
        "updated_at": "2026-10-28T00:00:00+00:00",
        "updated_monotonic_ns": time.monotonic_ns(),
        "openflow_version": "1.3",
        "datapaths": [
            {"datapath_id": "0000000000000001", "epoch_id": "epoch-1"},
            {"datapath_id": "0000000000000001", "epoch_id": "epoch-2"},
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert ControllerStatusReader(path).read()["controller"] == "INVALID"
    path.write_text("not json", encoding="utf-8")
    assert ControllerStatusReader(path).read()["controller"] == "INVALID"


def test_api_status_includes_reader_state_and_keeps_live_detection_gated(tmp_path: Path) -> None:
    status_path = tmp_path / "runtime" / "ryu.json"
    ControllerStatusPublisher(status_path).publish(
        controller_instance_id="controller-abc",
        datapaths=[{"datapath_id": "0000000000000001", "epoch_id": "epoch-1"}],
    )
    app = DemoApplication(
        DemoStore(tmp_path / "demo.sqlite3"),
        controller_status=ControllerStatusReader(status_path),
    )
    captured: dict[str, str] = {}

    def start_response(status: str, _headers: list[tuple[str, str]]) -> None:
        captured["status"] = status

    parsed = urlsplit("/api/v1/status")
    body = b"".join(
        app(
            {
                "REQUEST_METHOD": "GET",
                "PATH_INFO": parsed.path,
                "QUERY_STRING": "",
                "CONTENT_LENGTH": "0",
                "wsgi.input": io.BytesIO(b""),
            },
            cast(StartResponse, start_response),
        )
    )
    assert captured["status"].startswith("200")
    state = json.loads(body)
    assert state["controller"] == "CONNECTED"
    assert state["live_detection"] == "PROVISIONAL_ANOMALY_SCORING"
    assert state["telemetry"] in {"WAITING_OR_UNAVAILABLE", "STALE_OR_UNAVAILABLE"}
    assert state["mitigation_enabled"] is False


def test_publisher_rejects_untrusted_datapath_identity(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="16 lowercase hexadecimal"):
        ControllerStatusPublisher(tmp_path / "status.json").publish(
            controller_instance_id="controller",
            datapaths=[{"datapath_id": "s1", "epoch_id": "epoch"}],
        )
