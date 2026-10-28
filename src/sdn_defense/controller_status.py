"""Atomic Ryu datapath status handoff for the local API.

This file communicates observed Ryu state; it does not open controller sockets
or infer connectivity from a listening port. A monotonic heartbeat makes stale
files detectable across processes on the same host.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import time
from collections.abc import Mapping, Sequence
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

STATUS_SCHEMA_VERSION = 1
_DATAPATH_ID = re.compile(r"^[0-9a-f]{16}$")


class ControllerStatusPublisher:
    """Publish actual active datapath state through atomic replacement."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()

    def publish(
        self,
        *,
        controller_instance_id: str,
        datapaths: Sequence[Mapping[str, object]],
        openflow_version: str = "1.3",
    ) -> None:
        if not controller_instance_id or not openflow_version:
            raise ValueError("controller instance and OpenFlow version are required")
        canonical: list[dict[str, str]] = []
        for item in datapaths:
            dpid, epoch = item.get("datapath_id"), item.get("epoch_id")
            if not isinstance(dpid, str) or not _DATAPATH_ID.fullmatch(dpid):
                raise ValueError("datapath ID must be 16 lowercase hexadecimal characters")
            if not isinstance(epoch, str) or not epoch:
                raise ValueError("active datapath epoch is required")
            canonical.append({"datapath_id": dpid, "epoch_id": epoch})
        payload = {
            "schema_version": STATUS_SCHEMA_VERSION,
            "controller_instance_id": controller_instance_id,
            "pid": os.getpid(),
            "updated_at": datetime.now(UTC).isoformat(),
            "updated_monotonic_ns": time.monotonic_ns(),
            "openflow_version": openflow_version,
            "datapaths": canonical,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, temporary_name = tempfile.mkstemp(
                prefix=f".{self.path.name}.", suffix=".tmp", dir=self.path.parent
            )
            os.fchmod(fd, 0o644)
            temporary = Path(temporary_name)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as stream:
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, self.path)
            finally:
                with suppress(OSError):
                    temporary.unlink(missing_ok=True)


class ControllerStatusReader:
    """Read the allowlisted local Ryu status artifact and classify freshness."""

    def __init__(self, path: Path, *, stale_after_seconds: float = 6.0) -> None:
        if stale_after_seconds <= 0:
            raise ValueError("stale_after_seconds must be positive")
        self.path = path
        self.stale_after_ns = int(stale_after_seconds * 1_000_000_000)

    def read(self, *, now_monotonic_ns: int | None = None) -> dict[str, Any]:
        unavailable: dict[str, Any] = {
            "controller": "NOT_MONITORED",
            "controller_reason": "No Ryu status artifact has been published.",
            "controller_instance_id": None,
            "datapaths": [],
            "controller_updated_at": None,
        }
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return unavailable
        except (OSError, json.JSONDecodeError) as error:
            return {
                **unavailable,
                "controller": "INVALID",
                "controller_reason": f"Ryu status artifact cannot be read: {type(error).__name__}.",
            }
        if not self._valid(payload):
            return {
                **unavailable,
                "controller": "INVALID",
                "controller_reason": "Ryu status artifact does not match schema version 1.",
            }
        now = time.monotonic_ns() if now_monotonic_ns is None else now_monotonic_ns
        age = now - payload["updated_monotonic_ns"]
        if age < 0 or age > self.stale_after_ns:
            return {
                **unavailable,
                "controller": "STALE",
                "controller_reason": "Ryu status heartbeat is stale; datapath state is unknown.",
                "controller_instance_id": payload["controller_instance_id"],
                "controller_updated_at": payload["updated_at"],
            }
        datapaths = payload["datapaths"]
        connected = bool(datapaths)
        return {
            "controller": "CONNECTED" if connected else "DISCONNECTED",
            "controller_reason": (
                "Ryu reports active OpenFlow datapaths."
                if connected
                else "Ryu is reporting, but no active OpenFlow datapaths are registered."
            ),
            "controller_instance_id": payload["controller_instance_id"],
            "controller_pid": payload["pid"],
            "controller_updated_at": payload["updated_at"],
            "controller_openflow_version": payload["openflow_version"],
            "datapaths": datapaths,
        }

    @staticmethod
    def _valid(payload: object) -> bool:
        if not isinstance(payload, dict):
            return False
        if (
            payload.get("schema_version") != STATUS_SCHEMA_VERSION
            or not isinstance(payload.get("controller_instance_id"), str)
            or not payload["controller_instance_id"]
            or isinstance(payload.get("pid"), bool)
            or not isinstance(payload.get("pid"), int)
            or payload.get("pid", 0) < 1
            or isinstance(payload.get("updated_monotonic_ns"), bool)
            or not isinstance(payload.get("updated_monotonic_ns"), int)
            or payload.get("updated_monotonic_ns", -1) < 0
            or not isinstance(payload.get("updated_at"), str)
            or not isinstance(payload.get("openflow_version"), str)
            or not isinstance(payload.get("datapaths"), list)
        ):
            return False
        datapaths = payload["datapaths"]
        if len({item.get("datapath_id") for item in datapaths if isinstance(item, dict)}) != len(
            datapaths
        ):
            return False
        return all(
            isinstance(item, dict)
            and isinstance(item.get("datapath_id"), str)
            and _DATAPATH_ID.fullmatch(item["datapath_id"]) is not None
            and isinstance(item.get("epoch_id"), str)
            and bool(item["epoch_id"])
            for item in payload["datapaths"]
        )
