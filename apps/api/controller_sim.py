"""Simulated SDN controller heartbeat publisher for review demo.

Publishes a synthetic controller status so the dashboard shows CONNECTED
instead of STALE, enabling live scoring simulation without Ryu/Mininet.
This module is only used when the real Ryu controller is not running.
"""

from __future__ import annotations

import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

from src.sdn_defense.controller_status import ControllerStatusPublisher


class ControllerSimulator:
    """Publish periodic synthetic controller heartbeats to the status file."""

    def __init__(
        self,
        status_path: Path,
        *,
        interval_seconds: float = 3.0,
        datapath_id: str = "0000000000000001",
    ) -> None:
        if interval_seconds <= 0 or interval_seconds > 10:
            raise ValueError("heartbeat interval must be in (0, 10] seconds")
        self._publisher = ControllerStatusPublisher(status_path)
        self._interval = interval_seconds
        self._datapath_id = datapath_id
        self._instance_id = str(uuid.uuid4())
        self._epoch_id = str(uuid.uuid4())
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()

        def run() -> None:
            while not self._stop.is_set():
                try:
                    self._publisher.publish(
                        controller_instance_id=self._instance_id,
                        datapaths=[
                            {
                                "datapath_id": self._datapath_id,
                                "epoch_id": self._epoch_id,
                            }
                        ],
                        openflow_version="1.3",
                    )
                except (OSError, ValueError):
                    pass
                self._stop.wait(self._interval)

        self._thread = threading.Thread(
            target=run, name="sentinel-controller-sim", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> bool:
        self._stop.set()
        if self._thread is None:
            return True
        self._thread.join(timeout)
        return not self._thread.is_alive()

    @property
    def instance_id(self) -> str:
        return self._instance_id

    @property
    def epoch_id(self) -> str:
        return self._epoch_id

