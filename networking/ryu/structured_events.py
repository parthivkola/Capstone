"""Structured event records for the Stage 2 control-plane adapter."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any


class MonotonicUtcClock:
    """UTC timestamps derived from one wall-clock anchor and monotonic elapsed time.

    Wall time is useful for operators but can step backward after clock sync.
    The collector therefore anchors UTC once and advances from ``monotonic_ns``.
    A lock serializes concurrent Ryu green/native-thread callbacks. If multiple
    calls land within one datetime microsecond, the emitted values advance by a
    microsecond so append-time event order remains explicit.
    """

    def __init__(
        self,
        *,
        wall_clock: Callable[[], datetime] | None = None,
        monotonic_clock_ns: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        wall = (wall_clock or (lambda: datetime.now(UTC)))()
        if wall.tzinfo is None:
            raise ValueError("wall clock must return a timezone-aware datetime")
        self._wall_anchor = wall.astimezone(UTC)
        self._monotonic_anchor_ns = monotonic_clock_ns()
        self._monotonic_clock_ns = monotonic_clock_ns
        self._last: datetime | None = None
        self._lock = threading.Lock()

    def now(self) -> datetime:
        """Return monotonic-in-process UTC suitable for event record ordering."""

        with self._lock:
            elapsed_ns = self._monotonic_clock_ns() - self._monotonic_anchor_ns
            if elapsed_ns < 0:
                raise RuntimeError("monotonic clock moved backwards")
            candidate = self._wall_anchor + timedelta(microseconds=elapsed_ns // 1_000)
            if self._last is not None and candidate <= self._last:
                candidate = self._last + timedelta(microseconds=1)
            self._last = candidate
            return candidate


def datapath_id_text(datapath_id: int | None) -> str | None:
    """Format a discovered datapath ID without inventing one during early disconnects."""

    return None if datapath_id is None else f"{datapath_id:016x}"


def flow_statistics_log_details(observation: dict[str, Any]) -> dict[str, Any]:
    """Return flow details without fields already supplied by the event envelope."""

    return {
        key: value
        for key, value in observation.items()
        if key not in {"event_type", "datapath_id"}
    }


def run_start_timestamp(metadata: Mapping[str, object], observed_at: str) -> str:
    """Return the append-time timestamp for a run boundary.

    ``metadata.start_at`` is scenario context supplied by the runner and may be
    older than controller startup (for example after delayed attachment). It
    must never replace the timestamp of a record appended now: doing so makes
    the JSONL event stream move backwards. The declared time remains available
    in the metadata object itself.
    """

    del metadata
    return observed_at


def stage2_event(
    event_type: str, datapath_id: int | None = None, **details: Any
) -> dict[str, Any]:
    """Build a JSON-serialisable controller event with a UTC timestamp."""

    event: dict[str, Any] = {
        "timestamp": datetime.now(UTC).isoformat(),
        "event_type": event_type,
    }
    if datapath_id is not None:
        event["datapath_id"] = datapath_id_text(datapath_id)
    event.update(details)
    return event
