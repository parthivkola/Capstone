"""Timestamp contract tests for the Ryu event recorder clock."""

from datetime import UTC, datetime

from networking.ryu.structured_events import MonotonicUtcClock


def test_clock_uses_one_utc_anchor_and_monotonic_elapsed_time() -> None:
    wall_reads = 0
    monotonic_values = iter((10_000, 1_000_010_000, 2_000_010_000))

    def wall_clock() -> datetime:
        nonlocal wall_reads
        wall_reads += 1
        # If consulted again, system wall time would have stepped backwards.
        return datetime(2026, 10, 28, 12 if wall_reads == 1 else 11, tzinfo=UTC)

    clock = MonotonicUtcClock(
        wall_clock=wall_clock,
        monotonic_clock_ns=lambda: next(monotonic_values),
    )

    first = clock.now()
    second = clock.now()

    assert second > first
    assert (second - first).total_seconds() == 1.0
    assert wall_reads == 1


def test_clock_keeps_timestamps_strict_when_events_share_a_microsecond() -> None:
    values = iter((100, 101, 101))
    clock = MonotonicUtcClock(
        wall_clock=lambda: datetime(2026, 10, 28, tzinfo=UTC),
        monotonic_clock_ns=lambda: next(values),
    )
    first = clock.now()
    second = clock.now()
    assert second > first
