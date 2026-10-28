# ADR 015: Monotonic UTC telemetry events and fail-closed lab preflight

- **Status:** Accepted
- **Date:** 2026-10-28

## Context

The append-only Ryu telemetry stream is audited in event order. Wall-clock timestamps can move
backward after system clock synchronization, and a controller may attach after a scenario's declared
start time. Either can make a newly appended event appear earlier than a prior event. Existing
telemetry with invalid order or legacy provenance must remain rejected. The reviewed host also has
an active shared OVS service, interfaces associated with Docker/VM networking, and denied access to
the OVS database socket.

## Decision

Ryu telemetry event timestamps use a process-local UTC anchor advanced by monotonic elapsed time.
The clock serializes calls and guarantees increasing microsecond timestamps. Scenario `start_at` stays
inside run metadata and never replaces the timestamp of a later envelope. The read-only
`scripts/preflight_stage7_lab.py` checks tools, privileges, OVS inventory, bridges/ports, host
interfaces, and loopback controller port 6653. It blocks when OVS scope is unavailable, existing
bridges are present, prerequisites fail, or explicit namespace-isolation acknowledgment is missing.

## Alternatives considered

- Sort or rewrite historical records: rejected because it would change evidence and conceal event
  ordering failures.
- Ignore timestamps in the audit: rejected because chronology and maximum-gap validation depend on
  trustworthy timing.
- Use only wall time: rejected because it is not guaranteed monotonic.
- Automatically stop OVS or create a private bridge: rejected because that mutates shared host
  networking and cannot safely establish ownership here.

## Consequences

New telemetry records have monotonic event order while retaining UTC readability; monotonic elapsed
nanoseconds remain the source for durations. Historical files are unchanged and continue to fail
where their evidence is invalid. Live collection remains blocked until an operator can inspect OVS
and establish an isolated topology. The preflight itself is read-only and does not grant permission
to start a lab.

## Evidence

Unit tests cover clock rollback behavior, same-microsecond callback ordering, and preflight success and
failure conditions through mocked command execution. On the current host, preflight reports UID 1000
and `ovs-vsctl show` fails with `database connection failed (Permission denied)`; no lab was started.
