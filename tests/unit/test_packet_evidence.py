"""Pure tests for opt-in bounded packet evidence; no Ryu/OVS is required."""

import pytest

from networking.ryu.packet_evidence import PacketEvidenceBudget, PacketEvidencePolicy


def test_packet_evidence_policy_is_fixed_to_local_port_scan_scope() -> None:
    policy = PacketEvidencePolicy()

    assert policy.ingress_port == 2
    assert policy.egress_port == 3
    assert policy.source_ip == "10.0.0.2"
    assert policy.destination_ip == "10.0.0.3"
    assert policy.destination_ports == (22, 53, 67, 80, 443, 8080, 18080, 5353)
    assert not hasattr(policy, "tcp_flags_value")
    assert not hasattr(policy, "tcp_flags_mask")
    assert policy.controller_copy_max_bytes == 54
    assert policy.flow_hard_timeout_seconds <= 30


def test_packet_evidence_policy_rejects_unbounded_or_invalid_configuration() -> None:
    with pytest.raises(ValueError, match="valid TCP ports"):
        PacketEvidencePolicy(destination_ports=(22, 70000))
    with pytest.raises(ValueError, match="header prefix"):
        PacketEvidencePolicy(controller_copy_max_bytes=4096)
    with pytest.raises(ValueError, match="rate"):
        PacketEvidencePolicy(max_observations_per_second=0)
    with pytest.raises(ValueError, match="expire"):
        PacketEvidencePolicy(flow_hard_timeout_seconds=120)


def test_budget_accepts_first_events_within_rolling_rate_and_run_caps() -> None:
    policy = PacketEvidencePolicy(
        max_observations_per_second=2,
        max_observations_per_run=3,
    )
    budget = PacketEvidenceBudget(policy)
    budget.begin_run("run-1")

    assert budget.offer("run-1", 100)
    assert budget.offer("run-1", 200)
    assert not budget.offer("run-1", 300)  # third in the same rolling second
    assert budget.offer("run-1", 1_000_000_100)  # first event has aged out
    assert not budget.offer("run-1", 1_000_000_200)  # run cap reached

    summary = budget.finish_run("run-1", ended_at="2026-10-08T00:00:02Z")
    assert summary["packetins_offered"] == 5
    assert summary["observations_accepted"] == 3
    assert summary["observations_dropped"] == 2
    assert summary["dropped_rate_limit"] == 1
    assert summary["dropped_run_limit"] == 1
    assert summary["memory_queue_capacity"] == 0


def test_budget_does_not_assign_unscoped_events_to_a_run() -> None:
    budget = PacketEvidenceBudget(PacketEvidencePolicy())
    assert not budget.offer(None, 100)
    budget.begin_run("run-1")
    assert budget.offer("run-1", 200)
    with pytest.raises(ValueError, match="does not match"):
        budget.offer("run-2", 300)
    with pytest.raises(ValueError, match="backwards"):
        budget.offer("run-1", 100)


def test_budget_requires_explicit_run_boundaries() -> None:
    budget = PacketEvidenceBudget(PacketEvidencePolicy())
    budget.begin_run("run-1")
    with pytest.raises(RuntimeError, match="finish the active"):
        budget.begin_run("run-2")
    with pytest.raises(ValueError, match="not active"):
        budget.finish_run("run-2", ended_at="2026-10-08T00:00:00Z")
