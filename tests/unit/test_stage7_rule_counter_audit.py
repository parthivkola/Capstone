"""Synthetic JSONL tests for rule-counter lineage/cadence tooling and runner helpers."""

import ast
import importlib.util
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from scripts.run_stage7_rule_counter_validation import (
    _run_worker as run_benign_validation,
)
from scripts.run_stage7_rule_counter_validation import (
    _verify_cleanup,
    build_controller_environment,
    build_ryu_command,
    create_fresh_output_directory,
)
from src.sdn_defense.flow_records import extract_flow_record
from src.sdn_defense.telemetry_audit import audit_telemetry_jsonl, render_audit_report

RUN_ID = "synthetic-run-001"
EPOCH = "synthetic-controller:0000000000000001:1"
DPID = "0000000000000001"
BASE = datetime(2026, 10, 21, tzinfo=UTC)


def _record(second: int, packets: int, *, timestamp: datetime | None = None) -> dict[str, object]:
    return extract_flow_record(
        {
            "event_type": "flow_statistics",
            "timestamp": (timestamp or BASE + timedelta(seconds=second)).isoformat(),
            "datapath_id": DPID,
            "table_id": 0,
            "priority": 10,
            "cookie": "0x10",
            "packet_count": packets,
            "byte_count": packets * 100,
            "match": "OFPMatch(oxm_fields={'eth_type': 2048, 'ipv4_src': '10.0.0.1'})",
        }
    ).to_dict()


def _valid_records(*, include_packetin: bool = True) -> list[dict[str, object]]:
    records: list[dict[str, object]] = [
        {
            "record_type": "recorder_metadata",
            "schema_version": 2,
            "recorded_at": BASE.isoformat(),
            "source_version": "synthetic",
        },
        {
            "record_type": "connection_boundary",
            "schema_version": 2,
            "timestamp": BASE.isoformat(),
            "datapath_id": DPID,
            "datapath_epoch_id": EPOCH,
            "epoch_sequence": 1,
            "controller_instance_id": "synthetic-controller",
            "state": "connected",
            "lifecycle_source": "synthetic_fixture_only",
            "run_id": RUN_ID,
        },
    ]
    for index, packets in enumerate((10, 15), 1):
        collection_id = f"{EPOCH}:{DPID}:{index:08x}"
        start_ns = index * 1_000_000_000
        end_ns = start_ns + 100_000_000
        start_at = BASE + timedelta(seconds=index)
        end_at = start_at + timedelta(milliseconds=100)
        records.extend(
            [
                {
                    "record_type": "flow_collection",
                    "schema_version": 2,
                    "timestamp": start_at.isoformat(),
                    "collection_id": collection_id,
                    "datapath_id": DPID,
                    "datapath_epoch_id": EPOCH,
                    "xid": index,
                    "state": "requested",
                    "run_id": RUN_ID,
                    "started_at": start_at.isoformat(),
                    "started_monotonic_ns": start_ns,
                },
                {
                    "record_type": "flow_collection",
                    "schema_version": 2,
                    "timestamp": end_at.isoformat(),
                    "collection_id": collection_id,
                    "datapath_id": DPID,
                    "datapath_epoch_id": EPOCH,
                    "xid": index,
                    "complete": True,
                    "terminal_state": "COMPLETE",
                    "part_count": 1,
                    "record_count": 1,
                    "run_id": RUN_ID,
                    "started_at": start_at.isoformat(),
                    "completed_at": end_at.isoformat(),
                    "started_monotonic_ns": start_ns,
                    "completed_monotonic_ns": end_ns,
                    "elapsed_seconds": 0.1,
                },
                {
                    "record_type": "flow_snapshot",
                    "schema_version": 2,
                    "timestamp": end_at.isoformat(),
                    "run_id": RUN_ID,
                    "collection_id": collection_id,
                    "datapath_epoch_id": EPOCH,
                    "collector_monotonic_ns": end_ns,
                    "flow_record": _record(index, packets, timestamp=end_at),
                },
            ]
        )
    if include_packetin:
        records.append(
            {
                "record_type": "telemetry_observation",
                "schema_version": 1,
                "observation": {
                    "schema_version": 1,
                    "observation_id": "synthetic-packetin",
                    "observation_type": "TCP_PACKET_IN",
                    "observed_at": (BASE + timedelta(seconds=3)).isoformat(),
                    "source": "synthetic_fixture_only",
                    "run_id": RUN_ID,
                    "scope": None,
                    "payload": {"dst_port": 80},
                    "provenance_version": "synthetic-v1",
                    "collector_monotonic_ns": 3_000_000_000,
                },
            }
        )
    return records


def _write_records(path: Path, records: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(item, sort_keys=True) + "\n" for item in records), encoding="utf-8"
    )


def _append_incomplete(rows: list[dict[str, object]]) -> None:
    rows.append(
        {
            "record_type": "incomplete_collection",
            "schema_version": 2,
            "timestamp": (BASE + timedelta(seconds=4)).isoformat(),
            "collection_id": f"{EPOCH}:{DPID}:00000001",
            "datapath_id": DPID,
            "datapath_epoch_id": EPOCH,
            "xid": 1,
            "run_id": RUN_ID,
            "complete": False,
            "terminal_state": "TIMED_OUT",
            "reason": "synthetic fixture only",
        }
    )


def _insert_duplicate_completion(rows: list[dict[str, object]]) -> None:
    rows.insert(4, dict(rows[3]))


def _insert_disconnect(rows: list[dict[str, object]]) -> None:
    rows.insert(
        5,
        {
            "record_type": "connection_boundary",
            "schema_version": 2,
            "timestamp": (BASE + timedelta(seconds=1, milliseconds=500)).isoformat(),
            "datapath_id": DPID,
            "datapath_epoch_id": EPOCH,
            "epoch_sequence": 1,
            "controller_instance_id": "synthetic-controller",
            "state": "disconnected",
            "lifecycle_source": "synthetic_fixture_only",
            "run_id": RUN_ID,
        },
    )


def _insert_run_end_between_snapshots(rows: list[dict[str, object]]) -> None:
    rows.insert(
        2,
        {
            "record_type": "run_boundary",
            "schema_version": 1,
            "timestamp": BASE.isoformat(),
            "run_id": RUN_ID,
            "state": "started",
        },
    )
    rows.insert(
        6,
        {
            "record_type": "run_boundary",
            "schema_version": 1,
            "timestamp": (BASE + timedelta(seconds=1, milliseconds=500)).isoformat(),
            "run_id": RUN_ID,
            "state": "ended",
        },
    )


def _mix_collection_run_id(rows: list[dict[str, object]]) -> None:
    for index in (5, 6, 7):
        rows[index]["run_id"] = "synthetic-run-002"


def _contradict_completion_timestamp(rows: list[dict[str, object]]) -> None:
    rows[3]["completed_at"] = (BASE + timedelta(seconds=3)).isoformat()


def _contradict_snapshot_timestamp(rows: list[dict[str, object]]) -> None:
    rows[4]["timestamp"] = (BASE + timedelta(seconds=1, milliseconds=200)).isoformat()


def test_audit_accepts_schema2_pairs_and_excludes_packetin_from_feature_evidence(
    tmp_path: Path,
) -> None:
    path = tmp_path / "synthetic.jsonl"
    _write_records(path, _valid_records())
    summary = audit_telemetry_jsonl(path)
    assert summary["status"] == "AUDIT_COMPLETE"
    assert summary["counts"]["requests"] == 2
    assert summary["counts"]["complete_collections"] == 2
    assert summary["counts"]["collections_with_valid_complete_lineage"] == 2
    assert summary["counts"]["flow_snapshot_records"] == 2
    assert summary["counts"]["lineage_linked_flow_snapshot_records"] == 2
    assert summary["counts"]["source_verified_pairs"] == 1
    assert summary["cadence"]["source_verified_snapshot_gap_samples"] == 1
    assert summary["cadence"]["source_verified_snapshot_gaps_seconds"] == [1.0]
    assert summary["cadence"]["request_gaps_seconds"] == [1.0]
    assert summary["cadence"]["completion_gaps_seconds"] == [1.0]
    assert summary["cadence"]["collection_durations_seconds"] == [0.1, 0.1]
    assert summary["counts"]["packetin_observations_excluded_from_feature_evidence"] == 1
    assert summary["feature_vectors_generated"] is False
    assert "not selected" in render_audit_report(summary)
    assert summary == audit_telemetry_jsonl(path)


@pytest.mark.parametrize(
    ("mutate", "issue_prefix"),
    [
        (lambda rows: rows[2].update(started_monotonic_ns=None), "collection_lineage_mismatch"),
        (_append_incomplete, "contradictory_or_duplicate_terminal"),
        (_insert_duplicate_completion, "contradictory_or_duplicate_terminal"),
        (_insert_disconnect, "source_pair_rejected:"),
        (
            _insert_run_end_between_snapshots,
            "source_pair_rejected:RUN_BOUNDARY_EVENT_BETWEEN_SNAPSHOTS",
        ),
        (_mix_collection_run_id, "missing_or_mixed_run_ids"),
        (lambda rows: rows[4].update(datapath_epoch_id="other-epoch"), "snapshot_lineage_mismatch"),
        (_contradict_completion_timestamp, "collection_lineage_mismatch"),
        (_contradict_snapshot_timestamp, "snapshot_lineage_mismatch"),
    ],
)
def test_audit_rejects_missing_contradictory_or_cross_epoch_lineage(
    tmp_path: Path, mutate: object, issue_prefix: str
) -> None:
    rows = _valid_records(include_packetin=False)
    mutate(rows)  # type: ignore[operator]
    path = tmp_path / "invalid.jsonl"
    _write_records(path, rows)
    summary = audit_telemetry_jsonl(path)
    assert summary["status"] == "AUDIT_INCOMPLETE"
    assert any(str(issue).startswith(issue_prefix) for issue in summary["issues"])


def test_audit_reports_missing_monotonic_timing_without_fabricating_gaps(tmp_path: Path) -> None:
    rows = _valid_records(include_packetin=False)
    rows[2].pop("started_monotonic_ns")
    rows[3].pop("started_monotonic_ns")
    rows[3].pop("completed_monotonic_ns")
    rows[5].pop("started_monotonic_ns")
    rows[6].pop("started_monotonic_ns")
    rows[6].pop("completed_monotonic_ns")
    path = tmp_path / "missing-times.jsonl"
    _write_records(path, rows)
    summary = audit_telemetry_jsonl(path)
    assert summary["status"] == "AUDIT_INCOMPLETE"
    assert summary["cadence"]["missing_timing_collections"] == 2
    assert summary["cadence"]["collection_durations_seconds"] == []
    assert summary["cadence"]["incomplete_or_invalid_collections"] == 2
    assert summary["cadence"]["max_gap_policy_seconds"] is None


def test_empty_complete_collection_is_counted_but_not_a_measured_rule_snapshot(
    tmp_path: Path,
) -> None:
    rows = _valid_records(include_packetin=False)
    collection_id = f"{EPOCH}:{DPID}:00000003"
    start_at = BASE + timedelta(seconds=3)
    end_at = start_at + timedelta(milliseconds=100)
    empty_events: list[dict[str, object]] = [
        {
            "record_type": "flow_collection",
            "schema_version": 2,
            "timestamp": start_at.isoformat(),
            "collection_id": collection_id,
            "datapath_id": DPID,
            "datapath_epoch_id": EPOCH,
            "xid": 3,
            "state": "requested",
            "run_id": RUN_ID,
            "started_at": start_at.isoformat(),
            "started_monotonic_ns": 3_000_000_000,
        },
        {
            "record_type": "flow_collection",
            "schema_version": 2,
            "timestamp": end_at.isoformat(),
            "collection_id": collection_id,
            "datapath_id": DPID,
            "datapath_epoch_id": EPOCH,
            "xid": 3,
            "complete": True,
            "terminal_state": "COMPLETE",
            "part_count": 1,
            "record_count": 0,
            "run_id": RUN_ID,
            "started_at": start_at.isoformat(),
            "completed_at": end_at.isoformat(),
            "started_monotonic_ns": 3_000_000_000,
            "completed_monotonic_ns": 3_100_000_000,
            "elapsed_seconds": 0.1,
        },
    ]
    rows.extend(empty_events)
    path = tmp_path / "empty.jsonl"
    _write_records(path, rows)
    summary = audit_telemetry_jsonl(path)
    assert summary["status"] == "AUDIT_COMPLETE"
    assert summary["cadence"]["empty_complete_collections"] == 1
    assert summary["counts"]["snapshots"] == 2
    assert summary["counts"]["collections_with_valid_complete_lineage"] == 3
    assert summary["counts"]["lineage_linked_flow_snapshot_records"] == 2


def test_schema1_records_fail_the_source_verified_feature_gate(tmp_path: Path) -> None:
    rows = _valid_records(include_packetin=False)
    snapshot = rows[4]
    snapshot["schema_version"] = 1
    snapshot.pop("collection_id")
    snapshot.pop("datapath_epoch_id")
    path = tmp_path / "historical.jsonl"
    _write_records(path, rows)
    summary = audit_telemetry_jsonl(path)
    assert summary["status"] == "AUDIT_INCOMPLETE"
    assert any(str(issue).startswith("legacy_flow_snapshot_schema") for issue in summary["issues"])


def test_unknown_schema_and_malformed_records_are_rejected(tmp_path: Path) -> None:
    for filename, rows in (
        ("unknown.jsonl", [{"record_type": "flow_snapshot", "schema_version": 99}]),
        ("malformed.jsonl", [{"record_type": "not-a-record", "schema_version": 1}]),
    ):
        path = tmp_path / filename
        _write_records(path, rows)
        with pytest.raises(ValueError, match="invalid telemetry JSONL"):
            audit_telemetry_jsonl(path)


def test_timeout_terminal_has_no_snapshot_and_is_not_accepted(tmp_path: Path) -> None:
    rows = _valid_records(include_packetin=False)
    collection_id = f"{EPOCH}:{DPID}:00000001"
    rows[3] = {
        "record_type": "incomplete_collection",
        "schema_version": 2,
        "timestamp": (BASE + timedelta(seconds=1, milliseconds=200)).isoformat(),
        "collection_id": collection_id,
        "datapath_id": DPID,
        "datapath_epoch_id": EPOCH,
        "xid": 1,
        "run_id": RUN_ID,
        "complete": False,
        "terminal_state": "TIMED_OUT",
        "reason": "synthetic fixture only",
        "terminal_monotonic_ns": 1_200_000_000,
    }
    del rows[4]
    path = tmp_path / "timed-out.jsonl"
    _write_records(path, rows)
    summary = audit_telemetry_jsonl(path)
    assert summary["status"] == "AUDIT_INCOMPLETE"
    assert summary["counts"]["incomplete_collections"] == 1
    assert any(str(issue).startswith("incomplete_collection:") for issue in summary["issues"])
    assert summary["cadence"]["incomplete_or_invalid_collections"] == 1
    assert summary["cadence"]["missing_timing_collections"] == 0


def test_runner_helpers_explicitly_bind_6653_and_never_reuse_output(tmp_path: Path) -> None:
    assert build_ryu_command(Path("ryu-manager"), 6653) == [
        "ryu-manager",
        "--ofp-tcp-listen-port",
        "6653",
        "networking.ryu.stage2_controller",
    ]
    environment = build_controller_environment(
        {"PYTHONPATH": "existing"},
        root=tmp_path / "project",
        context_path=tmp_path / "context.json",
        telemetry_path=tmp_path / "telemetry.jsonl",
    )
    assert environment["SDN_STAGE2_RECORD_PACKETIN_TELEMETRY"] == "false"
    assert environment["SDN_STAGE2_PACKET_EVIDENCE_ENABLED"] == "false"
    assert environment["SDN_STAGE2_INSTALL_TEST_RULE"] == "false"
    assert environment["SDN_RYU_STATUS_FILE"] == str(
        tmp_path / "project" / "var/runtime/ryu-status.json"
    )
    assert environment["SDN_STAGE2_MAX_FEATURE_GAP_SECONDS"] == "30.0"
    assert environment["PYTHONPATH"].endswith(os.pathsep + "existing")
    created = create_fresh_output_directory(tmp_path / "fresh")
    assert created.is_dir()
    with pytest.raises(FileExistsError):
        create_fresh_output_directory(created)


def test_runner_gap_configuration_is_validated_before_process_start(tmp_path: Path) -> None:
    configured = build_controller_environment(
        {"SDN_STAGE2_MAX_FEATURE_GAP_SECONDS": "12.5"},
        root=tmp_path / "project",
        context_path=tmp_path / "context.json",
        telemetry_path=tmp_path / "telemetry.jsonl",
    )
    assert configured["SDN_STAGE2_MAX_FEATURE_GAP_SECONDS"] == "12.5"
    for value in ("0", "nan", "inf", "invalid"):
        with pytest.raises(ValueError, match="SDN_STAGE2_MAX_FEATURE_GAP_SECONDS"):
            build_controller_environment(
                {"SDN_STAGE2_MAX_FEATURE_GAP_SECONDS": value},
                root=tmp_path / "project",
                context_path=tmp_path / "context.json",
                telemetry_path=tmp_path / "telemetry.jsonl",
            )


def test_runner_environment_inventory_uses_bounded_version_argv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import scripts.run_stage7_rule_counter_validation as runner

    commands: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: object) -> SimpleNamespace:
        commands.append(command)
        assert kwargs["timeout"] == 5
        assert kwargs["capture_output"] is True
        return SimpleNamespace(returncode=0, stdout=f"{command[0]} version", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    versions = runner._capture_environment_versions(tmp_path / "ryu-manager")
    assert set(versions) == {"ryu_manager", "mininet", "ovs_vsctl", "ovs_ofctl"}
    assert commands[0] == [str(tmp_path / "ryu-manager"), "--version"]
    assert all(command[-1] == "--version" for command in commands)
    hashes = runner._source_hashes(Path(__file__).resolve().parents[2])
    assert "networking/ryu/stage2_controller.py" in hashes
    assert all(len(digest) == 64 for digest in hashes.values())


def test_runner_preflight_rejects_missing_mininet_python_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import scripts.run_stage7_rule_counter_validation as runner

    monkeypatch.setattr(importlib.util, "find_spec", lambda _name: None)
    with pytest.raises(RuntimeError, match="Mininet Python module is unavailable"):
        runner._ensure_mininet_python_module()


def test_packetin_recording_guard_does_not_remove_forwarding_path() -> None:
    controller_path = Path(__file__).resolve().parents[2] / "networking/ryu/stage2_controller.py"
    tree = ast.parse(controller_path.read_text(encoding="utf-8"))
    controller = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "Stage2Controller"
    )
    methods = {
        node.name: node
        for node in controller.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    table_miss = methods["_install_table_miss"]
    assert any(
        isinstance(node, ast.Attribute) and node.attr == "OFPP_CONTROLLER"
        for node in ast.walk(table_miss)
    )

    packet_handler = methods["packet_in_handler"]
    recording_guards = [
        node
        for node in ast.walk(packet_handler)
        if isinstance(node, ast.If)
        and "record_packetin_telemetry" in ast.dump(node.test, include_attributes=False)
    ]
    assert len(recording_guards) == 2
    assert all(
        any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "_record_packet_observation"
            for statement in guard.body
            for node in ast.walk(statement)
        )
        for guard in recording_guards
    )
    assert any(
        isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "packet_out" for target in node.targets
        )
        for node in packet_handler.body
    )
    assert any(
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Attribute)
        and node.value.func.attr == "send_msg"
        for node in packet_handler.body
    )


def test_runner_refuses_dangling_output_symlink_before_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import scripts.run_stage7_rule_counter_validation as runner

    link = tmp_path / "occupied-link"
    link.symlink_to(tmp_path / "not-created")
    monkeypatch.setattr(
        runner,
        "_ensure_prerequisites",
        lambda _port: pytest.fail("preflight must not run for an existing symlink"),
    )
    with pytest.raises(FileExistsError):
        run_benign_validation(link, tmp_path / "unused-ryu-manager")
    assert not (tmp_path / "not-created").exists()


def test_benign_runner_refuses_existing_directory_before_any_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import scripts.run_stage7_rule_counter_validation as runner

    existing = tmp_path / "already-used"
    existing.mkdir()
    monkeypatch.setattr(
        runner,
        "_ensure_prerequisites",
        lambda _port: pytest.fail("preflight must not run for an existing output directory"),
    )
    with pytest.raises(FileExistsError):
        run_benign_validation(existing, tmp_path / "unused-ryu-manager")


def test_runner_allocates_run_id_before_preflight_processes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import scripts.run_stage7_rule_counter_validation as runner

    events: list[str] = []

    class StopAtPreflight(RuntimeError):
        pass

    def make_run_id() -> str:
        events.append("run-id")
        return RUN_ID

    monkeypatch.setattr(runner, "_run_id", make_run_id)

    def stop_after_id(_port: int) -> None:
        assert events == ["run-id"]
        events.append("preflight")
        raise StopAtPreflight

    monkeypatch.setattr(runner, "_ensure_prerequisites", stop_after_id)
    with pytest.raises(StopAtPreflight):
        run_benign_validation(tmp_path / "new-run", tmp_path / "unused-ryu-manager")


def test_runner_cli_does_not_accept_an_attack_or_scenario_selector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts import run_stage7_rule_counter_validation as runner

    monkeypatch.setattr(
        sys,
        "argv",
        ["runner", "--output-dir", str(tmp_path / "unused"), "--scenario", "port-scan"],
    )
    with pytest.raises(SystemExit) as error:
        runner.main()
    assert error.value.code == 2


def test_auditor_cli_refuses_output_aliasing_input_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts import audit_stage7_rule_counter_telemetry as cli

    path = tmp_path / "telemetry.jsonl"
    _write_records(path, _valid_records())
    before = path.read_bytes()
    monkeypatch.setattr(sys, "argv", ["audit", str(path), "--summary-json", str(path)])
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 2
    assert path.read_bytes() == before


def test_auditor_cli_refuses_hard_link_alias_to_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts import audit_stage7_rule_counter_telemetry as cli

    source = tmp_path / "telemetry.jsonl"
    _write_records(source, _valid_records())
    alias = tmp_path / "output.json"
    os.link(source, alias)
    before = source.read_bytes()
    monkeypatch.setattr(sys, "argv", ["audit", str(source), "--summary-json", str(alias)])
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 2
    assert source.read_bytes() == before


def test_auditor_cli_refuses_same_path_for_summary_and_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts import audit_stage7_rule_counter_telemetry as cli

    source = tmp_path / "telemetry.jsonl"
    _write_records(source, _valid_records())
    output = tmp_path / "summary.json"
    monkeypatch.setattr(
        sys,
        "argv",
        ["audit", str(source), "--summary-json", str(output), "--report-md", str(output)],
    )
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 2
    assert not output.exists()


def test_auditor_cli_reports_unwritable_output_without_claiming_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from scripts import audit_stage7_rule_counter_telemetry as cli

    path = tmp_path / "telemetry.jsonl"
    _write_records(path, _valid_records())
    output = tmp_path / "missing-parent" / "summary.json"
    monkeypatch.setattr(sys, "argv", ["audit", str(path), "--summary-json", str(output)])
    assert cli.main() == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("AUDIT_OUTPUT_ERROR:")


def test_cleanup_verification_fails_on_unstopped_controller_or_residual_bridge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    alive = SimpleNamespace(poll=lambda: None)
    with pytest.raises(RuntimeError, match="did not stop"):
        _verify_cleanup(cast(subprocess.Popen[bytes], alive), 6653)

    stopped = SimpleNamespace(poll=lambda: 0)
    monkeypatch.setattr(
        "scripts.run_stage7_rule_counter_validation.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0),
    )
    with pytest.raises(RuntimeError, match="bridge s1 behind"):
        _verify_cleanup(cast(subprocess.Popen[bytes], stopped), 6653)

    monkeypatch.setattr(
        "scripts.run_stage7_rule_counter_validation.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=2),
    )

    class ListeningSocket:
        def __enter__(self) -> object:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def settimeout(self, _timeout: float) -> None:
            return None

        def connect(self, _address: tuple[str, int]) -> None:
            return None

    monkeypatch.setattr(
        "scripts.run_stage7_rule_counter_validation.socket.socket",
        lambda *_args, **_kwargs: ListeningSocket(),
    )
    with pytest.raises(RuntimeError, match="listener remains"):
        _verify_cleanup(cast(subprocess.Popen[bytes], stopped), 6653)
