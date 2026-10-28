"""Configuration contract for the Stage 2 Ryu controller."""

from __future__ import annotations

import math
from dataclasses import dataclass
from os import getenv
from pathlib import Path

from networking.ryu.packet_evidence import PacketEvidencePolicy


def _as_bool(value: str) -> bool:
    """Interpret an explicit environment flag."""

    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True, slots=True)
class ControllerConfig:
    """Controller observation and explicitly invoked test-rule configuration."""

    monitor_interval_seconds: float
    install_explicit_test_rule: bool
    test_rule_cookie: int
    test_rule_priority: int
    test_rule_idle_timeout_seconds: int
    test_rule_source_ip: str
    test_rule_destination_ip: str
    test_rule_tcp_port: int
    test_rule_egress_port: int
    observation_context_file: Path | None = None
    telemetry_jsonl: Path | None = None
    packet_evidence_enabled: bool = False
    record_packetin_telemetry: bool = True
    packet_evidence_max_per_second: int = 4
    packet_evidence_max_per_run: int = 16
    maximum_feature_gap_seconds: float = 30.0
    status_file: Path = Path("var/runtime/ryu-status.json")
    run_telemetry_directory: Path | None = None

    @classmethod
    def from_environment(cls) -> ControllerConfig:
        """Load settings; test-rule installation remains disabled by default."""

        context_file = getenv("SDN_OBSERVATION_CONTEXT_FILE")
        telemetry_file = getenv("SDN_TELEMETRY_JSONL")
        run_telemetry_directory = getenv("SDN_STAGE2_RUN_TELEMETRY_DIR")
        return cls(
            monitor_interval_seconds=float(getenv("SDN_STAGE2_MONITOR_INTERVAL_SECONDS", "2.0")),
            install_explicit_test_rule=_as_bool(getenv("SDN_STAGE2_INSTALL_TEST_RULE", "false")),
            test_rule_cookie=int(getenv("SDN_STAGE2_TEST_RULE_COOKIE", "0x534432"), 0),
            test_rule_priority=int(getenv("SDN_STAGE2_TEST_RULE_PRIORITY", "100")),
            test_rule_idle_timeout_seconds=int(
                getenv("SDN_STAGE2_TEST_RULE_IDLE_TIMEOUT_SECONDS", "120")
            ),
            test_rule_source_ip=getenv("SDN_STAGE2_TEST_RULE_SOURCE_IP", "10.0.0.1"),
            test_rule_destination_ip=getenv("SDN_STAGE2_TEST_RULE_DESTINATION_IP", "10.0.0.3"),
            test_rule_tcp_port=int(getenv("SDN_STAGE2_TEST_RULE_TCP_PORT", "18080")),
            test_rule_egress_port=int(getenv("SDN_STAGE2_TEST_RULE_EGRESS_PORT", "3")),
            observation_context_file=(
                Path(context_file) if context_file is not None and context_file else None
            ),
            telemetry_jsonl=(
                Path(telemetry_file) if telemetry_file is not None and telemetry_file else None
            ),
            packet_evidence_enabled=_as_bool(getenv("SDN_STAGE2_PACKET_EVIDENCE_ENABLED", "false")),
            record_packetin_telemetry=_as_bool(
                getenv("SDN_STAGE2_RECORD_PACKETIN_TELEMETRY", "true")
            ),
            packet_evidence_max_per_second=int(getenv("SDN_PACKET_EVIDENCE_MAX_PER_SECOND", "4")),
            packet_evidence_max_per_run=int(getenv("SDN_PACKET_EVIDENCE_MAX_PER_RUN", "16")),
            maximum_feature_gap_seconds=float(
                getenv("SDN_STAGE2_MAX_FEATURE_GAP_SECONDS", "30.0")
            ),
            status_file=Path(getenv("SDN_RYU_STATUS_FILE", "var/runtime/ryu-status.json")),
            run_telemetry_directory=(
                Path(run_telemetry_directory)
                if run_telemetry_directory
                else None
            ),
        )

    def validate(self) -> None:
        """Reject invalid explicit test-rule settings before controller operation."""

        if self.monitor_interval_seconds <= 0:
            raise ValueError("SDN_STAGE2_MONITOR_INTERVAL_SECONDS must be positive")
        if (
            not math.isfinite(self.maximum_feature_gap_seconds)
            or self.maximum_feature_gap_seconds <= 0
        ):
            raise ValueError("SDN_STAGE2_MAX_FEATURE_GAP_SECONDS must be finite and positive")
        if not 1 <= self.test_rule_tcp_port <= 65535:
            raise ValueError("SDN_STAGE2_TEST_RULE_TCP_PORT must be between 1 and 65535")
        if self.test_rule_egress_port <= 0:
            raise ValueError("SDN_STAGE2_TEST_RULE_EGRESS_PORT must be positive")
        if self.test_rule_idle_timeout_seconds <= 0:
            raise ValueError("SDN_STAGE2_TEST_RULE_IDLE_TIMEOUT_SECONDS must be positive")
        if self.packet_evidence_enabled:
            if self.telemetry_jsonl is None or self.observation_context_file is None:
                raise ValueError(
                    "packet evidence requires a JSONL recorder and explicit run context"
                )
            PacketEvidencePolicy(
                max_observations_per_second=self.packet_evidence_max_per_second,
                max_observations_per_run=self.packet_evidence_max_per_run,
            )
