"""Opt-in privileged test for synthetic detection-to-OVS integration."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(
    os.environ.get("SDN_STAGE7_RUN_DETECTION_INTEGRATION") != "1",
    reason="requires explicit opt-in, root, Mininet, OVS, and the pinned Ryu runtime",
)
def test_synthetic_detection_to_live_ovs_enforcement() -> None:
    if os.geteuid() != 0:
        pytest.skip("live Stage 7 integration requires root")
    result = subprocess.run(
        [
            os.environ.get("SDN_STAGE7_VALIDATION_PYTHON", "/usr/bin/python3"),
            str(ROOT / "scripts/run_stage7_detection_enforcement.py"),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    report = Path(
        os.environ.get(
            "SDN_STAGE7_INTEGRATION_REPORT", "/tmp/stage7-detection-enforcement.json"
        )
    )
    assert report.is_file()
    assert '"result": "PASS"' in report.read_text(encoding="utf-8")
