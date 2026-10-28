"""Privileged Stage 7 enforcement test; opt in on an isolated Mininet host only."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(
    os.environ.get("SDN_STAGE7_RUN_LIVE_TESTS") != "1",
    reason="requires explicit opt-in, root, Mininet, OVS, and Ryu",
)
def test_live_mininet_ovs_enforcement_and_rollback() -> None:
    """Run the real, bounded local enforcement validation harness."""

    if os.geteuid() != 0:
        pytest.skip("live Stage 7 validation requires root")
    result = subprocess.run(
        [
            os.environ.get("SDN_STAGE7_VALIDATION_PYTHON", "/usr/bin/python3"),
            str(ROOT / "scripts/run_stage7_live_validation.py"),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    report = Path(
        os.environ.get("SDN_STAGE7_VALIDATION_REPORT", "/tmp/stage7-live-validation.json")
    )
    assert report.is_file()
    assert '"result": "PASS"' in report.read_text(encoding="utf-8")
