"""Kernel storage faults — real Rocky Linux 10 captures (GCP, 2026-10-13).

Induced with a dm-error device, an mdadm RAID-1 member failure, and ext4 on
dm-flakey with failing writes. Before: CLEAN on every distro tested.
"""
import json
from datetime import datetime

import pytest
from typer.testing import CliRunner

from logcrux.analysis.anomaly import analyze_storage_faults
from logcrux.cli import app
from logcrux.models import ParsedEvent, Severity
from tests.integration.test_cli import _copy_to_tmp

runner = CliRunner()


@pytest.mark.parametrize("fixture, headline, needle", [
    ("kernel_dm_error_io_rocky10.log", "Disk I/O errors", "Buffer I/O error on dev dm-0"),
    ("kernel_raid1_degraded_rocky10.log", "RAID array degraded", "Disk failure on loop1"),
    ("kernel_ext4_readonly_rocky10.log", "Filesystem remounted read-only",
     "Remounting filesystem read-only"),
])
def test_storage_fault_is_critical_and_named(fixture, headline, needle, tmp_path):
    log = _copy_to_tmp(fixture, tmp_path)
    result = runner.invoke(app, [str(log), "--json", "--no-baseline"])
    out = json.loads(result.stdout)
    assert out["level"] == "CRITICAL" and result.exit_code == 4
    assert out["findings"][0]["headline"] == headline
    assert needle in out["findings"][0]["detail"]
    # No legacy category means "the disk is failing"; the classifier may not
    # relabel it as one.
    assert out["category"] == "unknown"


def _ev(msg):
    return ParsedEvent(timestamp=datetime(2026, 10, 13), severity=Severity.INFO,
                       source="kernel", message=msg, raw=msg, line_number=1)


def test_unrelated_io_words_do_not_fire():
    for msg in ("I/O scheduler mq-deadline registered",
                "EXT4-fs (sda1): mounted filesystem with ordered data mode",
                "md/raid1:md0: active with 2 out of 2 mirrors"):
        assert analyze_storage_faults([_ev(msg)]) == []
