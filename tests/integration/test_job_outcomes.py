"""Job-outcome detection — real restic runs on a GCP Debian 12 VM (2026-10-13).

Every induced restic failure was reported CLEAN on all 12 distros tested: a
failed backup is one "Fatal:" line, and every detector needed a burst. The
restic parser already declared the run's outcome; nothing read it.
"""
import json
from datetime import datetime

import pytest
from typer.testing import CliRunner

from logcrux.analysis.anomaly import analyze_job_outcomes
from logcrux.cli import app
from logcrux.models import ParsedEvent, Severity
from tests.integration.test_cli import _copy_to_tmp

runner = CliRunner()


def _run(name, tmp_path):
    log = _copy_to_tmp(name, tmp_path)
    result = runner.invoke(app, [str(log), "--json", "--no-baseline"])
    return json.loads(result.stdout), result.exit_code


@pytest.mark.parametrize("fixture, why", [
    ("restic_real_badpass.log", "wrong password or no key found"),
    ("restic_real_missing_src.log", "all source directories/files do not exist"),
    ("restic_real_repo_gone.log", "repository does not exist"),
])
def test_failed_backup_is_reported_with_its_cause(fixture, why, tmp_path):
    out, code = _run(fixture, tmp_path)
    assert out["level"] != "CLEAN" and code != 0
    assert out["findings"][0]["headline"] == "Job failed"
    assert why in out["findings"][0]["detail"]
    # The classifier must not rename a wrong-password abort "Auth Brute Force".
    assert out["category"] == "unknown"
    assert out["confidence"] >= 0.9


def test_partial_backup_is_reported_as_partial(tmp_path):
    out, _ = _run("restic_real_unreadable.log", tmp_path)
    assert out["level"] == "WARNING"
    assert out["findings"][0]["headline"] == "Job completed with missing data"


def test_clean_backup_stays_clean(tmp_path):
    out, code = _run("restic_real_ok.log", tmp_path)
    assert out["level"] == "CLEAN" and code == 0


def _ev(msg, **extra):
    return ParsedEvent(timestamp=datetime(2026, 10, 13), severity=Severity.CRITICAL,
                       source="x", message=msg, raw=msg, line_number=1, extra=extra)


def test_only_a_declared_outcome_counts_never_the_word():
    # A CRITICAL line that merely says "Fatal" is not a job outcome.
    assert analyze_job_outcomes([_ev("Fatal: this is just prose")]) == []
    sig = analyze_job_outcomes([_ev("Fatal: x", outcome="aborted"),
                                _ev("Warning: y", outcome="partial")])
    assert len(sig) == 1 and sig[0].severity == Severity.ERROR
