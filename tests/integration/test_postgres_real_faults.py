"""PostgreSQL faults induced on real GCP VMs (2026-10-13), anonymised captures.

Before these fixes: a SIGKILLed backend was CLEAN on 12/12 distros (the
postmaster logs the crash and recovery entirely at LOG level); a full data
volume was CLEAN on PG 13/14 (different ENOSPC wording); and SUSE's packaged
log_line_prefix fell to the generic parser.
"""
import json

import pytest
from typer.testing import CliRunner

from logcrux.cli import app
from tests.integration.test_cli import _copy_to_tmp

runner = CliRunner()


def _run(name, tmp_path):
    log = _copy_to_tmp(name, tmp_path)
    return json.loads(runner.invoke(app, [str(log), "--json", "--no-baseline"]).stdout)


@pytest.mark.parametrize("fixture", [
    "postgres_crash_pg15_debian12.log",   # "server process (PID n) was terminated by signal 9"
    "postgres_crash_pg18_suse.log",       # "client backend (PID n) ..." + SUSE prefix
])
def test_sigkilled_backend_is_a_service_crash(fixture, tmp_path):
    out = _run(fixture, tmp_path)
    assert out["parser_format"] == "postgresql"
    assert out["level"] != "CLEAN"
    assert out["category"] == "service_crash"


def test_pg14_enospc_wording_is_disk_full(tmp_path):
    out = _run("postgres_diskfull_pg14_ubuntu2204.log", tmp_path)
    assert out["level"] == "CRITICAL"
    assert out["category"] == "disk_full"


def test_suse_prefix_parses_every_line(tmp_path):
    # '%m %d %u [%p]' -> "... UTC postgres postgres [4428]FATAL:  ..." plus
    # tab-indented DETAIL continuations; previously 0 lines -> generic.
    out = _run("postgres_authfail_pg17_suse.log", tmp_path)
    assert out["parser_format"] == "postgresql"
    assert out["skipped_count"] == 0
    assert out["category"] == "auth_brute_force"
