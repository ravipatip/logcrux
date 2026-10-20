"""journalctl exports — the most common way logcrux is fed a Linux box.

Fixtures are real, anonymised captures from GCP VMs (2026-10-13, the
project's real-VM campaign): a healthy RHEL 10.2 boot, a Debian 12 boot after an
OOM kill / sshd brute force / restart loop, and `journalctl -k -o short-iso`
around a cgroup OOM kill.

Before these fixes every one of them fell to the generic parser on all 12
distros tested: the boot journal opens with hundreds of ``kernel:`` lines, so
detection picked ``kernel``, which covered half the file, and the fallback went
straight to generic instead of re-detecting.
"""

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from logcrux.analysis.engine import _BOOT_SETTLE, _drop_boot_noise
from logcrux.cli import app
from logcrux.models import AnomalySignal, Severity, TimeWindow
from logcrux.parsers.kernel import KernelParser
from logcrux.parsers.registry import redetect_candidates
from logcrux.parsers.syslog import SyslogParser
from tests.integration.test_cli import _copy_to_tmp

runner = CliRunner()
FIXTURES = Path(__file__).parent.parent / "fixtures"


def _run(name, tmp_path):
    log = _copy_to_tmp(name, tmp_path)
    result = runner.invoke(app, [str(log), "--json", "--no-baseline"])
    return json.loads(result.stdout)


def test_healthy_boot_journal_redetects_to_syslog_and_stays_clean(tmp_path):
    out = _run("journal_boot_healthy_rhel10.log", tmp_path)
    assert out["parser_format"] == "syslog"
    # setfont/rngd/guest-agent complaints during boot are not an incident.
    assert out["level"] == "CLEAN"


def test_faulted_boot_journal_still_reports_its_faults(tmp_path):
    # The boot-noise rule must not swallow real faults later in the same boot.
    out = _run("journal_boot_faults_debian12.log", tmp_path)
    assert out["parser_format"] == "syslog"
    assert out["level"] == "CRITICAL"
    headlines = {f["headline"] for f in out["findings"]}
    assert "OOM killer fired" in headlines


def test_kernel_short_iso_parses_every_line(tmp_path):
    lines = (FIXTURES / "kernel_short_iso_oom.log").read_text().splitlines()
    parser = KernelParser()
    events = list(parser.parse_stream(iter(lines)))
    non_blank = sum(1 for ln in lines if ln.strip())
    # The OOM report's indented memory.stat dump folds into its record.
    assert len(events) + parser.meta_lines == non_blank
    assert any("oom-killer" in e.message for e in events)
    out = _run("kernel_short_iso_oom.log", tmp_path)
    assert out["parser_format"] == "kernel"
    assert out["category"] == "oom"


def test_syslog_folds_indented_continuations():
    lines = [
        "Oct 13 03:38:43 host kernel: Memory cgroup stats for /system.slice/lc-oom.service:",
        "                                              anon 155103232",
        "                                              file 32768",
        "Oct 13 03:38:43 host kernel: Killed process 1494 (tail)",
    ]
    parser = SyslogParser()
    events = list(parser.parse_stream(iter(lines)))
    assert len(events) == 2
    assert "anon 155103232" in events[0].message
    assert parser.meta_lines == 2


def test_redetect_candidates_skips_the_failed_parser_and_generic():
    lines = (FIXTURES / "journal_boot_healthy_rhel10.log").read_text().splitlines(True)
    cands = redetect_candidates(lines, KernelParser)
    names = [c.FORMAT_NAME for c, _ in cands]
    assert "kernel" not in names and "generic" not in names
    assert "syslog" in names


def _burst(start, end):
    return AnomalySignal(
        kind="error_burst",
        window=TimeWindow(start=start, end=end, duration_seconds=(end - start).total_seconds()),
        event_count=12, baseline_count=None, severity=Severity.ERROR,
        representative_events=[],
    )


def test_boot_noise_window_boundaries():
    b0 = datetime(2026, 10, 13, 3, 48, 52)
    b1 = b0 + timedelta(seconds=20)
    phase = [(b0, b1)]
    inside = _burst(b0, b1 + timedelta(seconds=4))          # spills into settle
    late = _burst(b1 + timedelta(seconds=5), b1 + timedelta(seconds=30))  # starts after boot
    long = _burst(b0, b1 + _BOOT_SETTLE + timedelta(seconds=1))           # outlasts settle
    kept = _drop_boot_noise([inside, late, long], phase)
    assert inside not in kept
    assert late in kept and long in kept


def test_parser_claiming_one_window_does_not_beat_one_claiming_the_body(tmp_path):
    # Real RHEL 8.10 boot (GCP, 2026-10-13): journald logs "Collecting audit
    # messages is disabled.", which used to let `pip` claim a window and then
    # win re-detection with "100% coverage" (pip accepts any line).
    out = _run("journal_boot_healthy_rhel8.log", tmp_path)
    assert out["parser_format"] == "syslog"
    assert out["level"] == "CLEAN"


def test_pip_markers_must_start_the_line():
    from logcrux.parsers.pip import PipParser
    journal = ["Oct 13 07:24:01 host systemd-journald[600]: Collecting audit messages is disabled."]
    assert not PipParser.can_parse(None, journal)
    assert PipParser.can_parse(None, ["Collecting requests==2.31.0"])


def test_short_precise_journal_parses_as_syslog():
    # `journalctl -o short-precise` (microseconds), real Debian 12 VM 2026-10-20:
    # generic before the syslog pattern took an optional fraction.
    import json

    from typer.testing import CliRunner

    from logcrux.cli import app
    path = Path(__file__).parent.parent / "fixtures" / "journal_short_precise_debian12.log"
    data = json.loads(CliRunner().invoke(app, [str(path), "--no-baseline", "--json"]).output)
    assert data["parser_format"] == "syslog" and data["coverage"]["ratio"] == 1.0
    assert data["category"] == "oom"


@pytest.mark.parametrize("name", [
    # GCP phase 3 (2026-10-20): both were false "Error burst" alarms.
    "journal_boot_healthy_debian13_gce.log",   # systemd-ssh-generator / AF_VSOCK, per reload
    "journal_boot_healthy_alma8_slow.log",      # user manager finished 2 min before PID 1
])
def test_healthy_gce_boots_stay_clean(name):
    import json

    from typer.testing import CliRunner

    from logcrux.cli import app
    path = Path(__file__).parent.parent / "fixtures" / name
    data = json.loads(CliRunner().invoke(app, [str(path), "--no-baseline", "--json"]).output)
    assert data["level"] == "CLEAN", data["findings"]
