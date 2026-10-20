"""Classic sysadmin incidents — lab/apps6, the sixth held-out round (real
containers, 2026-10-20). First contact: 1/7; no detector existed for
resource limits or refused certificates, and borg had no parser."""
import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from logcrux.cli import app

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _run(name: str) -> dict[str, Any]:
    r = CliRunner().invoke(app, [str(FIXTURES / name), "--no-baseline", "--json"])
    data: dict[str, Any] = json.loads(r.output)
    return data


@pytest.mark.parametrize("name,kind,subject", [
    ("nginx_nofile_docker.log", "resource_limit", ("limit", "open files")),
    ("fork_limit_docker.log", "resource_limit", ("limit", "processes")),
    ("tls_expired_client_docker.log", "tls_error", None),
    ("postfix_relay_denied_docker.log", "mail_reject_cluster", ("client", "loving_lewin.lc6[172.23.0.3]")),
    ("borg_badpass.log", "job_failure", None),
    ("borg_missing_src.log", "job_failure", None),
    ("borg_repo_gone.log", "job_failure", None),
])
def test_incident(name, kind, subject):
    data = _run(name)
    f = data["findings"][0]
    assert data["level"] in ("WARNING", "CRITICAL") and f["kind"] == kind, data["title"]
    if subject:
        assert subject in {(s["label"], s["value"]) for s in f["subjects"]}


def test_tls_is_named_a_network_issue():
    assert _run("tls_expired_client_docker.log")["category"] == "network_issue"


def test_borg_clean_run_is_clean_and_partial_is_partial():
    assert _run("borg_ok.log")["level"] == "CLEAN"
    assert _run("borg_missing_src.log")["title"] == "Job completed with missing data"


def test_a_few_mail_rejects_are_normal():
    from logcrux.analysis.anomaly import analyze_mail_rejects
    from logcrux.parsers.syslog import SyslogParser
    lines = (FIXTURES / "postfix_relay_denied_docker.log").read_text().splitlines()
    p = SyslogParser()
    evs = [e for i, ln in enumerate(lines, 1) if (e := p.parse_line(ln, i)) is not None]
    rejects = [e for e in evs if "NOQUEUE: reject" in e.message]
    assert analyze_mail_rejects(rejects[:5]) == []


@pytest.mark.parametrize("name,parser", [
    # lab/apps7: structured JSON app logs ending on a fatal record.
    ("pino_dbdown_docker.log", "pino"),
    ("structlog_dbdown_docker.log", "json"),
])
def test_structured_app_fatal_exit(name, parser):
    data = _run(name)
    assert data["parser_format"] == parser and data["category"] == "service_crash"
    assert any(f["kind"] == "fatal_exit" for f in data["findings"])


def test_structlog_healthy_is_clean_and_parsed():
    data = _run("structlog_ok_docker.log")
    assert data["parser_format"] == "json" and data["level"] == "CLEAN"
    assert data["time_range"] is not None


def test_winston_ending_on_error_is_not_a_fatal_exit():
    data = _run("winston_cachedown_docker.log")
    assert data["level"] == "WARNING"
    assert not any(f["kind"] == "fatal_exit" for f in data["findings"])


def test_security_event_json_critical_is_not_a_process_exit():
    from logcrux.analysis.anomaly import analyze_fatal_exit
    from logcrux.models import ParsedEvent, Severity
    evs = [ParsedEvent(timestamp=None, severity=Severity.CRITICAL if i == 3 else Severity.INFO,
                       source="suricata", message="alert", raw='{"event_type":"alert"}',
                       line_number=i, extra={"level": "critical"}) for i in range(1, 4)]
    assert analyze_fatal_exit(evs) == []


def test_chrony_clock_jump_real_vm():
    data = _run("chrony_clock_jump_rhel9.log")
    f = data["findings"][0]
    assert f["kind"] == "clock_jump" and ("offset", "-7200 s") in {
        (s["label"], s["value"]) for s in f["subjects"]}


def test_small_boot_time_corrections_are_quiet():
    from logcrux.analysis.anomaly import is_clock_jump
    from logcrux.models import ParsedEvent, Severity
    e = ParsedEvent(timestamp=None, severity=Severity.INFO, source="chronyd", raw="",
                    message="System clock wrong by 0.412345 seconds", line_number=1)
    assert not is_clock_jump(e)


def test_systemd_service_limitnofile_real_vm():
    data = _run("systemd_limitnofile_debian12.log")
    assert any(f["kind"] == "resource_limit" for f in data["findings"])


def test_package_manager_lock_held_is_a_failed_job():
    data = _run("zypper_lock_held_sles15.log")
    f = data["findings"][0]
    assert f["kind"] == "job_failure" and "System management is locked" in f["detail"]


@pytest.mark.parametrize("name,limit", [
    # lab/apps8: capacity limits. httpd's line sat in the 27% an access
    # parser skipped — now kept as a generic event and found.
    ("httpd_maxrequestworkers_docker.log", "workers"),
    ("postgres_too_many_clients_docker.log", "connections"),
])
def test_capacity_limits(name, limit):
    data = _run(name)
    f = next(x for x in data["findings"] if x["kind"] == "resource_limit")
    assert ("limit", limit) in {(s["label"], s["value"]) for s in f["subjects"]}


def test_no_line_is_dropped_when_a_parser_covers_most_of_a_file():
    data = _run("httpd_maxrequestworkers_docker.log")
    assert data["parsed_count"] + data["skipped_count"] >= data["coverage"]["lines"] - 1
    assert data["skipped_count"] == 0


def test_steady_spam_rejects_on_a_busy_mx_are_background():
    from datetime import datetime, timedelta

    from logcrux.analysis.anomaly import analyze_mail_rejects
    from logcrux.models import ParsedEvent, Severity
    t0 = datetime(2026, 10, 20)
    evs = [ParsedEvent(timestamp=t0 + timedelta(seconds=20 * i), severity=Severity.INFO,
                       source="postfix/smtpd", raw="", line_number=i,
                       message="NOQUEUE: reject: RCPT from x[203.0.113.9]: 554 5.7.1 spam")
           for i in range(2000)]   # 3 a minute for 11 hours
    assert analyze_mail_rejects(evs) == []


@pytest.mark.parametrize("name,category", [
    # lab/apps9: BIND zone not loaded, Samba wrong passwords (0/2 before).
    ("bind9_badzone_docker.log", "config_error"),
    ("samba_authfail_docker.log", "auth_brute_force"),
])
def test_network_services(name, category):
    data = _run(name)
    assert data["category"] == category, data["title"]


def test_bind_healthy_start_is_clean():
    assert _run("bind9_ok_docker.log")["level"] == "CLEAN"


def test_samba_counts_each_attempt_once():
    f = _run("samba_authfail_docker.log")["findings"][0]
    assert f["count"] == 20
