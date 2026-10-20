"""Findings carry their evidence: who/what they are about and the lines."""
from datetime import datetime, timedelta

from logcrux.analysis.engine import run_analysis
from logcrux.analysis.evidence import evidence_events, subjects, template
from logcrux.config import AnalysisConfig
from logcrux.models import ParsedEvent, Severity

T0 = datetime(2026, 10, 13, 8, 34, 0)


def _ev(i: int, msg: str, sev: Severity = Severity.INFO, source: str = "sshd",
        extra: dict[str, object] | None = None) -> ParsedEvent:
    return ParsedEvent(timestamp=T0 + timedelta(seconds=i), severity=sev, source=source,
                       message=msg, raw=f"Oct 13 08:34:{i:02d} host {source}[1]: {msg}",
                       line_number=i + 1, extra=extra or {})


def test_template_masks_variable_tokens():
    assert template("Failed password for root from 10.0.0.5 port 4422 ssh2") == \
        "Failed password for root from <ip> port <n> ssh<n>"
    assert template("first line\nsecond line") == "first line"


def test_auth_subjects_count_sources_and_users():
    evs = [_ev(i, f"Failed password for {'root' if i % 2 else 'invalid user admin'} "
                  f"from 203.0.113.9 port {4000 + i} ssh2") for i in range(20)]
    evs.append(_ev(21, "Failed password for root from 198.51.100.7 port 1 ssh2"))
    subs = {(s.label, s.value): s.count for s in subjects("auth_failure_cluster", evs)}
    assert subs[("source", "203.0.113.9")] == 20
    assert subs[("source", "198.51.100.7")] == 1
    assert subs[("user", "root")] == 11
    assert subs[("user", "admin")] == 10


def test_db_auth_users():
    pg = _ev(0, 'FATAL:  password authentication failed for user "postgres"')
    my = _ev(1, "Access denied for user 'root'@'localhost' (using password: YES)")
    subs = {(s.label, s.value) for s in subjects("auth_failure_cluster", [pg, my])}
    assert ("user", "postgres") in subs and ("user", "root") in subs


def test_oom_and_crash_subjects():
    oom = _ev(0, "Memory cgroup out of memory: Killed process 4522 (tail) total-vm:1kB",
              source="kernel")
    assert ("killed", "tail") in {(s.label, s.value) for s in subjects("oom_event", [oom])}
    unit = _ev(1, "lc-worker.service: Main process exited, code=killed, status=9/KILL",
               source="systemd")
    seg = _ev(2, "myapp[311]: segfault at 0 ip 000055 sp 00007f error 4", source="kernel")
    got = {(s.label, s.value) for s in subjects("service_crash", [unit, seg])}
    assert ("unit", "lc-worker.service") in got and ("process", "myapp") in got


def test_burst_subjects_are_message_templates():
    evs = [_ev(i, f"upstream timed out ({i}) while connecting", Severity.ERROR)
           for i in range(30)]
    subs = subjects("error_burst", evs)
    assert subs[0].label == "message" and subs[0].count == 30


def test_http_subjects_from_access_fields():
    evs = [_ev(i, "GET /api/orders 502", Severity.ERROR, source="nginx",
               extra={"status_code": 502, "path": "/api/orders?id=1", "client_ip": "10.1.1.1"})
           for i in range(5)]
    got = {(s.label, s.value): s.count for s in subjects("error_burst", evs)}
    assert got[("status", "502")] == 5 and got[("path", "/api/orders")] == 5


def test_evidence_prefers_frequent_templates_in_file_order():
    evs = [_ev(0, "rare thing happened")] + [_ev(i, f"common failure {i}") for i in range(1, 9)]
    evs += [_ev(10, "second kind of failure 1"), _ev(11, "second kind of failure 2")]
    picked = evidence_events(evs, limit=2)
    assert [e.line_number for e in picked] == [2, 11]


def test_redundant_burst_is_folded_into_the_auth_finding():
    evs = [_ev(i, f"Failed password for root from 203.0.113.9 port {i} ssh2", Severity.ERROR)
           for i in range(40)]
    res = run_analysis(evs, "syslog", "x.log", baseline=None, config=AnalysisConfig())
    kinds = [s.kind for s in res.signals]
    assert kinds == ["auth_failure_cluster"], kinds
    # The burst's ERROR severity passes to the auth finding (level unchanged).
    assert res.signals[0].severity == Severity.ERROR
    assert res.signals[0].subjects[0].value == "203.0.113.9"
    assert res.signals[0].evidence


def test_unrelated_burst_is_kept_after_specific_findings():
    evs = [_ev(i, f"Failed password for root from 203.0.113.9 port {i} ssh2")
           for i in range(15)]
    evs += [_ev(20 + i, f"disk controller timeout {i}", Severity.ERROR, source="app")
            for i in range(30)]
    res = run_analysis(evs, "syslog", "x.log", baseline=None, config=AnalysisConfig())
    kinds = [s.kind for s in res.signals]
    assert kinds[0] == "auth_failure_cluster" and "error_burst" in kinds


def test_steady_error_rate_is_not_a_burst():
    # 13 h at a uniform ~1 error/min: every 5-min window clears the absolute
    # floor of 10 only if the floor ignores the file's own rate.
    evs = [_ev(i * 6, f"request {i} failed", Severity.ERROR if i % 2 == 0 else Severity.INFO)
           for i in range(8000)]
    res = run_analysis(evs, "generic", "x.log", baseline=None, config=AnalysisConfig())
    assert not [s for s in res.signals if s.kind == "error_burst"]


def test_burst_inside_a_long_steady_log_is_still_found():
    evs = [_ev(i * 6, f"request {i} failed", Severity.ERROR if i % 10 == 0 else Severity.INFO)
           for i in range(8000)]
    evs += [_ev(20000 + i, "connection pool exhausted", Severity.ERROR) for i in range(120)]
    res = run_analysis(sorted(evs, key=lambda e: e.timestamp or T0), "generic", "x.log",
                       baseline=None, config=AnalysisConfig())
    assert [s for s in res.signals if s.kind == "error_burst"]


def test_service_neutral_auth_wording_clusters():
    # An unseen service's own format, but the universal phrasing.
    evs = [_ev(i, f"Authentication failed for user bob from 10.0.0.{i % 3} (attempt {i})",
               source="myapp") for i in range(12)]
    res = run_analysis(evs, "generic", "x.log", baseline=None, config=AnalysisConfig())
    assert [s.kind for s in res.signals] == ["auth_failure_cluster"]
    assert ("user", "bob") in {(s.label, s.value) for s in res.signals[0].subjects}


def test_vocabulary_free_auth_failures():
    from logcrux.analysis.anomaly import _is_auth_failure
    yes = ['user "admin": password mismatch, client: 10.0.0.1',          # nginx auth_basic
           "Login failed for user 'sa'. Reason: Password did not match",  # mssql-like
           "Authentication for user [alice] FAILED"]
    no = ["login page rendered in 12 ms", "password policy updated",
          "authentication succeeded for bob", "failed to load template header.html"]
    assert all(_is_auth_failure(_ev(0, m)) for m in yes)
    assert not any(_is_auth_failure(_ev(0, m)) for m in no)


def test_oom_evidence_includes_the_kill_line():
    evs = [_ev(i, "lc-oom.service: A process of this unit has been killed by the OOM killer.",
               source="systemd") for i in range(5)]
    evs += [_ev(9, "Memory cgroup out of memory: Killed process 42 (tail) total-vm:1kB",
                source="kernel")]
    res = run_analysis(evs, "syslog", "x.log", baseline=None, config=AnalysisConfig())
    oom = next(s for s in res.signals if s.kind == "oom_event")
    assert any("Killed process 42" in e.message for e in oom.evidence)
