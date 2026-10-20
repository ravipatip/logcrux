"""`docker logs` of common images — real captures from lab/apps (2026-10-20).

Held-out corpus: measured before the fixes below, 13/18 faults detected and
9/13 categories right; every file here was one of the misses or misnames.
"""
import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from logcrux.analysis.anomaly import analyze_uncaught_exception
from logcrux.cli import app
from logcrux.ingest.normalize import normalize
from logcrux.models import ParsedEvent, Severity

runner = CliRunner()
FIXTURES = Path(__file__).parent.parent / "fixtures"


def _run(name: str) -> dict[str, Any]:
    result = runner.invoke(app, [str(FIXTURES / name), "--no-baseline", "--json"])
    assert result.exit_code in (0, 3, 4), result.output
    data: dict[str, Any] = json.loads(result.output)
    return data


@pytest.mark.parametrize("name,category,kind", [
    # nginx image: access lines on stdout, error lines on stderr, entrypoint banner.
    ("nginx_mixed_docker_502.log", "http_overload", None),
    ("nginx_docker_timestamps_502.log", "http_overload", None),
    ("httpd_mixed_docker_503.log", "http_overload", None),
    ("haproxy_raw_docker_down.log", "http_overload", "backend_down"),
    ("python_uncaught_docker.log", "service_crash", "uncaught_exception"),
    ("python_startup_crash_docker.log", "service_crash", "uncaught_exception"),
    ("node_uncaught_docker.log", "service_crash", "uncaught_exception"),
    ("node_heap_oom_docker.log", "oom", "oom_event"),
    ("java_oom_docker.log", "oom", "oom_event"),
    ("postgres_docker_initdb_crash.log", "service_crash", "service_crash"),
    ("mongo_authfail_docker.log", "auth_brute_force", "auth_failure_cluster"),
])
def test_docker_capture_verdict(name, category, kind):
    data = _run(name)
    assert data["level"] in ("WARNING", "CRITICAL"), data["title"]
    assert data["category"] == category, (data["title"], data["findings"])
    if kind:
        assert data["findings"][0]["kind"] == kind, [f["kind"] for f in data["findings"]]


def test_mixed_nginx_stream_keeps_http_status():
    data = _run("nginx_mixed_docker_502.log")
    assert "nginx-access" in data["parser_format"]
    subs = {(s["label"], s["value"]) for f in data["findings"] for s in f["subjects"]}
    assert ("status", "502") in subs


def test_haproxy_raw_stdout_parses_and_names_the_server():
    data = _run("haproxy_raw_docker_down.log")
    assert data["parser_format"] == "haproxy"
    assert data["coverage"]["ratio"] == 1.0
    f = data["findings"][0]
    assert ("server", "be/app1") in {(s["label"], s["value"]) for s in f["subjects"]}


def test_rabbitmq_with_utc_offset_and_colour_parses():
    data = _run("rabbitmq_tz_docker.log")
    # The image's startup banner is not RabbitMQ's format: kept as generic.
    assert data["parser_format"].split("+")[0] == "rabbitmq", data["parser_format"]
    assert data["level"] == "CLEAN"


def test_uncaught_exception_detail_is_the_exception_line():
    data = _run("python_startup_crash_docker.log")
    f = data["findings"][0]
    assert f["detail"].startswith("FileNotFoundError: [Errno 2]")
    assert f["evidence"][0]["line"] == 6


def _ev(i: int, raw: str) -> ParsedEvent:
    return ParsedEvent(timestamp=None, severity=Severity.UNKNOWN, source="generic",
                       message=raw, raw=raw, line_number=i)


def test_logged_exception_is_not_a_crash():
    # log.exception() writes its record, then the traceback — the process lives on.
    lines = ["2026-10-19 18:47:22,809 ERROR orders: lookup failed",
             "Traceback (most recent call last):",
             '  File "/app.py", line 3, in <module>',
             "KeyError: 'id'"]
    assert analyze_uncaught_exception([_ev(i, t) for i, t in enumerate(lines, 1)]) == []


def test_traceback_followed_by_more_logging_is_not_terminal():
    lines = ["starting", "Traceback (most recent call last):", '  File "x.py", line 1',
             "ValueError: bad", "INFO retrying", "INFO ok", "INFO serving"]
    assert analyze_uncaught_exception([_ev(i, t) for i, t in enumerate(lines, 1)]) == []


def test_go_panic_is_a_crash():
    lines = ["listening on :8080", "panic: runtime error: index out of range [3] with length 3",
             "", "goroutine 1 [running]:", "main.main()", "\t/app/main.go:9 +0x1d",
             "exit status 2"]
    sig = analyze_uncaught_exception([_ev(i, t) for i, t in enumerate(lines, 1) if t])
    assert sig and sig[0].representative_events[0].message.startswith("panic: runtime error")


def test_normalize_strips_transport_wrappers():
    lines = ["2026-10-19T18:46:59.191271967Z <14>\x1b[32mhello\x1b[0m\n"] * 5
    out, done = normalize(lines)
    assert out[0] == "hello\n"
    assert set(done) == {"ANSI colour codes", "docker/kubectl --timestamps column",
                         "syslog <PRI> prefix"}
    kube = ["[pod/web-7d9/nginx] 10.0.0.1 - - GET / 200\n"] * 3
    assert normalize(kube)[0][0].startswith("10.0.0.1")


def test_normalize_leaves_a_minority_alone():
    lines = ["2026-10-19T18:46:59Z starts with a timestamp\n"] + ["plain line\n"] * 9
    out, done = normalize(lines)
    assert out == lines and done == []


def test_backend_that_comes_up_is_not_down():
    lines = ["Oct 13 08:38:24 h haproxy[1]: Server be/s1 is DOWN, reason: Layer4 connection problem",
             "Oct 13 08:38:24 h haproxy[1]: backend be has no server available!",
             "Oct 13 08:38:26 h haproxy[1]: Server be/s1 is UP, reason: Layer4 check passed"]
    from logcrux.analysis.anomaly import analyze_backend_down
    from logcrux.parsers.haproxy import HAProxyParser
    p = HAProxyParser()
    evs = [e for i, t in enumerate(lines, 1) if (e := p.parse_line(t, i)) is not None]
    assert len(evs) == 3
    assert analyze_backend_down(evs) == []
    assert analyze_backend_down(evs[:2])  # still down at the end: reported


def test_jvm_oom_flags_are_not_an_oom():
    from logcrux.analysis.anomaly import _is_oom_event
    flags = _ev(1, "JVM arguments [-XX:+HeapDumpOnOutOfMemoryError, -XX:+ExitOnOutOfMemoryError]")
    real = _ev(2, 'Exception in thread "main" java.lang.OutOfMemoryError: Java heap space')
    assert not _is_oom_event(flags) and _is_oom_event(real)


def test_cri_format_keeps_its_timestamp():
    lines = ["2026-06-20T10:23:45.123456789Z stdout F hello\n"] * 5
    assert normalize(lines)[0] == lines


def test_gunicorn_worker_timeout_is_a_crash_not_an_oom():
    data = _run("gunicorn_worker_timeout_docker.log")
    assert data["category"] == "service_crash", data["title"]
    assert "WORKER TIMEOUT" in data["findings"][0]["evidence"][0]["text"]
    assert "timeout" in data["remediation"]


def test_docker_inspect_oomkilled_flag():
    # Every `docker inspect` carries "OOMKilled": true|false; false must not alarm.
    assert _run("docker_inspect_ok.json.log")["level"] == "CLEAN"
    assert _run("docker_inspect_oomkilled.json.log")["category"] == "oom"


@pytest.mark.parametrize("name,text", [
    ("go_panic_docker.log", "index out of range"),       # real go 1.23 binary
    ("rust_panic_docker.log", "cannot read /etc/ingest.toml"),  # real rust 1.x binary
])
def test_native_runtime_panics(name, text):
    data = _run(name)
    f = next(x for x in data["findings"] if x["kind"] == "uncaught_exception")
    assert text in f["detail"] and data["category"] == "service_crash"


def test_rust_worker_thread_panic_is_not_a_process_death():
    lines = ["serving", "thread 'tokio-runtime-worker' panicked at src/x.rs:1:1:", "boom"]
    evs = [ParsedEvent(timestamp=None, severity=Severity.UNKNOWN, source="g", message=t,
                       raw=t, line_number=i) for i, t in enumerate(lines, 1)]
    assert analyze_uncaught_exception(evs) == []
