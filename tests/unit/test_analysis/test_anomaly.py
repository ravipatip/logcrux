from datetime import UTC, datetime, timedelta

import pytest

from logcrux.analysis.anomaly import (
    _is_oom_event,
    _is_service_crash,
    analyze_auth_failures,
)
from logcrux.models import ParsedEvent, Severity


def _ev(msg: str, sev: Severity) -> ParsedEvent:
    return ParsedEvent(
        timestamp=None, severity=sev, source="x", message=msg, raw=msg, line_number=1
    )


@pytest.mark.parametrize(
    "msg,sev,expected",
    [
        # "failed to start" is an ambiguous weak keyword: a real systemd unit
        # failure is logged at ERROR (-> crash); the same phrase in benign INFO
        # chatter ("failed to start optional upload, continuing") is not.
        ("Failed to start nginx.service", Severity.ERROR, True),
        ("Failed to start optional telemetry upload, continuing", Severity.INFO, False),
        # Unambiguous crash tokens count at any severity (a kernel segfault line
        # has no level field and parses as INFO but is still a real crash).
        ("app[123]: segfault at 0 ip 00007f", Severity.INFO, True),
        ("main process exited, code=killed, status=11/SEGV", Severity.INFO, True),
    ],
)
def test_service_crash_keyword_severity_gate(msg, sev, expected):
    assert _is_service_crash(_ev(msg, sev)) is expected


@pytest.mark.parametrize(
    "msg,expected",
    [
        # Kubernetes' container-termination reason — the most common k8s OOM
        # signal. One word, so it doesn't match the kernel's "oom-kill".
        ("Last State: Terminated Reason: OOMKilled Exit Code: 137", True),
        ("container was OOMKilled", True),
        ("Memory cgroup out of memory: Killed process 1234", True),
        ("oom-killer: gfp_mask=0x100", True),
        ("processing request, memory usage nominal", False),
    ],
)
def test_oom_detects_k8s_oomkilled(msg, expected):
    assert _is_oom_event(_ev(msg, Severity.ERROR)) is expected


@pytest.mark.parametrize(
    "msg",
    [
        "Back-off restarting failed container payment in pod payment-7d9_default",
        'Error syncing pod reason="CrashLoopBackOff"',
    ],
)
def test_service_crash_detects_k8s_crashloop(msg):
    # Unambiguous k8s crash phrases count at any severity (kubelet often logs the
    # back-off as a plain INFO/Warning event).
    assert _is_service_crash(_ev(msg, Severity.INFO)) is True


def _auth_fail(minutes: int, ip: str = "198.51.100.42") -> ParsedEvent:
    ts = datetime(2026, 6, 16, 3, 41, 0, tzinfo=UTC) + timedelta(minutes=minutes)
    return ParsedEvent(
        timestamp=ts, severity=Severity.WARNING, source="sshd",
        message="Failed password for root from 198.51.100.42 port 54001 ssh2",
        raw="raw", line_number=1,
        extra={"client_ip": ip, "user": "root"},
    )


def test_no_signal_below_threshold():
    events = [_auth_fail(0) for _ in range(10)]
    signals = analyze_auth_failures(events, failure_threshold=50)
    assert signals == []


def test_signal_above_threshold():
    events = [_auth_fail(i % 3) for i in range(60)]
    signals = analyze_auth_failures(events, failure_threshold=50)
    assert len(signals) == 1
    sig = signals[0]
    assert sig.kind == "auth_failure_cluster"
    assert sig.event_count == 60
    assert sig.severity == Severity.WARNING
    # representative_events must be populated so _inference_supported can check
    # them for lexical evidence before trusting an AI-supplied category.
    assert len(sig.representative_events) > 0
    assert sig.representative_events[0].extra.get("client_ip") == "198.51.100.42"


def test_empty_events():
    assert analyze_auth_failures([], failure_threshold=50) == []


def test_thinly_spread_failures_not_a_brute_force():
    # 60 failures spread one-per-hour over 60 hours: above the count threshold
    # but never concentrated. A brute force is temporally concentrated, so this
    # background noise must NOT raise a cluster (regression: previously every
    # auth failure in the file was counted regardless of how far apart).
    events = [_auth_fail(i * 60) for i in range(60)]
    assert analyze_auth_failures(events, failure_threshold=50) == []


def test_cluster_window_anchored_to_dense_region():
    # 10 stray failures spread over hours plus a 60-strong burst in 2 minutes.
    # The signal must report the *dense* window, not the whole multi-hour span.
    spread = [_auth_fail(i * 60) for i in range(10)]
    burst = [_auth_fail(1000 + (i % 2)) for i in range(60)]
    signals = analyze_auth_failures(spread + burst, failure_threshold=50)
    assert len(signals) == 1
    sig = signals[0]
    assert sig.event_count == 60
    assert sig.window.duration_seconds <= 120


def test_untimed_failures_fall_back_to_count():
    # No timestamps to anchor a window (e.g. timestamp-less app stdout): a count
    # at/above threshold should still surface.
    events = [
        ParsedEvent(
            timestamp=None, severity=Severity.WARNING, source="sshd",
            message="authentication failure; logname= uid=0",
            raw="raw", line_number=i,
        )
        for i in range(60)
    ]
    signals = analyze_auth_failures(events, failure_threshold=50)
    assert len(signals) == 1
    assert signals[0].event_count == 60


@pytest.mark.parametrize(
    "msg,sev,expected",
    [
        # Go/Rust runtime panics announce a fatal crash with "panic:" — but only
        # on a WARNING-or-worse line, so prose mentions in INFO chatter don't count.
        ("panic: runtime error: invalid memory address or nil pointer dereference", Severity.CRITICAL, True),
        ("FATAL: panic: could not initialize database pool", Severity.ERROR, True),
        ("user manual says: don't panic: this message is harmless", Severity.INFO, False),
        # A kernel panic is unambiguous at any severity.
        ("Kernel panic - not syncing: Attempted to kill init!", Severity.INFO, True),
    ],
)
def test_service_crash_detects_panics(msg, sev, expected):
    assert _is_service_crash(_ev(msg, sev)) is expected
