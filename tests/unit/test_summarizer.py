from datetime import UTC, datetime

import pytest

from logcrux.models import (
    AnalysisResult,
    AnomalySignal,
    IncidentCategory,
    InferenceResult,
    ParsedEvent,
    Severity,
    TimeWindow,
)
from logcrux.summarizer.engine import summarize


def _ts():
    return datetime(2026, 6, 16, 3, 41, 0, tzinfo=UTC)


def _empty_result() -> AnalysisResult:
    return AnalysisResult(
        log_path="/var/log/messages", parser_format="syslog",
        parsed_count=100, skipped_count=0, time_range=None, signals=[],
    )


def _result_with_auth_signal() -> AnalysisResult:
    ts = _ts()
    return AnalysisResult(
        log_path="/var/log/secure", parser_format="secure",
        parsed_count=200, skipped_count=0,
        time_range=TimeWindow(start=ts, end=ts, duration_seconds=60),
        signals=[AnomalySignal(
            kind="auth_failure_cluster",
            window=TimeWindow(start=ts, end=ts, duration_seconds=60),
            event_count=60, baseline_count=None,
            severity=Severity.WARNING,
            representative_events=[ParsedEvent(
                timestamp=ts, severity=Severity.WARNING, source="sshd",
                message="Failed password for root", raw="raw", line_number=1,
            )],
        )],
    )


def _inference(category: IncidentCategory, confidence: float) -> InferenceResult:
    return InferenceResult(
        category=category, confidence=confidence,
        correlated_signals=["auth_failure_cluster"],
        grouped_event_clusters=[[0]],
    )


def test_clean_log_returns_clean_level():
    summary = summarize(_empty_result(), None, elapsed_seconds=0.5)
    assert summary.level == "CLEAN"
    assert summary.category == IncidentCategory.UNKNOWN
    # A CLEAN verdict is a definite statement ("no anomalies found"), not a
    # low-confidence guess — it must not surface as 0.0 confidence.
    assert summary.confidence == pytest.approx(1.0)


def test_signals_without_inference_returns_warning():
    summary = summarize(_result_with_auth_signal(), None, elapsed_seconds=1.0)
    assert summary.level == "WARNING"
    assert len(summary.findings) >= 1


def test_high_confidence_critical_category():
    # Use a generic "error_burst" signal so the deterministic signal-to-category
    # mapping doesn't fire; CRITICAL level and OOM category must come from the AI.
    # representative_events must contain OOM keywords so _inference_supported passes.
    ts = _ts()
    result = AnalysisResult(
        log_path="/var/log/messages", parser_format="syslog",
        parsed_count=100, skipped_count=0,
        time_range=TimeWindow(start=ts, end=ts, duration_seconds=0),
        signals=[AnomalySignal(
            kind="error_burst",
            window=TimeWindow(start=ts, end=ts, duration_seconds=0),
            event_count=3, baseline_count=None,
            severity=Severity.ERROR,
            representative_events=[ParsedEvent(
                timestamp=ts, severity=Severity.ERROR, source="kernel",
                message="Out of memory: Killed process 12345 (java)",
                raw="raw", line_number=1,
            )],
        )],
    )
    inference = _inference(IncidentCategory.OOM, 0.94)
    summary = summarize(result, inference, elapsed_seconds=3.2)
    # CRITICAL comes from OOM being in _CRITICAL_CATEGORIES (via AI inference)
    assert summary.level == "CRITICAL"
    assert summary.category == IncidentCategory.OOM
    assert summary.confidence == pytest.approx(0.94)
    assert summary.remediation is not None


def test_zero_confidence_inference_ignored():
    # confidence=0.0 makes _inference_usable return False, so the AI category
    # is not applied. Level and category come from the deterministic signal alone.
    summary = summarize(
        _result_with_auth_signal(),
        _inference(IncidentCategory.AUTH_BRUTE_FORCE, 0.0),
        elapsed_seconds=1.0,
    )
    assert summary.level == "WARNING"
    # Category still resolves via auth_failure_cluster signal mapping, not AI
    assert summary.category == IncidentCategory.AUTH_BRUTE_FORCE


def test_summary_has_uuid_id():
    summary = summarize(_empty_result(), None, elapsed_seconds=0.1)
    assert len(summary.analysis_id) == 36


def _result_with_generic_burst(message: str) -> AnalysisResult:
    ts = _ts()
    return AnalysisResult(
        log_path="/var/log/install.log", parser_format="generic",
        parsed_count=60000, skipped_count=0,
        time_range=TimeWindow(start=ts, end=ts, duration_seconds=300),
        signals=[AnomalySignal(
            kind="error_burst",
            window=TimeWindow(start=ts, end=ts, duration_seconds=300),
            event_count=60, baseline_count=None,
            severity=Severity.ERROR,
            representative_events=[ParsedEvent(
                timestamp=ts, severity=Severity.ERROR, source="generic",
                message=message, raw=message, line_number=1,
            )],
        )],
    )


def test_ai_category_rejected_without_lexical_evidence():
    # A generic error burst whose events have nothing to do with auth must not be
    # labelled "Auth Brute Force" just because the 7-way classifier guessed it.
    # "authoring" must NOT count as evidence for the auth category (whole-word).
    result = _result_with_generic_burst(
        "Package Authoring: error running installation-check script"
    )
    summary = summarize(
        result, _inference(IncidentCategory.AUTH_BRUTE_FORCE, 0.84), elapsed_seconds=1.0,
    )
    assert summary.category == IncidentCategory.UNKNOWN
    assert summary.title == "Error burst detected"
    assert summary.confidence == pytest.approx(0.5)


def test_apparmor_denial_not_labelled_auth_brute_force():
    # A burst of AppArmor MAC-policy denials must NOT surface as "Auth Brute
    # Force" just because the line contains "DENIED". apparmor="DENIED" is an
    # access-control event, not a credential attack; bare "denied" was dropped
    # from the auth evidence tokens so the falsely-confident classifier guess is
    # rejected and degrades to a generic burst instead of a wrong root cause.
    result = _result_with_generic_burst(
        'apparmor="DENIED" operation="open" profile="/usr/sbin/mysqld" '
        'name="/etc/shadow" pid=1234 comm="mysqld"'
    )
    summary = summarize(
        result, _inference(IncidentCategory.AUTH_BRUTE_FORCE, 0.96), elapsed_seconds=1.0,
    )
    assert summary.category == IncidentCategory.UNKNOWN
    assert summary.title == "Error burst detected"


def test_ciod_login_not_labelled_auth_brute_force():
    # A Blue Gene RAS kernel/app error burst must NOT surface as "Auth Brute
    # Force" just because a line contains "LOGIN". `ciod: LOGIN chdir() failed`
    # is a compute-node I/O daemon job-startup error, not a credential attack;
    # bare "login"/"logon" were dropped from the auth evidence tokens so the
    # falsely-confident classifier guess degrades to a generic burst.
    result = _result_with_generic_burst(
        "RAS APP FATAL ciod: LOGIN chdir(/p/gb2/glosli/8M) failed: "
        "No such file or directory"
    )
    summary = summarize(
        result, _inference(IncidentCategory.AUTH_BRUTE_FORCE, 0.73), elapsed_seconds=1.0,
    )
    assert summary.category == IncidentCategory.UNKNOWN
    assert summary.title == "Error burst detected"


def test_real_auth_denial_still_labelled():
    # The qualified "permission denied" / "access denied" phrases must still
    # count, so a genuine SSH/sudo auth denial keeps its label.
    result = _result_with_generic_burst(
        "sudo: pam_unix(sudo:auth): permission denied for user bob"
    )
    summary = summarize(
        result, _inference(IncidentCategory.AUTH_BRUTE_FORCE, 0.84), elapsed_seconds=1.0,
    )
    assert summary.category == IncidentCategory.AUTH_BRUTE_FORCE


def test_rate_spike_finding_headline():
    ts = _ts()
    result = AnalysisResult(
        log_path="/var/log/syslog", parser_format="syslog",
        parsed_count=50, skipped_count=0,
        time_range=TimeWindow(start=ts, end=ts, duration_seconds=300),
        signals=[AnomalySignal(
            kind="rate_spike",
            window=TimeWindow(start=ts, end=ts, duration_seconds=300),
            event_count=40, baseline_count=5.0,
            severity=Severity.WARNING, representative_events=[],
        )],
    )
    summary = summarize(result, None, elapsed_seconds=1.0)
    assert summary.findings[0].headline == "Error rate spike vs baseline"
    detail = summary.findings[0].detail
    assert detail is not None and "baseline" in detail


def test_proxy_denial_remediation_is_squid_specific():
    ts = _ts()
    result = AnalysisResult(
        log_path="/var/log/squid.log", parser_format="squid",
        parsed_count=50, skipped_count=0,
        time_range=TimeWindow(start=ts, end=ts, duration_seconds=60),
        signals=[AnomalySignal(
            kind="proxy_denial_cluster",
            window=TimeWindow(start=ts, end=ts, duration_seconds=60),
            event_count=12, baseline_count=None,
            severity=Severity.WARNING, representative_events=[],
        )],
    )
    summary = summarize(result, None, elapsed_seconds=1.0)
    assert summary.remediation is not None
    assert "squid" in summary.remediation.lower() or "acl" in summary.remediation.lower()


def test_ai_category_trusted_with_lexical_evidence():
    # The same path keeps a real AI label when the events actually support it.
    result = _result_with_generic_burst(
        "Failed password for invalid user admin from 10.0.0.1 port 22 ssh2"
    )
    summary = summarize(
        result, _inference(IncidentCategory.AUTH_BRUTE_FORCE, 0.84), elapsed_seconds=1.0,
    )
    assert summary.category == IncidentCategory.AUTH_BRUTE_FORCE
    assert summary.title == "Auth Brute Force"


def test_signal_detected_category_confidence_without_inference():
    # When the category comes from a deterministic keyword signal (auth_failure_cluster
    # maps to AUTH_BRUTE_FORCE) and inference is disabled, confidence should be high
    # (0.9), not 0.0. 0.0 would imply the detection is unreliable even though we
    # matched an explicit keyword cluster.
    summary = summarize(_result_with_auth_signal(), None, elapsed_seconds=1.0)
    assert summary.category == IncidentCategory.AUTH_BRUTE_FORCE
    assert summary.confidence >= 0.9


def test_deterministic_signal_category_beats_ai_category():
    # Category precedence: a specific deterministic signal (oom_event) is a
    # high-precision keyword match and must name the incident even when the AI
    # classifier confidently says something else. The event message carries
    # disk-full evidence too, so the AI label passes the lexical-evidence gate
    # and only the precedence rule keeps OOM on top.
    ts = _ts()
    result = AnalysisResult(
        log_path="/var/log/kern.log", parser_format="kernel",
        parsed_count=500, skipped_count=0,
        time_range=TimeWindow(start=ts, end=ts, duration_seconds=60),
        signals=[AnomalySignal(
            kind="oom_event",
            window=TimeWindow(start=ts, end=ts, duration_seconds=60),
            event_count=3, baseline_count=None,
            severity=Severity.CRITICAL,
            representative_events=[ParsedEvent(
                timestamp=ts, severity=Severity.CRITICAL, source="kernel",
                message="Out of memory: Killed process 4321 (java); no space left on device",
                raw="raw", line_number=1,
            )],
        )],
    )
    summary = summarize(
        result, _inference(IncidentCategory.DISK_FULL, 0.95), elapsed_seconds=1.0,
    )
    assert summary.category == IncidentCategory.OOM
