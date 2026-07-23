from datetime import UTC, datetime, timedelta

import pytest

from logcrux.analysis.error_rate import analyze_error_rate
from logcrux.models import ParsedEvent, Severity


def _make_event(minutes_offset: int, severity: Severity) -> ParsedEvent:
    ts = datetime(2026, 6, 16, 3, 0, 0, tzinfo=UTC) + timedelta(minutes=minutes_offset)
    return ParsedEvent(
        timestamp=ts, severity=severity, source="test",
        message="test message", raw="raw", line_number=1,
    )


def test_no_signals_on_clean_log():
    events = [_make_event(i, Severity.INFO) for i in range(10)]
    signals = analyze_error_rate(events, timedelta(minutes=5), None, spike_factor=3.0)
    assert signals == []


def test_error_burst_detected():
    events = (
        [_make_event(0, Severity.INFO)] * 5
        + [_make_event(1, Severity.ERROR)] * 30
    )
    signals = analyze_error_rate(events, timedelta(minutes=5), None, spike_factor=3.0)
    assert len(signals) >= 1
    assert signals[0].kind == "error_burst"


def test_spike_against_baseline():
    events = [_make_event(i % 5, Severity.ERROR) for i in range(20)]
    signals = analyze_error_rate(
        events,
        timedelta(minutes=5),
        baseline_avg_errors_per_hour=2.0,
        spike_factor=3.0,
    )
    rate_signals = [s for s in signals if s.kind == "rate_spike"]
    assert len(rate_signals) == 1
    sig = rate_signals[0]
    assert sig.baseline_count == pytest.approx(2.0)  # passed-in baseline preserved
    assert sig.event_count > 0
    assert sig.severity in (Severity.ERROR, Severity.WARNING)


def test_few_errors_do_not_spike_despite_short_window():
    # 2 errors over a few seconds extrapolate to a huge errors/hour figure, but
    # too few absolute errors to be a meaningful spike — must not flag.
    base = datetime(2026, 6, 16, 3, 0, 0, tzinfo=UTC)
    events = [
        ParsedEvent(
            timestamp=base + timedelta(seconds=s), severity=Severity.ERROR,
            source="test", message="boom", raw="raw", line_number=1,
        )
        for s in (0, 6)
    ]
    signals = analyze_error_rate(
        events, timedelta(minutes=5),
        baseline_avg_errors_per_hour=2.0, spike_factor=3.0,
    )
    assert [s for s in signals if s.kind == "rate_spike"] == []


def test_no_spike_below_threshold():
    # 3 errors spread over 60 minutes → rate = 3/hour
    # threshold = 10.0 * 3.0 = 30/hour → no spike
    events = [_make_event(i * 20, Severity.ERROR) for i in range(3)]
    signals = analyze_error_rate(
        events,
        timedelta(minutes=5),
        baseline_avg_errors_per_hour=10.0,
        spike_factor=3.0,
    )
    assert signals == []


def test_untimed_error_cluster_detected():
    # Logs without timestamps (app/docker stdout) that are largely errors must
    # still surface an incident — the time-based paths cannot run here.
    events = (
        [ParsedEvent(timestamp=None, severity=Severity.INFO, source="app",
                     message="info", raw="info", line_number=i) for i in range(10)]
        + [ParsedEvent(timestamp=None, severity=Severity.ERROR, source="app",
                       message="boom", raw="boom", line_number=i) for i in range(20)]
    )
    signals = analyze_error_rate(events, timedelta(minutes=5), None)
    assert len(signals) == 1
    assert signals[0].kind == "error_burst"
    assert signals[0].event_count == 20


def test_untimed_few_errors_stay_clean():
    # A large, healthy log with only a handful of stray errors must not fire.
    events = (
        [ParsedEvent(timestamp=None, severity=Severity.INFO, source="app",
                     message="info", raw="info", line_number=i) for i in range(200)]
        + [ParsedEvent(timestamp=None, severity=Severity.ERROR, source="app",
                       message="boom", raw="boom", line_number=i) for i in range(5)]
    )
    assert analyze_error_rate(events, timedelta(minutes=5), None) == []
