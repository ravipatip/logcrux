"""Comprehensive tests for edge cases and multiple burst scenarios."""

from datetime import UTC, datetime, timedelta

from logcrux.analysis.burst import analyze_burst
from logcrux.analysis.error_rate import analyze_error_rate
from logcrux.models import ParsedEvent, Severity


def _ev(
    minutes: float,
    sev: Severity = Severity.INFO,
    message: str = "test",
) -> ParsedEvent:
    """Create a test event at specified time offset."""
    ts = datetime(2026, 6, 16, 3, 0, 0, tzinfo=UTC) + timedelta(minutes=minutes)
    return ParsedEvent(
        timestamp=ts,
        severity=sev,
        source="test",
        message=message,
        raw="raw",
        line_number=1,
    )


def test_burst_detects_spike_over_quiet_baseline():
    """A dense spike standing out against a quiet baseline is flagged.

    analyze_burst measures each event's forward-window count against the
    *average* window count, so detection requires contrast: a cluster that is
    several times denser than the surrounding traffic.
    """
    baseline = [_ev(i) for i in range(60)]  # 1/min for an hour — low density
    # A spike of error-level events: a burst of benign INFO volume is not an
    # incident (see test_burst.py::test_info_only_burst_is_not_an_incident).
    spike = [_ev(30 + i * (1 / 30), Severity.ERROR) for i in range(30)]  # 30 in ~1 min
    signals = analyze_burst(baseline + spike, timedelta(minutes=5), burst_multiplier=2.0)

    assert len(signals) == 1
    assert signals[0].kind == "error_burst"
    # The window count covers the spike plus any baseline events that overlap it.
    assert signals[0].event_count >= 30


def test_burst_ignores_uniform_series_without_contrast():
    """A uniformly dense series produces no burst — there is no spike.

    Because the baseline is the average of the same windows, an evenly busy
    stretch never exceeds ``burst_multiplier * avg``. This is by design: a
    sustained steady rate is not an anomaly relative to itself. (A genuine
    rate increase vs a stored baseline is caught by analyze_error_rate.)
    """
    events = [_ev(i * 0.1) for i in range(40)]  # 40 events evenly over 4 minutes
    signals = analyze_burst(events, timedelta(minutes=5), burst_multiplier=2.0)
    assert signals == []


def test_error_rate_anchors_burst_to_densest_window():
    """analyze_error_rate (no baseline) reports the *densest* window of errors.

    Two error clusters more than one window apart surface as an ``error_burst``
    anchored to a single dense window — not lumped into one giant span from the
    first to the last error. Lumping across the whole file is what made a
    months-long log that merely mentions "error" report a single absurd burst.
    """
    errors1 = [_ev(i * 0.1, Severity.ERROR, "error") for i in range(15)]
    errors2 = [_ev(5.5 + i * 0.1, Severity.ERROR, "error") for i in range(15)]
    signals = analyze_error_rate(errors1 + errors2, timedelta(minutes=5), None)

    assert len(signals) == 1
    assert signals[0].kind == "error_burst"
    # The densest 5-minute window holds one cluster (15), not both (30); the
    # window does not stretch across the quiet gap between the clusters.
    assert signals[0].event_count == 15
    assert signals[0].window.duration_seconds < timedelta(minutes=5).total_seconds()


def test_error_rate_ignores_errors_spread_thinly_over_long_span():
    """Errors scattered across a long span (never concentrated) are not a burst.

    This is the macOS-install.log case: thousands of benign "error" mentions
    over months must not collapse into one giant false "burst".
    """
    # 30 errors spread one every 10 minutes -> at most 1 per 5-min window.
    errors = [_ev(i * 10, Severity.ERROR, "error") for i in range(30)]
    signals = analyze_error_rate(errors, timedelta(minutes=5), None)
    assert signals == []


def test_error_rate_detects_10_plus_errors():
    """Test that error_rate detects when there are 10+ error events."""
    events = [_ev(i * 0.1, Severity.ERROR, "error") for i in range(12)]
    signals = analyze_error_rate(events, timedelta(minutes=5), None)
    assert len(signals) == 1
    assert signals[0].kind == "error_burst"
    assert signals[0].event_count == 12


def test_burst_counts_events_of_every_severity():
    """Burst detection is severity-agnostic — it counts event frequency.

    A spike made of mixed critical/error/warning lines (over a quiet baseline)
    is flagged, and the count includes all severities, not just errors.
    """
    baseline = [_ev(i) for i in range(60)]
    spike = [
        _ev(30 + i * (1 / 30), Severity.CRITICAL if i < 10 else Severity.WARNING)
        for i in range(30)
    ]
    signals = analyze_burst(baseline + spike, timedelta(minutes=5), burst_multiplier=2.0)

    assert len(signals) == 1
    assert signals[0].event_count >= 30


def test_timestamp_edge_case_none_timestamps():
    """Test handling of events with no timestamps."""
    events = [
        ParsedEvent(
            timestamp=None,
            severity=Severity.ERROR,
            source="test",
            message="no timestamp",
            raw="raw",
            line_number=1,
        )
        for _ in range(15)
    ]
    signals = analyze_burst(events, timedelta(minutes=5))
    assert signals == []
