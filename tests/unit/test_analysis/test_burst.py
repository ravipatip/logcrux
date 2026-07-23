from datetime import UTC, datetime, timedelta

from logcrux.analysis.burst import analyze_burst
from logcrux.models import ParsedEvent, Severity


def _ev(minutes: float, sev: Severity = Severity.ERROR) -> ParsedEvent:
    ts = datetime(2026, 6, 16, 3, 0, 0, tzinfo=UTC) + timedelta(minutes=minutes)
    return ParsedEvent(timestamp=ts, severity=sev, source="test",
                       message="msg", raw="raw", line_number=1)


def test_no_burst_for_even_distribution():
    events = [_ev(i * 6) for i in range(10)]
    signals = analyze_burst(events, timedelta(minutes=5), burst_multiplier=3.0)
    assert signals == []


def test_burst_detected_for_spike():
    # Sparse background: 1 event every 10 minutes over 200 minutes (21 events)
    # Dense burst: 30 error events packed into 1 minute at t=300
    background = [_ev(i * 10) for i in range(21)]
    burst = [_ev(300 + i * 0.02) for i in range(30)]
    events = background + burst
    signals = analyze_burst(events, timedelta(minutes=5), burst_multiplier=3.0)
    assert len(signals) >= 1
    assert signals[0].kind == "error_burst"


def test_info_only_burst_is_not_an_incident():
    # A spike in *volume* of benign INFO lines (e.g. install progress) is not an
    # incident. analyze_error_rate handles genuine error bursts; a burst with no
    # warning-or-worse events must produce nothing — flagging it caused confident
    # false positives (a benign install log mislabeled "Auth Brute Force").
    background = [_ev(i * 10, Severity.INFO) for i in range(21)]
    burst = [_ev(300 + i * 0.02, Severity.INFO) for i in range(30)]
    signals = analyze_burst(background + burst, timedelta(minutes=5), burst_multiplier=3.0)
    assert signals == []


def test_burst_reports_peak_severity():
    # A burst dominated by INFO but carrying enough errors is an incident, and is
    # reported at the highest severity present, counting only the significant
    # events.
    background = [_ev(i * 10, Severity.INFO) for i in range(21)]
    burst = [_ev(300 + i * 0.02, Severity.INFO) for i in range(30)]
    errors = [_ev(300 + i * 0.02, Severity.CRITICAL) for i in range(12)]
    signals = analyze_burst(background + burst + errors, timedelta(minutes=5),
                            burst_multiplier=3.0)
    assert len(signals) == 1
    assert signals[0].severity == Severity.CRITICAL
    assert signals[0].event_count == 12
    assert all(e.severity == Severity.CRITICAL for e in signals[0].representative_events)


def test_two_separated_bursts_yield_two_signals():
    # A sparse baseline with two dense clusters an hour apart must surface as
    # two distinct incidents, not collapse into the first one.
    background = [_ev(i * 2) for i in range(60)]  # 1 event / 2 min for 2 hours
    burst1 = [_ev(30 + i * 0.02) for i in range(30)]  # 30 events at t=30
    burst2 = [_ev(90 + i * 0.02) for i in range(30)]  # 30 events at t=90
    signals = analyze_burst(background + burst1 + burst2, timedelta(minutes=5),
                            burst_multiplier=3.0)
    assert len(signals) == 2
    assert all(s.kind == "error_burst" for s in signals)
    # Signals are time-ordered and do not overlap: first burst ends before the
    # second begins.
    assert signals[0].window.end < signals[1].window.start
    assert all(s.event_count >= 30 for s in signals)


def test_sustained_burst_spanning_windows_is_one_signal():
    # A single sustained burst longer than the window must stay one signal, not
    # fragment into one-per-window. It remains a minority of overall traffic so
    # the median baseline still reflects the quiet level.
    background = [_ev(i) for i in range(200)]  # 1 / min for 200 min
    sustained = [_ev(100 + i * (11 / 60)) for i in range(60)]  # 60 events / 11 min
    signals = analyze_burst(background + sustained, timedelta(minutes=5),
                            burst_multiplier=3.0)
    assert len(signals) == 1
    # The burst spans more than two 5-minute windows yet is reported once.
    assert (signals[0].window.end - signals[0].window.start) > timedelta(minutes=10)


def test_no_events_returns_empty():
    assert analyze_burst([], timedelta(minutes=5), burst_multiplier=3.0) == []


def test_baseline_count_uses_significant_events_not_all_events():
    # Regression: burst.py used to store median(all-event window counts) as
    # baseline_count but compare it against event_count=len(significant-only).
    # In INFO-heavy logs this produced ratios < 1× even for genuine bursts
    # (e.g. 59 significant events / 75 all-event baseline = 0.8×).
    # baseline_count must now use significant-event window counts so the ratio
    # is always >= 1 for any reported burst.
    #
    # Dense INFO background with scattered errors (2 errors per 5-min window) —
    # errors exist in the background so sig_baseline > 0 and a ratio is shown.
    # The burst has 50 errors packed into 1 minute, well above 3× the threshold.
    # Old code: baseline ≈ 52 (all events/window), event_count = 50 → ratio 0.96×
    # New code: sig_baseline ≈ 2 (sig events/window),  event_count = 50 → ratio 25×
    background_info = [_ev(i * 0.1, Severity.INFO) for i in range(600)]  # t=0..60, 50/window
    # 2 warning events per 5-min window spread across background
    background_warn = [_ev(i * 2.5, Severity.WARNING) for i in range(25)]  # t=0..60
    # all-event baseline ≈ 52/window → threshold = 3 × 52 = 156; burst needs > 156
    burst_errors = [_ev(300 + i * 0.02) for i in range(200)]  # 200 errors in 4 min
    signals = analyze_burst(
        background_info + background_warn + burst_errors,
        timedelta(minutes=5),
        burst_multiplier=3.0,
    )
    assert len(signals) >= 1
    sig = signals[0]
    assert sig.baseline_count is not None, (
        "baseline_count should be set when background has scattered warnings"
    )
    # The ratio must be >= 1: burst significant-event count exceeds the per-window
    # significant-event baseline.  A ratio < 1 means the baseline uses different
    # units than event_count (the bug that was fixed).
    ratio = sig.event_count / sig.baseline_count
    assert ratio >= 1.0, (
        f"ratio={ratio:.2f} < 1 means baseline_count ({sig.baseline_count}) "
        f"is in different units than event_count ({sig.event_count})"
    )
