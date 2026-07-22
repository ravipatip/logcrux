from datetime import UTC, datetime, timedelta

from logcrux.analysis.correlation import analyze_correlation
from logcrux.models import AnomalySignal, Severity, TimeWindow


def _signal(minutes_start: int, minutes_end: int, kind: str = "error_burst") -> AnomalySignal:
    base = datetime(2026, 6, 16, 3, 0, 0, tzinfo=UTC)
    start = base + timedelta(minutes=minutes_start)
    end = base + timedelta(minutes=minutes_end)
    return AnomalySignal(
        kind=kind,  # type: ignore[arg-type]
        window=TimeWindow(start=start, end=end, duration_seconds=(end - start).total_seconds()),
        event_count=10, baseline_count=None,
        severity=Severity.WARNING, representative_events=[],
    )


def test_close_signals_get_correlated():
    # s1 and s2 are close → correlated group; s3 is far → isolated.
    # Correlated signals must appear before isolated ones in the output.
    s1 = _signal(0, 1, "oom_event")
    s2 = _signal(1, 2, "error_burst")
    s3 = _signal(60, 61, "error_burst")  # isolated — 59-min gap
    result = analyze_correlation([s1, s2, s3], max_gap=timedelta(minutes=2))
    assert len(result) == 3
    # Correlated pair (s1, s2) must appear before the isolated signal (s3)
    assert result.index(s1) < result.index(s3)
    assert result.index(s2) < result.index(s3)


def test_distant_signals_not_correlated():
    # s1 is isolated; s2 and s3 are close → correlated.
    # s2 and s3 must appear before s1 in the output. Distinct kinds so the
    # overlap-dedup pass doesn't collapse s2/s3 — this test is about ordering.
    s1 = _signal(0, 1, "oom_event")
    s2 = _signal(30, 31, "error_burst")
    s3 = _signal(31, 32, "service_crash")
    result = analyze_correlation([s1, s2, s3], max_gap=timedelta(minutes=2))
    assert len(result) == 3
    assert result.index(s2) < result.index(s1)
    assert result.index(s3) < result.index(s1)


def test_empty_signals():
    assert analyze_correlation([], timedelta(minutes=2)) == []


def test_long_signal_keeps_later_signal_correlated():
    # A long early signal A (0-10m) overlaps a late signal B (8-9m). Between
    # them, a short signal (2-3m) ends well before B. Grouping must compare B's
    # start against the running *max* end of the group (A's 10m), not the
    # last-appended signal's end (the short one's 3m). With the buggy
    # last-appended logic, B is wrongly split into its own group and, being
    # isolated, is reordered *after* the distant correlated pair (C, D).
    # C and D use distinct kinds so the overlap-dedup pass keeps them separate
    # (this test is about grouping/ordering, not dedup).
    a = _signal(0, 10, "oom_event")
    short = _signal(2, 3, "error_burst")
    b = _signal(8, 9, "service_crash")
    c = _signal(20, 21, "error_burst")
    d = _signal(21, 22, "rate_spike")
    result = analyze_correlation([a, short, b, c, d], max_gap=timedelta(seconds=30))
    assert len(result) == 5
    # B overlaps A, so it is part of the first correlated group and must appear
    # before the later C/D group — not isolated to the tail.
    assert result.index(b) < result.index(c)
    assert result.index(b) < result.index(d)


def test_overlapping_same_kind_signals_deduped():
    # The error-rate and burst detectors both flag the same dense window, each
    # emitting an error_burst over an overlapping span. They must collapse into a
    # single signal so one incident isn't reported as two identical findings.
    s1 = _signal(0, 2, "error_burst")
    s1 = s1.model_copy(update={"event_count": 46})
    s2 = _signal(0, 2, "error_burst")
    s2 = s2.model_copy(update={"event_count": 40})
    result = analyze_correlation([s1, s2], max_gap=timedelta(minutes=2))
    assert len(result) == 1
    assert result[0].event_count == 46  # survivor keeps the larger count


def test_overlapping_different_kind_signals_not_deduped():
    # Different kinds over the same window are distinct findings, not duplicates.
    s1 = _signal(0, 2, "error_burst")
    s2 = _signal(0, 2, "auth_failure_cluster")
    result = analyze_correlation([s1, s2], max_gap=timedelta(minutes=2))
    assert len(result) == 2
