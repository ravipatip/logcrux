from __future__ import annotations

from datetime import timedelta

from logcrux.models import AnomalySignal, Severity, TimeWindow

_SEVERITY_RANK = {
    Severity.UNKNOWN: -1,
    Severity.DEBUG: -1,
    Severity.INFO: -1,
    Severity.WARNING: 0,
    Severity.ERROR: 1,
    Severity.CRITICAL: 2,
}


def _windows_overlap(a: TimeWindow, b: TimeWindow) -> bool:
    return a.start <= b.end and b.start <= a.end


def _merge_into(keep: AnomalySignal, other: AnomalySignal) -> AnomalySignal:
    """Fold ``other`` into ``keep``: union the window, take the larger event
    count and stronger severity, and union the representative events."""
    start = min(keep.window.start, other.window.start)
    end = max(keep.window.end, other.window.end)
    window = TimeWindow(
        start=start, end=end, duration_seconds=(end - start).total_seconds()
    )
    seen: set[tuple[int | None, str]] = set()
    reps = []
    for ev in (*keep.representative_events, *other.representative_events):
        key = (ev.line_number, ev.message)
        if key in seen:
            continue
        seen.add(key)
        reps.append(ev)
    bigger = keep if keep.event_count >= other.event_count else other
    stronger = max(
        keep.severity, other.severity, key=lambda s: _SEVERITY_RANK.get(s, -1)
    )
    return keep.model_copy(
        update={
            "window": window,
            "event_count": max(keep.event_count, other.event_count),
            "baseline_count": bigger.baseline_count,
            "severity": stronger,
            "representative_events": reps[:5],
        }
    )


def _dedup_overlapping(signals: list[AnomalySignal]) -> list[AnomalySignal]:
    """Collapse same-kind signals whose windows overlap into one.

    The error-rate and burst detectors independently flag the same dense window,
    so without this a single incident surfaces as two identical findings (seen on
    real syslog: "46 events in 2s window" listed twice). Two signals are
    duplicates when they share a ``kind`` and their time windows overlap; the
    survivor takes the union window and the larger event count. Distinct windows
    (e.g. several error bursts at different times) are preserved.
    """
    kept: list[AnomalySignal] = []
    for signal in signals:
        for i, existing in enumerate(kept):
            if existing.kind == signal.kind and _windows_overlap(
                existing.window, signal.window
            ):
                kept[i] = _merge_into(existing, signal)
                break
        else:
            kept.append(signal)
    return kept


def analyze_correlation(
    signals: list[AnomalySignal],
    max_gap: timedelta,
) -> list[AnomalySignal]:
    """Dedup overlapping same-kind signals, then order correlated groups first."""
    if not signals:
        return []

    signals = _dedup_overlapping(signals)
    sorted_signals = sorted(signals, key=lambda s: s.window.start)
    groups: list[list[AnomalySignal]] = []
    current_group = [sorted_signals[0]]
    # Track the latest end seen in the group, not just the last-appended signal's
    # end: signals are sorted by start, so a long early signal can still overlap a
    # later one whose predecessor ended sooner. Using the running max prevents a
    # premature split that would isolate correlated signals.
    group_end = sorted_signals[0].window.end

    for signal in sorted_signals[1:]:
        gap = signal.window.start - group_end
        if gap <= max_gap:
            current_group.append(signal)
            group_end = max(group_end, signal.window.end)
        else:
            groups.append(current_group)
            current_group = [signal]
            group_end = signal.window.end
    groups.append(current_group)

    correlated = [s for g in groups if len(g) > 1 for s in g]
    isolated = [s for g in groups if len(g) == 1 for s in g]
    return correlated + isolated
