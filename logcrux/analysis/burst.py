from __future__ import annotations

from bisect import bisect_left, bisect_right
from datetime import timedelta
from statistics import median

from logcrux.models import (
    AnomalySignal,
    ParsedEvent,
    Severity,
    TimeWindow,
    event_sort_key,
)

# A burst must contain at least this many events to be worth reporting, no
# matter how quiet the surrounding baseline is — a couple of events three times
# above a near-zero baseline is noise, not an incident.
_MIN_BURST_EVENTS = 10

# Severities that make a burst worth reporting. A spike in *volume* alone is not
# an incident — a log can legitimately get chatty (install progress, INFO status
# lines). Only a concentration of warning-or-worse events is an anomaly. Without
# this gate, benign INFO bursts (e.g. macOS install.log) were flagged as
# "error_burst" WARNINGs and then mislabeled by the AI classifier.
_SIGNIFICANT_SEVERITIES = {Severity.WARNING, Severity.ERROR, Severity.CRITICAL}

# Severity ordering for picking a burst's reported severity (highest present).
_SEVERITY_RANK = {
    Severity.WARNING: 0,
    Severity.ERROR: 1,
    Severity.CRITICAL: 2,
}


def analyze_burst(
    events: list[ParsedEvent],
    window_size: timedelta,
    burst_multiplier: float = 3.0,
) -> list[AnomalySignal]:
    """Detect high-frequency bursts of warning-or-worse events, emitting one
    signal per *distinct* burst.

    For each event we count how many events fall within ``window_size`` ahead of
    it (a forward sliding window). A window is "dense" when that count clears
    both ``burst_multiplier * baseline`` and an absolute floor.

    The baseline is the **median** window count. The median represents the log's
    typical level and — unlike the mean — is not dragged upward by the bursts
    themselves, so a genuine spike still stands out even when it contributes a
    large share of the events. A uniformly busy log has no spike relative to its
    own median and correctly produces nothing (sustained high volume vs a stored
    historical baseline is ``analyze_error_rate``'s job, not this one's).

    Consecutive dense windows are merged into a single burst region; a quiet gap
    between two dense clusters ends one region and starts another, so separate
    incidents are reported as separate signals instead of collapsing into the
    first one.

    A dense window is only emitted as a signal when it holds at least
    ``_MIN_BURST_EVENTS`` warning-or-worse events: a spike in *volume* of benign
    INFO/DEBUG lines is not an incident, and surfacing it produced confident
    false positives (a benign install log mislabeled "Auth Brute Force").
    """
    timed = sorted(
        (e for e in events if e.timestamp is not None),
        key=event_sort_key,
    )
    if len(timed) < 2:
        return []

    starts = [event_sort_key(e) for e in timed]
    n = len(timed)

    # Forward-window event counts via a two-pointer sweep (events are sorted, so
    # the right edge only ever advances — O(n) overall).
    window_counts: list[int] = [0] * n
    right = 0
    for i in range(n):
        cutoff = starts[i] + window_size
        if right < i:
            right = i
        while right < n and starts[right] <= cutoff:
            right += 1
        window_counts[i] = right - i

    baseline = median(window_counts)
    threshold = max(burst_multiplier * baseline, _MIN_BURST_EVENTS)

    # Compute per-window counts for *significant* events only so that the
    # reported ratio compares apples to apples (significant events in burst vs
    # significant-event baseline). Using the all-event baseline produced ratios
    # < 1× for INFO-heavy logs where warning-or-worse events were a minority.
    timed_sig = [e for e in timed if e.severity in _SIGNIFICANT_SEVERITIES]
    sig_starts = [event_sort_key(e) for e in timed_sig]
    sig_counts: list[int] = [
        bisect_right(sig_starts, starts[i] + window_size)
        - bisect_left(sig_starts, starts[i])
        for i in range(n)
    ]
    sig_baseline: float | None = median(sig_counts) if sig_counts else None
    if sig_baseline == 0:
        sig_baseline = None

    signals: list[AnomalySignal] = []
    i = 0
    while i < n:
        if window_counts[i] < threshold:
            i += 1
            continue
        # Start of a burst: consume the maximal run of consecutive dense windows
        # so one incident yields one signal regardless of how many windows it
        # spans.
        run_start = i
        while i < n and window_counts[i] >= threshold:
            i += 1
        run_end = i - 1  # last dense window's start index

        # The burst covers every event from the first dense window's start
        # through the end of the last dense window (its tail events have low
        # forward counts and so are not run starts themselves).
        cutoff = starts[run_end] + window_size
        burst_events = [
            ev for ev, t in zip(timed[run_start:], starts[run_start:]) if t <= cutoff
        ]

        # Gate on severity: a volume spike of benign INFO/DEBUG lines is not an
        # incident. Only report when warning-or-worse events are themselves
        # concentrated in the burst. Lead with the significant events so the
        # representative sample shows the actual problem, not surrounding noise.
        significant = [e for e in burst_events if e.severity in _SIGNIFICANT_SEVERITIES]
        if len(significant) < _MIN_BURST_EVENTS:
            continue

        burst_start = starts[run_start]
        burst_end = event_sort_key(burst_events[-1])
        peak_severity = max(
            (e.severity for e in significant),
            key=lambda s: _SEVERITY_RANK[s],
        )
        signals.append(
            AnomalySignal(
                kind="error_burst",
                window=TimeWindow(
                    start=burst_start,
                    end=burst_end,
                    duration_seconds=(burst_end - burst_start).total_seconds(),
                ),
                event_count=len(significant),
                baseline_count=sig_baseline,
                severity=peak_severity,
                representative_events=significant[:20],
            )
        )
        # ``i`` already points just past the run; keep scanning for the next.
    return signals
