from __future__ import annotations

from datetime import datetime, timedelta

from logcrux.models import (
    AnomalySignal,
    ParsedEvent,
    Severity,
    TimeWindow,
    event_sort_key,
    event_time_bounds,
)

_ERROR_SEVERITIES = {Severity.ERROR, Severity.CRITICAL}

# A rate spike is only meaningful with enough absolute errors. Without this
# guard, a handful of errors over a few seconds extrapolates to a huge
# errors/hour figure and trips the spike against any modest baseline.
_MIN_SPIKE_ERRORS = 5

# Absolute floor for a no-baseline error burst: a cluster must hold at least
# this many errors (within one window when timed; in the whole file when not) to
# be worth reporting, so a handful of stray errors never raises an incident.
_MIN_BURST_ERRORS = 10
# When there are no timestamps we additionally require errors to make up this
# fraction of the log, so a big, healthy log with a few stray errors stays CLEAN.
_MIN_UNTIMED_ERROR_FRACTION = 0.2


def analyze_error_rate(
    events: list[ParsedEvent],
    window_size: timedelta,
    baseline_avg_errors_per_hour: float | None,
    spike_factor: float = 3.0,
) -> list[AnomalySignal]:
    timed = [e for e in events if e.timestamp is not None]
    bounds = event_time_bounds(timed)
    if bounds is None:
        # No usable timestamps anywhere — fall back to a count + proportion check
        # so error-heavy logs (app/docker stdout) aren't silently reported clean.
        return _untimed_error_cluster(events)

    # ``timed`` only holds events with a timestamp, so the sort key is total.
    errors = sorted(
        (e for e in timed if e.severity in _ERROR_SEVERITIES),
        key=event_sort_key,
    )
    if not errors:
        return []

    signals: list[AnomalySignal] = []
    t_start, t_end = bounds
    duration_hours = max((t_end - t_start).total_seconds() / 3600, 1 / 3600)
    current_rate = len(errors) / duration_hours

    if baseline_avg_errors_per_hour is not None and len(errors) >= _MIN_SPIKE_ERRORS:
        if current_rate > baseline_avg_errors_per_hour * spike_factor:
            signals.append(AnomalySignal(
                kind="rate_spike",
                window=TimeWindow(
                    start=t_start,
                    end=t_end,
                    duration_seconds=(t_end - t_start).total_seconds(),
                ),
                event_count=len(errors),
                baseline_count=baseline_avg_errors_per_hour,
                severity=Severity.ERROR,
                representative_events=errors[:20],
            ))
            return signals

    # No baseline to compare against: flag only a *concentrated* burst of
    # errors. Counting every error in the file would flag a months-long log that
    # merely mentions "error" thousands of times spread thinly across a huge
    # span (e.g. macOS install.log over 137 days) as a single giant "burst".
    # Require enough errors inside one window and anchor the signal to the
    # densest window, mirroring analyze_burst's concentration test.
    densest = _densest_error_window(errors, window_size)
    if densest is not None:
        window_events, w_start, w_end = densest
        signals.append(AnomalySignal(
            kind="error_burst",
            window=TimeWindow(
                start=w_start,
                end=w_end,
                duration_seconds=(w_end - w_start).total_seconds(),
            ),
            event_count=len(window_events),
            baseline_count=None,
            severity=Severity.ERROR,
            representative_events=window_events[:20],
        ))
    return signals


def _densest_error_window(
    errors: list[ParsedEvent],
    window_size: timedelta,
) -> tuple[list[ParsedEvent], datetime, datetime] | None:
    """Return the densest ``window_size``-wide cluster of errors, or None.

    ``errors`` must be sorted by timestamp. We sweep a forward window and keep
    the position holding the most errors; if that peak clears the absolute floor
    the cluster is a genuine burst worth reporting. Spreading the same error
    count across a long span lowers the peak and correctly yields nothing.
    """
    n = len(errors)
    if n < _MIN_BURST_ERRORS:
        return None
    starts = [event_sort_key(e) for e in errors]
    best_count = 0
    best_i = 0
    best_right = 0
    right = 0
    for i in range(n):
        cutoff = starts[i] + window_size
        if right < i:
            right = i
        while right < n and starts[right] <= cutoff:
            right += 1
        if right - i > best_count:
            best_count = right - i
            best_i = i
            best_right = right
    if best_count < _MIN_BURST_ERRORS:
        return None
    window_events = errors[best_i:best_right]
    return window_events, starts[best_i], event_sort_key(window_events[-1])


def _untimed_error_cluster(events: list[ParsedEvent]) -> list[AnomalySignal]:
    """Detect a dominant cluster of errors in a log that has no timestamps.

    The time-based spike/burst paths can't run without timestamps, but a log
    that is largely errors is still an incident worth surfacing. We require both
    an absolute floor and a high error fraction so that a large, healthy log
    with a handful of stray ERROR lines is not flagged.
    """
    if not events:
        return []
    errors = [e for e in events if e.severity in _ERROR_SEVERITIES]
    if len(errors) < _MIN_BURST_ERRORS:
        return []
    if len(errors) / len(events) < _MIN_UNTIMED_ERROR_FRACTION:
        return []

    # No timestamps to anchor a window; use a zero-width window at analysis time
    # (naive, matching the engine's tz-normalized events).
    now = datetime.now()
    return [AnomalySignal(
        kind="error_burst",
        window=TimeWindow(start=now, end=now, duration_seconds=0.0),
        event_count=len(errors),
        baseline_count=None,
        severity=Severity.ERROR,
        representative_events=errors[:20],
    )]
