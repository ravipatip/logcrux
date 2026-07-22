from __future__ import annotations

from copy import copy
from datetime import timedelta

from logcrux.analysis.anomaly import (
    analyze_auth_failures,
    analyze_disk_full,
    analyze_oom_events,
    analyze_service_crashes,
)
from logcrux.analysis.burst import analyze_burst
from logcrux.analysis.correlation import analyze_correlation
from logcrux.analysis.error_rate import analyze_error_rate
from logcrux.analysis.proxy import analyze_proxy_anomalies
from logcrux.config import AnalysisConfig
from logcrux.models import (
    AnalysisResult,
    AnomalySignal,
    ParsedEvent,
    TimeWindow,
    event_time_bounds,
)

_LEVEL_ORDER = ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "UNKNOWN"]


def _severity_rank(signal: AnomalySignal) -> int:
    val = signal.severity.value.upper()
    try:
        return _LEVEL_ORDER.index(val)
    except ValueError:
        return 99


def _strip_tzinfo(events: list[ParsedEvent]) -> list[ParsedEvent]:
    """Return events with all timestamps normalized to naive datetimes.

    Parsers may produce a mix of tz-aware (journald, squid) and tz-naive
    (syslog) timestamps. Sorting or comparing mixed datetimes raises TypeError,
    so we strip tzinfo uniformly before analysis (UTC offset is discarded but
    relative ordering is preserved for same-zone logs).
    """
    out = []
    for e in events:
        ts = e.timestamp
        if ts is not None and ts.tzinfo is not None:
            e = copy(e)
            e.timestamp = ts.replace(tzinfo=None)
        out.append(e)
    return out


def run_analysis(
    events: list[ParsedEvent],
    parser_format: str,
    log_path: str,
    baseline: object | None,
    config: AnalysisConfig,
    skipped_count: int = 0,
) -> AnalysisResult:
    events = _strip_tzinfo(events)
    window = timedelta(minutes=config.window_size_minutes)
    baseline_errors: float | None = getattr(baseline, "avg_errors_per_hour", None)

    signals: list[AnomalySignal] = []
    signals += analyze_error_rate(events, window, baseline_errors, config.spike_factor)
    signals += analyze_burst(events, window, config.burst_multiplier)
    signals += analyze_auth_failures(events, config.auth_failure_threshold, window)
    signals += analyze_oom_events(events)
    signals += analyze_service_crashes(events)
    signals += analyze_disk_full(events)
    signals += analyze_proxy_anomalies(events, config.auth_failure_threshold, window)
    signals = analyze_correlation(signals, timedelta(seconds=config.correlation_gap_seconds))
    signals.sort(key=_severity_rank)

    time_range: TimeWindow | None = None
    bounds = event_time_bounds(events)
    if bounds is not None:
        t_start, t_end = bounds
        time_range = TimeWindow(
            start=t_start, end=t_end,
            duration_seconds=(t_end - t_start).total_seconds(),
        )

    return AnalysisResult(
        log_path=log_path,
        parser_format=parser_format,
        parsed_count=len(events),
        skipped_count=skipped_count,
        time_range=time_range,
        signals=signals,
    )
