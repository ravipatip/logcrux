from __future__ import annotations

from datetime import datetime, timedelta
from typing import Literal

from logcrux.analysis.anomaly import densest_window
from logcrux.models import (
    AnomalySignal,
    ParsedEvent,
    Severity,
    TimeWindow,
    event_time_bounds,
)

_SAFE_CONNECT_PORTS = frozenset([80, 443, 8080, 8443])
_DEFAULT_WINDOW = timedelta(minutes=5)


def _is_squid(event: ParsedEvent) -> bool:
    return event.extra.get("parser") == "squid"


def _make_window(events: list[ParsedEvent]) -> TimeWindow:
    bounds = event_time_bounds(events)
    if bounds is not None:
        t_start, t_end = bounds
    else:
        # Naive to match the engine's tz-normalized event timestamps; mixing
        # naive and aware windows would break time-based correlation sorting.
        now = datetime.now()
        t_start = t_end = now
    return TimeWindow(start=t_start, end=t_end, duration_seconds=(t_end - t_start).total_seconds())


def _cluster_signal(
    kind: Literal["proxy_denial_cluster", "auth_failure_cluster", "firewall_block_cluster"],
    matched: list[ParsedEvent],
    failure_threshold: int,
    window_size: timedelta,
) -> list[AnomalySignal]:
    """Emit a cluster signal only when ``matched`` events are temporally
    concentrated (>= ``failure_threshold`` inside one ``window_size`` window),
    anchored to the densest window. Mirrors ``analyze_auth_failures``: a denial
    or proxy-auth-failure count spread thinly across a long span is background
    noise, not an incident, and reporting the whole span as the window misleads.
    """
    if len(matched) < failure_threshold:
        return []
    if any(e.timestamp is not None for e in matched):
        densest = densest_window(matched, window_size, failure_threshold)
        if densest is None:
            return []
        window_events, w_start, w_end = densest
        return [AnomalySignal(
            kind=kind,
            window=TimeWindow(
                start=w_start, end=w_end,
                duration_seconds=(w_end - w_start).total_seconds(),
            ),
            event_count=len(window_events),
            baseline_count=None,
            severity=Severity.WARNING,
            representative_events=window_events[:20],
        )]
    return [AnomalySignal(
        kind=kind,
        window=_make_window(matched),
        event_count=len(matched),
        baseline_count=None,
        severity=Severity.WARNING,
        representative_events=matched[:20],
    )]


def _analyze_denial_cluster(
    squid_events: list[ParsedEvent],
    failure_threshold: int,
    window_size: timedelta,
) -> list[AnomalySignal]:
    # Native logs carry a TCP_DENIED result code; CLF logs have no result code,
    # so a 403 status is the denial equivalent there.
    denied = [
        e for e in squid_events
        if "DENIED" in (e.extra.get("result_code") or "")
        or e.extra.get("status_code") == 403
    ]
    return _cluster_signal("proxy_denial_cluster", denied, failure_threshold, window_size)


def _analyze_tunnel_anomaly(squid_events: list[ParsedEvent]) -> list[AnomalySignal]:
    suspicious = [
        e for e in squid_events
        if e.extra.get("method") == "CONNECT"
        and e.extra.get("connect_port") not in _SAFE_CONNECT_PORTS
        and e.extra.get("connect_port") is not None
    ]
    if not suspicious:
        return []
    return [AnomalySignal(
        kind="tunnel_anomaly",
        window=_make_window(suspicious),
        event_count=len(suspicious),
        baseline_count=None,
        severity=Severity.WARNING,
        representative_events=suspicious[:20],
    )]


def _analyze_proxy_auth_failures(
    squid_events: list[ParsedEvent],
    failure_threshold: int,
    window_size: timedelta,
) -> list[AnomalySignal]:
    auth_fails = [
        e for e in squid_events
        if e.extra.get("status_code") == 407
    ]
    return _cluster_signal("auth_failure_cluster", auth_fails, failure_threshold, window_size)


def _analyze_cache_bypass(squid_events: list[ParsedEvent]) -> list[AnomalySignal]:
    if len(squid_events) < 20:
        return []
    cacheable = [
        e for e in squid_events
        if e.extra.get("result_code") in ("TCP_MISS", "TCP_HIT", "TCP_MEM_HIT", "TCP_REFRESH_HIT")
    ]
    if not cacheable:
        return []
    misses = [e for e in cacheable if e.extra.get("result_code") == "TCP_MISS"]
    if len(misses) / len(squid_events) < 0.9:
        return []
    return [AnomalySignal(
        kind="error_burst",
        window=_make_window(misses),
        event_count=len(misses),
        baseline_count=None,
        severity=Severity.WARNING,
        representative_events=misses[:20],
    )]


# Host firewall parsers tag dropped packets with an "action" extra; a
# concentrated flood of blocks (a port scan, a worm probing, a misconfigured
# client hammering a closed port) is a reportable network signal, while
# scattered background-noise drops are not — the _cluster_signal density gate
# handles that distinction.
_FIREWALL_SOURCES = frozenset(["ufw", "filterlog", "firewalld"])
_FIREWALL_BLOCK_ACTIONS = frozenset(["block", "reject", "drop"])


def _is_firewall_block(event: ParsedEvent) -> bool:
    if event.source not in _FIREWALL_SOURCES:
        return False
    action = str(event.extra.get("action", "")).lower()
    return action in _FIREWALL_BLOCK_ACTIONS


def _analyze_firewall_blocks(
    events: list[ParsedEvent],
    failure_threshold: int,
    window_size: timedelta,
) -> list[AnomalySignal]:
    blocked = [e for e in events if _is_firewall_block(e)]
    return _cluster_signal("firewall_block_cluster", blocked, failure_threshold, window_size)


def analyze_proxy_anomalies(
    events: list[ParsedEvent],
    failure_threshold: int = 10,
    window_size: timedelta = _DEFAULT_WINDOW,
) -> list[AnomalySignal]:
    signals: list[AnomalySignal] = []
    signals += _analyze_firewall_blocks(events, failure_threshold, window_size)

    squid = [e for e in events if _is_squid(e)]
    if not squid:
        return signals

    signals += _analyze_denial_cluster(squid, failure_threshold, window_size)
    signals += _analyze_tunnel_anomaly(squid)
    signals += _analyze_proxy_auth_failures(squid, failure_threshold, window_size)
    signals += _analyze_cache_bypass(squid)
    return signals
