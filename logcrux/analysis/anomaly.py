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

# Default window for concentration tests when a caller doesn't supply one.
_DEFAULT_WINDOW = timedelta(minutes=5)

# "invalid credentials" is the standard LDAP resultCode=49 wording (PingDirectory,
# OpenLDAP/slapd, 389-ds) and is also emitted verbatim by many IAM stacks
# (PingFederate, Keycloak) on a failed login — always an authentication failure,
# so it anchors the same brute-force cluster detection as the syslog wordings.
_AUTH_KEYWORDS = frozenset(
    ["failed password", "invalid user", "authentication failure", "invalid credentials"]
)
# "oomkilled" is Kubernetes' container-termination reason (Reason: OOMKilled,
# exit code 137) — the single most common OOM signal on a k8s node, and one word
# so it won't match the kernel's hyphenated "oom-kill".
_OOM_KEYWORDS = frozenset(
    ["out of memory", "oom-kill", "oomkilled", "oom_reaper", "oom killer"]
)
# Unambiguous crash indicators — a line carrying any of these is a crash
# regardless of the parser-assigned severity (e.g. a kernel "segfault" line has
# no level field and parses as INFO, but is still a real crash).
_SERVICE_CRASH_KEYWORDS = frozenset([
    "main process exited", "failed with result 'signal'",
    "segfault", "core dumped", "killed process",
    # Kubernetes crash indicators — unambiguous: each phrase only ever means a
    # container is repeatedly dying. kubelet logs "Back-off restarting failed
    # container" / surfaces "CrashLoopBackOff" as the pod's waiting reason.
    "crashloopbackoff", "back-off restarting failed container",
    "kernel panic",
])
# Ambiguous phrase — "failed to start" is the systemd unit-failure wording but
# also appears in benign INFO chatter (e.g. an app logging "Failed to start
# optional telemetry upload, continuing"). Only count it as a crash when the
# line is WARNING-or-worse, which is how a service actually logs a real unit
# start failure.
# "panic:" is how Go/Rust runtimes announce a fatal crash, but the bare word
# also shows up in prose ("don't panic") and INFO chatter, so require the
# colon form on a WARNING-or-worse line.
_SERVICE_CRASH_WEAK_KEYWORDS = frozenset(["failed to start", "panic:"])
_DISK_FULL_KEYWORDS = frozenset(["no space left on device", "disk full", "quota exceeded"])


def _is_auth_failure(event: ParsedEvent) -> bool:
    return any(kw in event.message.lower() for kw in _AUTH_KEYWORDS)


def _is_oom_event(event: ParsedEvent) -> bool:
    msg = event.message.lower()
    return any(kw in msg for kw in _OOM_KEYWORDS)


def _is_service_crash(event: ParsedEvent) -> bool:
    msg = event.message.lower()
    if any(kw in msg for kw in _SERVICE_CRASH_KEYWORDS):
        return True
    if event.severity in (Severity.WARNING, Severity.ERROR, Severity.CRITICAL):
        return any(kw in msg for kw in _SERVICE_CRASH_WEAK_KEYWORDS)
    return False


def _is_disk_full(event: ParsedEvent) -> bool:
    msg = event.message.lower()
    return any(kw in msg for kw in _DISK_FULL_KEYWORDS)


def _make_window(matched: list[ParsedEvent]) -> TimeWindow:
    bounds = event_time_bounds(matched)
    if bounds is not None:
        t_start, t_end = bounds
    else:
        # Naive to match the engine's tz-normalized event timestamps; mixing
        # naive and aware windows would break time-based correlation sorting.
        now = datetime.now()
        t_start = t_end = now
    return TimeWindow(start=t_start, end=t_end, duration_seconds=(t_end - t_start).total_seconds())


def densest_window(
    matched: list[ParsedEvent],
    window_size: timedelta,
    threshold: int,
) -> tuple[list[ParsedEvent], datetime, datetime] | None:
    """Return the densest ``window_size``-wide cluster holding ``>= threshold``
    timestamped events, or None if even the densest window falls short.

    A forward sliding window is swept over the timestamped events (sorted) and
    the position holding the most events wins. Spreading the same number of
    events thinly across a long span lowers the peak and correctly yields None,
    so a cluster signal requires genuine temporal concentration. Mirrors
    ``error_rate._densest_error_window``; events without a timestamp are ignored
    here (the caller decides how to handle a fully timestamp-less log).
    """
    timed = sorted(
        (e for e in matched if e.timestamp is not None),
        key=event_sort_key,
    )
    n = len(timed)
    if n < threshold:
        return None
    starts = [event_sort_key(e) for e in timed]
    best_count = best_i = best_right = 0
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
    if best_count < threshold:
        return None
    window_events = timed[best_i:best_right]
    return window_events, starts[best_i], event_sort_key(window_events[-1])


def analyze_auth_failures(
    events: list[ParsedEvent],
    failure_threshold: int = 10,
    window_size: timedelta = _DEFAULT_WINDOW,
) -> list[AnomalySignal]:
    failures = [e for e in events if _is_auth_failure(e)]
    if len(failures) < failure_threshold:
        return []

    if any(e.timestamp is not None for e in failures):
        # A brute force is temporally concentrated. Require >= threshold failures
        # inside one window and anchor the signal to the densest cluster.
        # Counting every failure in the file flagged e.g. 490 failed logins
        # spread over 41 days (normal background noise on an internet-facing
        # host) as an "Auth Brute Force"; it also reported the whole multi-week
        # span as the incident window, which is misleading.
        densest = densest_window(failures, window_size, failure_threshold)
        if densest is None:
            return []
        window_events, w_start, w_end = densest
        return [AnomalySignal(
            kind="auth_failure_cluster",
            window=TimeWindow(
                start=w_start, end=w_end,
                duration_seconds=(w_end - w_start).total_seconds(),
            ),
            event_count=len(window_events),
            baseline_count=None,
            severity=Severity.WARNING,
            representative_events=window_events[:20],
        )]

    # No timestamps anywhere to anchor a window: fall back to the total count
    # (already >= threshold) so timestamp-less auth logs still surface.
    return [AnomalySignal(
        kind="auth_failure_cluster",
        window=_make_window(failures),
        event_count=len(failures),
        baseline_count=None,
        severity=Severity.WARNING,
        representative_events=failures[:20],
    )]


def analyze_oom_events(events: list[ParsedEvent]) -> list[AnomalySignal]:
    matched = [e for e in events if _is_oom_event(e)]
    if not matched:
        return []

    return [AnomalySignal(
        kind="oom_event",
        window=_make_window(matched),
        event_count=len(matched),
        baseline_count=None,
        severity=Severity.CRITICAL,
        representative_events=matched[:20],
    )]


def analyze_service_crashes(events: list[ParsedEvent]) -> list[AnomalySignal]:
    matched = [e for e in events if _is_service_crash(e)]
    if not matched:
        return []

    return [AnomalySignal(
        kind="service_crash",
        window=_make_window(matched),
        event_count=len(matched),
        baseline_count=None,
        severity=Severity.ERROR,
        representative_events=matched[:20],
    )]


def analyze_disk_full(events: list[ParsedEvent]) -> list[AnomalySignal]:
    matched = [e for e in events if _is_disk_full(e)]
    if not matched:
        return []

    return [AnomalySignal(
        kind="disk_full",
        window=_make_window(matched),
        event_count=len(matched),
        baseline_count=None,
        severity=Severity.CRITICAL,
        representative_events=matched[:20],
    )]
