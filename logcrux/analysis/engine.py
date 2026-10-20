from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable
from datetime import datetime, timedelta

from logcrux.analysis.anomaly import (
    _CONFIG_ERROR_RE,
    _is_auth_failure,
    _is_disk_full,
    _is_oom_event,
    _is_service_crash,
    analyze_auth_failures,
    analyze_backend_down,
    analyze_clock_jumps,
    analyze_config_errors,
    analyze_disk_full,
    analyze_fatal_exit,
    analyze_job_outcomes,
    analyze_mail_rejects,
    analyze_oom_events,
    analyze_package_locks,
    analyze_policy_denials,
    analyze_probe_failures,
    analyze_resource_limits,
    analyze_service_crashes,
    analyze_storage_faults,
    analyze_tls_errors,
    analyze_uncaught_exception,
    final_error_event,
    is_backend_down,
    is_clock_jump,
    is_mail_reject,
    is_tls_cert_error,
    resource_limit_kind,
    storage_fault_kind,
)
from logcrux.analysis.burst import analyze_burst
from logcrux.analysis.correlation import analyze_correlation
from logcrux.analysis.error_rate import analyze_error_rate
from logcrux.analysis.evidence import decisive_first, subjects
from logcrux.analysis.proxy import analyze_proxy_anomalies
from logcrux.config import AnalysisConfig
from logcrux.models import (
    AnalysisResult,
    AnomalySignal,
    ParsedEvent,
    Severity,
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

    Normalised in place. Copying every tz-aware event (all of nginx's, for
    example) duplicated the whole event list: on a real 510k-line, 43 MB
    access log that copy alone was +480 MB of peak RSS (1.0 -> 1.5 GB). The
    CLI reads nothing tz-dependent from the events after analysis — the
    ``--last`` filter has already run and the baseline update strips tzinfo
    itself.
    """
    for e in events:
        ts = e.timestamp
        if ts is not None and ts.tzinfo is not None:
            e.timestamp = ts.replace(tzinfo=None)
    return events


# A boot journal opens with a dense block of routine startup complaints —
# "setfont failed ... ignoring", "rngd: Initialization Failed", a guest agent
# without logging permission. Captured on healthy GCP VMs across 12 distros
# (2026-10-13): parsed properly, that block always clears the error-burst floor,
# because the boot *is* the volume spike. The boot phase is bounded by the
# kernel's "Linux version" banner and systemd's "Startup finished in". A
# *generic* burst that starts inside it (and ends within _BOOT_SETTLE) is boot
# noise; specific detectors (OOM,
# crash, disk full, auth) still fire there, so a boot that really fails is
# still reported.
_BOOT_START = re.compile(r"\bLinux version \d")
# The system manager's line ("Startup finished in 1.3s (kernel) + 4.0s
# (initrd) + 2min 45s (userspace)"), not a user session manager's
# ("systemd[1505]: Startup finished in 73ms.") — on a real Alma 8 VM the user
# manager finished 2 minutes before PID 1, and the boot noise between them
# became a false "Error burst" (GCP phase 3, 2026-10-20).
_BOOT_DONE = re.compile(r"\bStartup finished in\b.*\((?:kernel|initrd|userspace|firmware)\)")
# Agents started by the boot (cloud guest agents, timers) log for a few seconds
# after systemd reaches its target; on the 12 captures the noise ended 4-6 s
# after "Startup finished". A burst that *starts* in the boot phase and ends
# within this settle period is still boot noise.
_BOOT_SETTLE = timedelta(seconds=60)


def _boot_phases(events: list[ParsedEvent]) -> list[tuple[datetime, datetime]]:
    phases: list[tuple[datetime, datetime]] = []
    start: datetime | None = None
    for e in events:
        if e.timestamp is None:
            continue
        if _BOOT_START.search(e.message):
            start = e.timestamp
        elif start is not None and _BOOT_DONE.search(e.message):
            phases.append((start, e.timestamp))
            start = None
    return phases


def _drop_boot_noise(
    signals: list[AnomalySignal], phases: list[tuple[datetime, datetime]]
) -> list[AnomalySignal]:
    if not phases:
        return signals
    return [
        s for s in signals
        if not (s.kind == "error_burst" and any(
            b0 <= s.window.start <= b1 and s.window.end <= b1 + _BOOT_SETTLE
            for b0, b1 in phases))
    ]


_MATCHERS: dict[str, Callable[[ParsedEvent], bool]] = {
    "auth_failure_cluster": _is_auth_failure,
    "oom_event": _is_oom_event,
    "service_crash": _is_service_crash,
    "disk_full": _is_disk_full,
    "storage_fault": lambda e: storage_fault_kind(e) is not None,
    "backend_down": is_backend_down,
    "config_error": lambda e: _CONFIG_ERROR_RE.search(e.message) is not None,
    "resource_limit": lambda e: resource_limit_kind(e) is not None,
    "tls_error": is_tls_cert_error,
    "mail_reject_cluster": is_mail_reject,
    "clock_jump": is_clock_jump,
}
_ERRORISH = (Severity.ERROR, Severity.CRITICAL)
_WARNISH = (Severity.WARNING, Severity.ERROR, Severity.CRITICAL)


def _signal_events(signal: AnomalySignal, events: list[ParsedEvent]) -> list[ParsedEvent]:
    """Every event a signal stands for — not just its representative sample —
    so subject counts ("from 203.0.113.9: 140") are true counts."""
    match = _MATCHERS.get(signal.kind)
    if match is None and signal.kind in ("error_burst", "rate_spike"):
        sev = _ERRORISH if any(e.severity in _ERRORISH for e in signal.representative_events) \
            else _WARNISH
        def match(e: ParsedEvent) -> bool:
            return e.severity in sev
    if match is None:
        return signal.representative_events
    start, end = signal.window.start, signal.window.end
    timed = any(e.timestamp is not None for e in signal.representative_events)
    return [
        e for e in events
        if match(e) and (not timed or (e.timestamp is not None and start <= e.timestamp <= end))
    ] or signal.representative_events


_GENERIC_KINDS = frozenset({"error_burst", "rate_spike"})
_SEV_RANK = {s: i for i, s in enumerate(
    (Severity.UNKNOWN, Severity.DEBUG, Severity.INFO, Severity.WARNING,
     Severity.ERROR, Severity.CRITICAL))}
# A generic burst made (almost) entirely of lines a specific detector already
# claimed is the same incident counted twice: 48 "Failed password" lines are
# an auth attack, and listing "Error burst detected" above it only pushes the
# real finding down.
_REDUNDANT_BURST = 0.8


def _fold_redundant_bursts(
    signals: list[AnomalySignal], events: list[ParsedEvent]
) -> list[AnomalySignal]:
    specific = [s for s in signals if s.kind in _MATCHERS]
    out = list(signals)
    for burst in [s for s in signals if s.kind in _GENERIC_KINDS and specific]:
        pool = _signal_events(burst, events)
        if not pool:
            continue
        claimed = {id(s): sum(1 for e in pool if _MATCHERS[s.kind](e)) for s in specific}
        owner = max(specific, key=lambda s: claimed[id(s)])
        covered = sum(1 for e in pool if any(_MATCHERS[s.kind](e) for s in specific))
        if covered < _REDUNDANT_BURST * len(pool):
            continue
        out.remove(burst)
        # Keep the verdict level: the burst's severity passes to its owner.
        if _SEV_RANK[burst.severity] > _SEV_RANK[owner.severity]:
            i = out.index(owner)
            out[i] = owner.model_copy(update={"severity": burst.severity})
            specific = [x for x in out if x.kind in _MATCHERS]
    # Specific findings first (they name the incident); generic bursts after,
    # each group still ordered by severity.
    return [s for s in out if s.kind not in _GENERIC_KINDS] + \
        [s for s in out if s.kind in _GENERIC_KINDS]


def _with_evidence(signal: AnomalySignal, events: list[ParsedEvent]) -> AnomalySignal:
    pool = _signal_events(signal, events)
    return signal.model_copy(update={
        "subjects": subjects(signal.kind, pool),
        "evidence": decisive_first(signal.kind, pool),
    })


def _last_error(events: list[ParsedEvent]) -> ParsedEvent | None:
    """A short log that stops on a fatal-sounding error: shown on a CLEAN
    result, not alarmed on (see final_error_event)."""
    return final_error_event(events)


# Lines that are errors by wording but harmless where they occur, each seen
# on every VM of its kind across the real campaigns. Kept narrow: exact
# daemon wording, never a bare keyword.
#   systemd 257 (Debian 13) re-runs its ssh generator on every daemon-reload;
#   on a VM without vsock (all of GCE) it fails the same way each time — 15x
#   each during one apt install, a false "Error burst" on a healthy boot:
#     systemd-ssh-generator[4605]: Failed to query local AF_VSOCK CID:
#         Cannot assign requested address
#     (sd-exec-[4590]: /usr/lib/systemd/system-generators/systemd-ssh-generator
#         failed with exit status 1.
_KNOWN_BENIGN = re.compile(
    r"Failed to query local AF_VSOCK CID: Cannot assign requested address"
    r"|/systemd-ssh-generator failed with exit status 1\."
)


def _quiet_known_benign(events: list[ParsedEvent]) -> list[ParsedEvent]:
    for e in events:
        if e.severity in _ERRORISH and _KNOWN_BENIGN.search(e.message):
            e.severity = Severity.INFO
    return events


def run_analysis(
    events: list[ParsedEvent],
    parser_format: str,
    log_path: str,
    baseline: object | None,
    config: AnalysisConfig,
    skipped_count: int = 0,
) -> AnalysisResult:
    events = _quiet_known_benign(_strip_tzinfo(events))
    window = timedelta(minutes=config.window_size_minutes)
    baseline_errors: float | None = getattr(baseline, "avg_errors_per_hour", None)

    signals: list[AnomalySignal] = []
    # Both analyze_error_rate (no-baseline path) and analyze_burst emit
    # "error_burst"; boot noise must be dropped from either.
    boot = _boot_phases(events)
    signals += _drop_boot_noise(
        analyze_error_rate(events, window, baseline_errors, config.spike_factor), boot
    )
    signals += _drop_boot_noise(analyze_burst(events, window, config.burst_multiplier), boot)
    signals += analyze_auth_failures(events, config.auth_failure_threshold, window)
    signals += analyze_oom_events(events)
    # Before service crashes: when a unit fails *because* its config was
    # rejected, the config error is the cause and should name the incident.
    signals += analyze_config_errors(events)
    signals += analyze_service_crashes(events)
    signals += analyze_disk_full(events)
    signals += analyze_job_outcomes(events)
    signals += analyze_policy_denials(events)
    signals += analyze_storage_faults(events)
    signals += analyze_backend_down(events)
    signals += analyze_uncaught_exception(events)
    signals += analyze_resource_limits(events)
    signals += analyze_tls_errors(events)
    signals += analyze_mail_rejects(events, window)
    signals += analyze_fatal_exit(events)
    signals += analyze_clock_jumps(events)
    signals += analyze_probe_failures(events)
    if not any(s.kind == "job_failure" for s in signals):
        signals += analyze_package_locks(events)
    signals += analyze_proxy_anomalies(events, config.auth_failure_threshold, window)
    signals = analyze_correlation(signals, timedelta(seconds=config.correlation_gap_seconds))
    signals.sort(key=_severity_rank)
    signals = _fold_redundant_bursts(signals, events)
    signals = [_with_evidence(s, events) for s in signals]

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
        severity_counts=dict(Counter(e.severity.value for e in events)),
        last_error=(_last_error(events) if not signals else None),
    )
