from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Literal, TypeGuard

from logcrux.models import (
    AnalysisResult,
    AnomalySignal,
    Finding,
    IncidentCategory,
    IncidentSummary,
    InferenceResult,
    Severity,
)

_CRITICAL_CATEGORIES = {IncidentCategory.OOM, IncidentCategory.SERVICE_CRASH}

_SIGNAL_TO_CATEGORY: dict[str, IncidentCategory] = {
    "oom_event": IncidentCategory.OOM,
    "service_crash": IncidentCategory.SERVICE_CRASH,
    "disk_full": IncidentCategory.DISK_FULL,
    "auth_failure_cluster": IncidentCategory.AUTH_BRUTE_FORCE,
    "proxy_denial_cluster": IncidentCategory.NETWORK_ISSUE,
    "tunnel_anomaly": IncidentCategory.NETWORK_ISSUE,
    "firewall_block_cluster": IncidentCategory.NETWORK_ISSUE,
}

_SIGNAL_REMEDIATION: dict[str, str] = {
    "proxy_denial_cluster": (
        "Review Squid ACL rules with `squid -k parse`. "
        "Check /etc/squid/squid.conf for overly broad deny rules. "
        "Audit denied client IPs in the access log."
    ),
    "tunnel_anomaly": (
        "CONNECT tunnels to non-standard ports may indicate data exfiltration. "
        "Review Squid SSL_bump config and consider blocking CONNECT to unusual ports via ACL."
    ),
    "firewall_block_cluster": (
        "A dense burst of firewall blocks usually means a port scan or a "
        "misconfigured client. Review the source IPs in the blocked events; "
        "rate-limit or drop persistent scanners upstream (e.g. `ufw deny from <ip>`)."
    ),
    "error_burst": (
        "Investigate the root service throwing errors. "
        "Check upstream connectivity and review recent config changes."
    ),
}

_REMEDIATION: dict[IncidentCategory, str] = {
    IncidentCategory.OOM: (
        "Check /proc/meminfo and `dmesg | grep -i oom`. "
        "Consider adding swap or tuning vm.overcommit_memory=2 in /etc/sysctl.conf."
    ),
    IncidentCategory.AUTH_BRUTE_FORCE: (
        "Block offending IPs with `firewall-cmd --add-rich-rule` or fail2ban. "
        "Review /var/log/secure for source IPs and consider disabling password auth in sshd_config."
    ),
    IncidentCategory.HTTP_OVERLOAD: (
        "Check upstream application health and CPU/memory. "
        "Review nginx/apache upstream timeout settings and consider rate limiting."
    ),
    IncidentCategory.DISK_FULL: (
        "Run `df -h` to identify full filesystem. "
        "Clear logs with `journalctl --vacuum-size=1G` or clean /tmp. "
        "Consider adding storage or rotating logs more aggressively."
    ),
    IncidentCategory.SERVICE_CRASH: (
        "Run `systemctl status <service>` and `journalctl -u <service> -n 50`. "
        "Check for segfaults with `dmesg | grep segfault`."
    ),
    IncidentCategory.CONFIG_ERROR: (
        "Validate config files with the service built-in check "
        "(e.g. `nginx -t`, `apache2ctl configtest`). "
        "Review recent config changes with `git log` or `rpm -qa --last`."
    ),
    IncidentCategory.NETWORK_ISSUE: (
        "Check connectivity with `ping`, `traceroute`, and `ss -tunp`. "
        "Review firewall rules with `firewall-cmd --list-all` or `iptables -L`."
    ),
}

# Human-friendly incident titles (the enum value .title() would render "Oom"
# and "Http Overload"). Falls back to a title-cased enum value when absent.
_CATEGORY_TITLES: dict[IncidentCategory, str] = {
    IncidentCategory.OOM: "Out of Memory",
    IncidentCategory.AUTH_BRUTE_FORCE: "Auth Brute Force",
    IncidentCategory.HTTP_OVERLOAD: "HTTP Overload",
    IncidentCategory.DISK_FULL: "Disk Full",
    IncidentCategory.SERVICE_CRASH: "Service Crash",
    IncidentCategory.CONFIG_ERROR: "Config Error",
    IncidentCategory.NETWORK_ISSUE: "Network Issue",
}

# Lexical evidence required before an AI-supplied category is trusted. The
# classifier is forced to pick one of 7 categories for every input, so on a
# generic error burst it still emits a confident guess (it labelled a benign
# macOS software-update log "Auth Brute Force" at 0.84). When the category comes
# from the AI alone (not a deterministic signal) we require at least one of these
# tokens in the representative events; otherwise the named incident is
# unfalsifiable and erodes trust, so we fall back to a generic burst title.
#
# Tokens are matched as **whole words** — substring matching repeats the bug it
# was meant to fix ("auth" hit "authoring" in the very install.log above), so
# every inflection ("connect"/"connection") must be listed explicitly.
_CATEGORY_EVIDENCE: dict[IncidentCategory, tuple[str, ...]] = {
    IncidentCategory.AUTH_BRUTE_FORCE: (
        "auth", "authentication", "failed login", "login failed",
        "failed logon", "logon failure", "password",
        "passwd", "credential", "credentials", "sshd", "ssh", "invalid user",
        "fail2ban", "unauthorized", "permission denied", "access denied",
        "sudo", "pam", "brute", "authorization",
        # NOTE: bare "denied" is deliberately excluded. Kernel MAC-policy
        # denials (AppArmor `apparmor="DENIED"`, SELinux `avc: denied`) are
        # access-control events, not credential brute force; matching bare
        # "denied" surfaced an AppArmor burst as "Auth Brute Force". The
        # qualified phrases above keep real SSH/sudo auth denials covered.
        #
        # NOTE: bare "login"/"logon" are likewise excluded — they appear in
        # non-auth contexts (Blue Gene `ciod: LOGIN chdir() failed` job-startup
        # I/O, Windows logon-type INFO lines), which surfaced a kernel RAS error
        # burst as "Auth Brute Force". Only the qualified failure phrases above
        # count as brute-force evidence. Real auth bursts also carry
        # "password"/"authentication"/"invalid user", and a genuine auth-failure
        # cluster is a deterministic signal that bypasses this gate entirely.
    ),
    IncidentCategory.HTTP_OVERLOAD: (
        "http", "request", "requests", "upstream", "gateway", "nginx",
        "gunicorn", "worker", "workers", "502", "503", "504", "too many",
        "throttled", "throttling", "rate limit", "overload",
    ),
    IncidentCategory.DISK_FULL: (
        "disk", "no space", "space left", "quota", "enospc", "filesystem",
        "write failed", "read-only", "full",
    ),
    IncidentCategory.SERVICE_CRASH: (
        "crash", "crashed", "segfault", "segmentation", "core dump",
        "core-dump", "panic", "exited", "killed", "terminated", "abort",
        "aborted", "signal", "traceback", "exception", "dumped", "coredump",
    ),
    IncidentCategory.CONFIG_ERROR: (
        "config", "configuration", "parse", "parsing", "syntax", "invalid",
        "directive", "malformed", "unexpected",
    ),
    IncidentCategory.NETWORK_ISSUE: (
        "network", "connection", "connections", "connect", "unreachable",
        "refused", "dns", "resolve", "timed out", "timeout", "no route",
        "reset by peer", "socket", "tls", "handshake",
    ),
    IncidentCategory.OOM: (
        "out of memory", "oom", "memory", "cannot allocate", "killed process",
    ),
}

# Pre-compiled whole-word matcher per category. ``\b`` around the alternation
# anchors on the first/last (word) char of each token, so phrases like
# "no space" and "reset by peer" still match while bare "auth" no longer hits
# "authoring".
_CATEGORY_EVIDENCE_RE: dict[IncidentCategory, re.Pattern[str]] = {
    cat: re.compile(r"\b(?:" + "|".join(re.escape(k) for k in kws) + r")\b", re.I)
    for cat, kws in _CATEGORY_EVIDENCE.items()
}


def _inference_supported(
    inference: InferenceResult, signals: list[AnomalySignal]
) -> bool:
    """True when the AI-supplied category has lexical support in the events.

    Without this, a confident classifier guess on generic error noise becomes a
    fabricated incident label (e.g. "Auth Brute Force" on an install log).
    """
    pattern = _CATEGORY_EVIDENCE_RE.get(inference.category)
    if pattern is None:
        return True
    text = " ".join(
        e.message for s in signals for e in s.representative_events
    )
    return pattern.search(text) is not None


_SIGNAL_HEADLINES: dict[str, str] = {
    "error_burst": "Error burst detected",
    "rate_spike": "Error rate spike vs baseline",
    "auth_failure_cluster": "Authentication failure cluster",
    "oom_event": "OOM killer fired",
    "service_crash": "Service crashed",
    "disk_full": "Disk full event",
    "proxy_denial_cluster": "Proxy ACL denial cluster",
    "firewall_block_cluster": "Firewall block flood",
    "tunnel_anomaly": "Suspicious CONNECT tunnel detected",
    "unknown": "Anomalous event cluster",
}


def _signal_finding(signal: AnomalySignal) -> Finding:
    headline = _SIGNAL_HEADLINES.get(signal.kind, signal.kind.replace("_", " ").title())
    detail = f"{signal.event_count} events in {signal.window.duration_seconds:.0f}s window"
    if signal.baseline_count is not None:
        if signal.kind == "rate_spike":
            # baseline_count is errors/hour, so compare it against the current
            # errors/hour rather than the raw event count (different units).
            hours = max(signal.window.duration_seconds / 3600, 1 / 3600)
            current_rate = signal.event_count / hours
            ratio = current_rate / max(signal.baseline_count, 0.001)
        else:
            ratio = signal.event_count / max(signal.baseline_count, 0.001)
        detail += f" ({ratio:.1f}× baseline)"
    return Finding(headline=headline, detail=detail)


def _category_from_signals(signals: list[AnomalySignal]) -> IncidentCategory:
    for signal in signals:
        if signal.kind in _SIGNAL_TO_CATEGORY:
            return _SIGNAL_TO_CATEGORY[signal.kind]
    return IncidentCategory.UNKNOWN


def _inference_usable(inference: InferenceResult | None) -> TypeGuard[InferenceResult]:
    """True when the classifier returned a category it was confident enough to
    report. The classifier already enforces the configured confidence threshold
    (returning UNKNOWN / 0.0 below it), so the summarizer trusts any concrete,
    non-zero result rather than re-applying a second hardcoded threshold.

    Returns a TypeGuard so callers get ``inference`` narrowed to non-None.
    """
    return (
        inference is not None
        and inference.confidence > 0
        and inference.category != IncidentCategory.UNKNOWN
    )


def _assign_level(
    signals: list[AnomalySignal],
    ai_category: IncidentCategory | None,
) -> Literal["CRITICAL", "WARNING", "INFO", "CLEAN"]:
    if not signals:
        return "CLEAN"
    any_critical = any(s.severity == Severity.CRITICAL for s in signals)
    if ai_category in _CRITICAL_CATEGORIES:
        return "CRITICAL"
    return "CRITICAL" if any_critical else "WARNING"


def summarize(
    analysis: AnalysisResult,
    inference: InferenceResult | None,
    elapsed_seconds: float,
) -> IncidentSummary:
    # The AI category is trusted only when it clears the confidence threshold
    # *and* has lexical support in the events (see _inference_supported).
    ai_category: IncidentCategory | None = None
    if _inference_usable(inference) and _inference_supported(inference, analysis.signals):
        ai_category = inference.category

    level = _assign_level(analysis.signals, ai_category)
    # Category precedence: a specific deterministic signal (oom_event,
    # disk_full, auth_failure_cluster, ...) is a high-precision keyword match
    # and the most trustworthy root cause, so it wins. The AI classifier fills
    # the gap only when the signals are generic (error_burst / rate_spike),
    # where it adds real value by naming the incident type.
    signal_category = _category_from_signals(analysis.signals)
    category: IncidentCategory
    if signal_category != IncidentCategory.UNKNOWN:
        category = signal_category
    elif ai_category is not None:
        category = ai_category
    else:
        category = IncidentCategory.UNKNOWN
    if level == "CLEAN":
        confidence = 1.0
    elif category == IncidentCategory.UNKNOWN:
        # A real burst we deliberately would not attach an AI label to; surfacing
        # the rejected classifier confidence here would overclaim, so report a
        # neutral statistical confidence instead.
        confidence = 0.5
    elif signal_category != IncidentCategory.UNKNOWN:
        # Category came from a deterministic keyword signal (OOM, auth failure, …) —
        # high confidence regardless of whether AI inference ran. Blend with AI
        # confidence when available; default to 0.9 when inference is disabled.
        confidence = max(inference.confidence, 0.9) if inference else 0.9
    else:
        confidence = inference.confidence if inference else 0.0
    remediation = None
    if level not in ("CLEAN", "INFO"):
        # Signal-specific advice (e.g. Squid ACL guidance for proxy_denial_cluster)
        # is more actionable than the generic per-category remediation, so prefer
        # it for the headline signal and only fall back to the category text.
        if analysis.signals:
            remediation = _SIGNAL_REMEDIATION.get(analysis.signals[0].kind)
        if remediation is None:
            remediation = _REMEDIATION.get(category)

    findings = [_signal_finding(s) for s in analysis.signals[:5]]

    if not findings and level == "CLEAN":
        title = "No incidents detected"
    elif category != IncidentCategory.UNKNOWN:
        title = _CATEGORY_TITLES.get(category, category.value.replace("_", " ").title())
    else:
        title = findings[0].headline if findings else "Anomaly detected"

    return IncidentSummary(
        level=level,
        title=title,
        findings=findings,
        confidence=confidence,
        category=category,
        remediation=remediation,
        log_path=analysis.log_path,
        parser_format=analysis.parser_format,
        analyzed_at=datetime.now(UTC),
        parsed_count=analysis.parsed_count,
        skipped_count=analysis.skipped_count,
        elapsed_seconds=elapsed_seconds,
    )
