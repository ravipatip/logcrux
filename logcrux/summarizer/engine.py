from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Literal, TypeGuard

from logcrux.analysis.anomaly import apparmor_denial, avc_denial, storage_fault_kind
from logcrux.analysis.evidence import evidence_events
from logcrux.models import (
    AnalysisResult,
    AnomalySignal,
    EvidenceLine,
    Finding,
    IncidentCategory,
    IncidentSummary,
    InferenceResult,
    ParsedEvent,
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
    # A SELinux denial of a service is a labelling/policy configuration fault
    # (wrong file context, port not in the service's type) far more often
    # than an attack.
    "policy_denial": IncidentCategory.CONFIG_ERROR,
    "config_error": IncidentCategory.CONFIG_ERROR,
    "backend_down": IncidentCategory.HTTP_OVERLOAD,
    "uncaught_exception": IncidentCategory.SERVICE_CRASH,
    # A refused certificate breaks the connection: the legacy category that
    # names it is network. resource_limit and mail_reject_cluster keep their
    # own titles (none of the 7 describes them).
    "tls_error": IncidentCategory.NETWORK_ISSUE,
    "fatal_exit": IncidentCategory.SERVICE_CRASH,
    # A failing health check: the closest legacy category is a crashing service.
    "probe_failure": IncidentCategory.SERVICE_CRASH,
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
    "policy_denial": (
        "A mandatory access control policy (SELinux or AppArmor) blocked a "
        "program. AppArmor: `aa-status`, then adjust the profile in "
        "/etc/apparmor.d and reload with `apparmor_parser -r`. SELinux: explain it "
        "with `ausearch -m avc -ts recent | "
        "audit2why`. Mislabelled files: `restorecon -Rv <path>` (or `semanage fcontext`); "
        "a service on a non-standard port: `semanage port -a -t <type> -p tcp <port>`. "
        "Prefer a targeted fix over `setenforce 0`."
    ),
    "storage_fault": (
        "The kernel reported a storage fault. Check the device with `dmesg -T`, "
        "`smartctl -a <dev>` and `cat /proc/mdstat`; replace a failed RAID member "
        "with `mdadm --manage <md> --add <dev>`. A filesystem remounted read-only "
        "needs fsck after the underlying device is fixed — do not just remount rw."
    ),
    "job_failure": (
        "A job (e.g. a backup run) did not complete. The failing line is in the "
        "representative events — fix its cause (credentials, missing source, "
        "unreachable or missing repository) and re-run; for a partial backup, "
        "check which files could not be read and whether the snapshot is usable."
    ),
    "backend_down": (
        "The proxy has no healthy backend. Check the backend service itself "
        "(`systemctl status`, `docker ps -a`, its own log) and that it listens on the "
        "address the proxy checks (`ss -ltnp`); the 5xx responses stop once one server "
        "passes its health check."
    ),
    "uncaught_exception": (
        "The process exited on an exception it did not handle; the evidence line is "
        "the exception and the lines above it in the log are its stack. Fix the cause "
        "it names (a missing file, an unreachable dependency, bad input), or catch and "
        "log it; check the restart policy if the service should have come back."
    ),
    "probe_failure": (
        "A Kubernetes health check is failing: liveness failures restart the container, "
        "readiness failures keep it out of its Service. `kubectl describe pod <pod>` shows "
        "the probe and its last output; check the endpoint/command the probe calls, its "
        "timeouts and initialDelaySeconds, and `kubectl logs <pod> --previous`."
    ),
    "clock_jump": (
        "The system clock jumped. Timestamps around it are unreliable, and TLS, "
        "Kerberos and cron misbehave while it is wrong. Check `chronyc tracking` / "
        "`timedatectl`, find what set the time (a manual `date -s`, a VM restore or "
        "migration, a bad NTP source in `chronyc sources`), and keep one time daemon."
    ),
    "fatal_exit": (
        "The program logged a fatal error as its last record and stopped. The record "
        "says why (often a dependency it could not reach, as in the errors above it); "
        "fix that, then check the restart policy brought it back."
    ),
    "resource_limit": (
        "A process hit an operating-system or server limit. Open files: raise the "
        "service's limit (systemd `LimitNOFILE=`, `ulimit -n`, docker `--ulimit nofile=`, "
        "nginx `worker_rlimit_nofile`) and look for leaked connections; processes: "
        "`ulimit -u`, systemd `TasksMax=`, docker `--pids-limit`; connections: the "
        "server's max-connections setting and the client's pooling."
    ),
    "tls_error": (
        "A TLS peer's certificate was refused. Check it with `openssl s_client -connect "
        "host:443 -servername host | openssl x509 -noout -dates -subject`: renew an "
        "expired certificate, fix the name, or install the issuing CA on the client. "
        "Do not disable verification."
    ),
    "mail_reject_cluster": (
        "The mail server refused a burst of messages. Read the reject reason in the "
        "evidence: a relay or spam attempt (block the client IP, check that the server is "
        "not an open relay with `postconf mynetworks smtpd_relay_restrictions`), or a "
        "local sender whose domain or DNS is broken."
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
        "Look at what the evidence lines name. A systemd unit: `systemctl status <unit>` "
        "and `journalctl -u <unit> -n 50`; a container: `docker logs --tail 100 <name>` "
        "or `kubectl describe pod <pod>` and `kubectl logs <pod> --previous`. "
        "Segfaults: `dmesg | grep segfault`."
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


# Signals none of the 7 legacy categories describes. They keep category
# "unknown", carry their own title, and the classifier may not relabel them.
_OWN_TITLE_KINDS = frozenset({"job_failure", "storage_fault", "resource_limit",
                              "mail_reject_cluster", "clock_jump"})

_GENERIC_KINDS = frozenset({"error_burst", "rate_spike"})
_TLS_REASON_RE = re.compile(
    r"(?:certificate verify failed: )?(?:certificate has expired|certificate is not yet valid"
    r"|self[- ]signed certificate[^,;)>]*|unable to get local issuer certificate"
    r"|x509: [^,;)>]+|hostname mismatch[^,;)>]*|SSL certificate problem: [^,;)>]+"
    r"|error=certificate has expired[^,;)>]*)"
)

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
    "job_failure": "Job failed",
    "config_error": "Configuration rejected",
    "backend_down": "Backend server down",
    "uncaught_exception": "Process died: unhandled exception",
    "resource_limit": "Resource limit reached",
    "tls_error": "TLS certificate rejected",
    "mail_reject_cluster": "Mail rejected in bulk",
    "fatal_exit": "Process exited after a fatal error",
    "clock_jump": "System clock jumped",
    "probe_failure": "Health check failing",

    "unknown": "Anomalous event cluster",
}


def _signal_finding(signal: AnomalySignal) -> Finding:
    """The headline finding for a signal, with the evidence a human (or an
    agent) needs to check it: what it is about, when, and the lines."""
    finding = _headline_finding(signal)
    finding.kind = signal.kind
    finding.count = signal.event_count
    finding.first_seen = signal.window.start if signal.window.duration_seconds or any(
        e.timestamp for e in signal.representative_events) else None
    finding.last_seen = signal.window.end if finding.first_seen else None
    finding.subjects = signal.subjects
    finding.evidence = [
        _evidence_line(e)
        for e in (signal.evidence or evidence_events(signal.representative_events))
    ]
    return finding


def _evidence_line(e: ParsedEvent) -> EvidenceLine:
    return EvidenceLine(line=e.line_number, timestamp=e.timestamp, source=e.source or None,
                        text=e.raw.strip()[:500] or e.message[:500],
                        message=" ".join(e.message.split("\n", 1)[0].split())[:500])


def _headline_finding(signal: AnomalySignal) -> Finding:
    if signal.kind == "tls_error" and signal.representative_events:
        # The reason, not the app's whole log line around it.
        msg = signal.representative_events[0].message
        m = _TLS_REASON_RE.search(msg)
        reason = m[0] if m else msg
        return Finding(headline=_SIGNAL_HEADLINES[signal.kind],
                       detail=" ".join(reason.split())[:200])
    if signal.kind in ("uncaught_exception", "backend_down", "resource_limit",
                       "fatal_exit") \
            and signal.representative_events:
        first = signal.representative_events[0]
        return Finding(headline=_SIGNAL_HEADLINES[signal.kind],
                       detail=" ".join(first.message.split("\n", 1)[0].split())[:300])
    if signal.kind == "job_failure":
        # The count is meaningless here (one Fatal line); the parser's own
        # account of why the job ended is what the operator needs.
        lead = signal.representative_events[0] if signal.representative_events else None
        partial = signal.severity == Severity.WARNING
        why = str(lead.extra.get("detail") or lead.message) if lead else ""
        return Finding(
            headline="Job completed with missing data" if partial else "Job failed",
            detail=why[:300],
        )
    if signal.kind == "storage_fault" and signal.representative_events:
        kinds = [storage_fault_kind(e) for e in signal.representative_events]
        # Most consequential first: a degraded array, then a filesystem that
        # stopped accepting writes, then raw I/O errors.
        for k, headline in (("raid", "RAID array degraded"),
                            ("readonly", "Filesystem remounted read-only"),
                            ("io", "Disk I/O errors")):
            if k in kinds:
                first = signal.representative_events[kinds.index(k)]
                return Finding(headline=headline, detail=" ".join(first.message.split())[:300])
    if signal.kind == "policy_denial" and signal.representative_events:
        aa = apparmor_denial(signal.representative_events[0])
        if aa:
            what = aa["name"] or aa["op"]
            return Finding(
                headline="AppArmor denied access",
                detail=(f"{aa['comm'] or aa['profile']} denied {aa['op']} on {what} "
                        f"(profile {aa['profile']}), {signal.event_count} denial(s)"),
            )
        m = avc_denial(signal.representative_events[0])
        if m:
            return Finding(
                headline="SELinux denied access",
                detail=(f"{m['comm']} denied {{{m['perm']}}} on {m['ttype']} "
                        f"({m['tclass']}), {signal.event_count} denial(s)"),
            )
    headline = _SIGNAL_HEADLINES.get(signal.kind, signal.kind.replace("_", " ").title())
    detail = f"{signal.event_count:,} event{'s' if signal.event_count != 1 else ''}"
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


# An unhandled exception whose class says the configuration was rejected
# (real Kafka 3.8: 'Exception in thread "main" org.apache.kafka.common.config.
# ConfigException: Missing required configuration ...') is a config error
# first: the process died *because* it could not start with that config.
_CONFIG_EXCEPTION_RE = re.compile(r"\bConfig(?:uration)?Exception\b|\bInvalidConfiguration")


def _category_from_signals(signals: list[AnomalySignal]) -> IncidentCategory:
    for signal in signals:
        if signal.kind == "uncaught_exception" and any(
                _CONFIG_EXCEPTION_RE.search(e.message) for e in signal.representative_events):
            return IncidentCategory.CONFIG_ERROR
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
    # A job failure is a parser-declared outcome, not a pattern to classify.
    # None of the 7 legacy categories describes "the backup did not run", and
    # the classifier would name a wrong-repository-password abort "Auth Brute
    # Force" — so it does not get to relabel one.
    job_failed = any(s.kind in _OWN_TITLE_KINDS for s in analysis.signals)
    if (not job_failed and _inference_usable(inference)
            and _inference_supported(inference, analysis.signals)):
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
    elif job_failed:
        # The parser read the job's own terminal line ("Fatal: ..."); that is
        # a statement of fact, not a statistical guess.
        confidence = 0.9
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
        # A generic burst's advice ("investigate the root service") is the
        # last resort: a named category's remediation is more specific.
        lead = next((s for s in analysis.signals if s.kind not in _GENERIC_KINDS), None)
        if lead is not None:
            remediation = _SIGNAL_REMEDIATION.get(lead.kind)
            if lead.kind == "service_crash" and any(
                    "WORKER TIMEOUT" in e.message for e in lead.representative_events):
                remediation = (
                    "The server killed a worker whose request ran past its timeout "
                    "(gunicorn -t / --timeout). Find the slow endpoint in the evidence and "
                    "fix what it waits on; raise the timeout only for work that is "
                    "legitimately long, and move that work off the request path."
                )
        if remediation is None:
            remediation = _REMEDIATION.get(category)
        if remediation is None and analysis.signals:
            remediation = _SIGNAL_REMEDIATION.get(analysis.signals[0].kind)

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
        time_range=analysis.time_range,
        severity_counts=analysis.severity_counts,
        last_error=(_evidence_line(analysis.last_error)
                    if analysis.last_error is not None and level == "CLEAN" else None),
    )
