from __future__ import annotations

import re
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
# OpenSSH PerSourcePenalties (9.8+; seen on Debian 13, RHEL 9.8/10, Rocky 9,
# Alma 10, CentOS Stream 10, Leap 16) throttles a guessing source itself and
# logs the refusals instead of more "Failed password" lines:
#   sshd[960]: drop connection #0 from [10.0.0.5]:49966 on [10.0.0.4]:22
#       penalty: failed authentication
# On a real Debian 13 VM a 48-attempt brute force produced only 12 "Failed
# password" lines; the rest of the attack is these. ("penalty: connections
# without attempting authentication" is scanner behaviour, not guessing, and
# is deliberately not counted.)
_AUTH_KEYWORDS = frozenset([
    "failed password", "invalid user", "authentication failure", "invalid credentials",
    # MySQL/MariaDB with log_warnings>=2: "[Warning] Access denied for user
    # 'root'@'localhost' (using password: YES)" — 40 of them on 6 real distros
    # formed no cluster before this was added.
    "access denied for user",
    # sudo logs ONE pam "authentication failure" per run, however many
    # passwords were tried, then "lcop : 3 incorrect password attempts ; ...".
    # On real SLES 15 SP5, 18 wrong passwords left 6 auth lines — below the
    # cluster threshold — until the summary line counted too.
    "incorrect password attempt",
    # Debian/Ubuntu: a non-sudoer gets one password prompt, then
    #   lcop : user NOT in sudoers ; PWD=/home/lcop ; USER=root ; COMMAND=...
    # — an unauthorized privilege attempt (real Debian 12 / Ubuntu VMs).
    "user not in sudoers",
    "penalty: failed authentication",
    # MongoDB 6+/7 structured log, at severity "I":
    #   {"s":"I","c":"ACCESS",...,"msg":"Failed to authenticate","attr":{"user":"root",...
    # (real mongo:7 container, 25 wrong passwords: reported CLEAN before).
    "failed to authenticate",
    # PostgreSQL, every version (real PG 13-18 on 12 distros and the official
    # image): 'FATAL:  password authentication failed for user "postgres"'.
    # Without it a PG brute force was only an error burst, named by the
    # classifier when it happened to agree.
    "password authentication failed",
    # Keycloak's event log (real 26.0, lab/apps4, 2026-10-20):
    #   WARN [org.keycloak.events] type="LOGIN_ERROR", ..., ipAddress="127.0.0.1",
    #       error="invalid_user_credentials", ..., username="admin"
    "error=\"invalid_user_credentials\"", "error=\"user_not_found\"",
    # OpenLDAP slapd stats (real 2.6): a bind's BindResponse (tag=97) with
    # resultCode 49, invalidCredentials:  conn=1000 op=0 RESULT tag=97 err=49
    "result tag=97 err=49",
    # Mosquitto 2.0 (real broker, lab/apps5): a client with a wrong password:
    #   1792443845: Client auto-BBE388AA-... disconnected, not authorised.
    "disconnected, not authorised", "disconnected, not authorized",
    # Service-neutral wordings, each an authentication failure by definition:
    # five held-out rounds (2026-10-20) found most first-contact misses were
    # one service's private phrasing of exactly this. A cluster still needs
    # >= 10 inside one window, so a stray line never alarms.
    "authentication failed", "login failed", "invalid password", "wrong password",
    "bad password", "invalid username or password", "incorrect username or password",
    # Samba (real dperson/samba, log level 2, lab/apps9) — counted on the
    # check_ntlm_password line only; the same attempt is also logged as an
    # "Auth:" line and a JSON audit record:
    #   check_ntlm_password:  Authentication for user [alice] -> [alice] FAILED with error
    #       NT_STATUS_WRONG_PASSWORD, authoritative=1
    "failed with error nt_status_wrong_password", "failed with error nt_status_no_such_user",
    "failed with error nt_status_logon_failure",
])
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
    # Redis/Valkey bug report: "# Redis 6.2.24 crashed by signal: 11, si_code: 1"
    "crashed by signal",
    # PHP: the script died on an uncaught error; php-fpm relays it per request
    # (real php 8.3-fpm, lab/apps4):
    #   NOTICE: PHP message: PHP Fatal error:  Uncaught Error: Call to undefined function ...
    "php fatal error",
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
# PostgreSQL >= 15 reports ENOSPC as "No space left on device"; 13 and 14 (RHEL
# 9, Ubuntu 22.04 — real GCP VMs, 2026-10-13) say only
#   ERROR:  could not extend file "base/13494/16384": wrote only 4096 of 8192 bytes
#   HINT:  Check free disk space.
# and reported a full data volume as CLEAN until these were added.
_DISK_FULL_KEYWORDS = frozenset([
    "no space left on device", "disk full", "quota exceeded",
    "could not extend file", "check free disk space",
])
# PostgreSQL logs a crashed backend, and the crash recovery it forces, entirely
# at LOG level — so no severity-driven detector ever sees it (12/12 distros
# reported a SIGKILLed backend as CLEAN). The postmaster's wording is specific:
#   LOG:  server process (PID 1997) was terminated by signal 9: Killed     (<= 17)
#   LOG:  client backend (PID 3168) was terminated by signal 9: Killed     (18)
#   LOG:  database system was not properly shut down; automatic recovery in progress
_PG_CRASH_RE = re.compile(
    r"\(pid \d+\) was terminated by (?:signal|exception)"
    r"|not properly shut down; automatic recovery in progress"
    # Recovery MariaDB performs only after it was killed mid-flight (real GCP
    # VMs, mariadbd SIGKILLed; 10.3: both lines, 10.5: the InnoDB one):
    #   [Note] InnoDB: Starting crash recovery from checkpoint LSN=45079
    #   [Note] Starting crash recovery...
    # Anchored on that exact phrasing: RHEL's kdump unit logs "Starting Crash
    # recovery kernel arming" on every boot, which a bare "starting crash
    # recovery" turned into a CRITICAL false alarm on healthy RHEL/Rocky boots.
    # MariaDB 11.8 (openSUSE Leap 16): "[Note] Starting table crash recovery..."
    r"|starting (?:table )?crash recovery(?: from checkpoint|\.\.\.)"
)


# Vocabulary-free fallback: an authentication noun and a failure word in the
# same line. Nine held-out rounds (2026-10-20) kept finding services whose
# auth failures were a private phrasing of exactly this (Keycloak
# LOGIN_ERROR/invalid_user_credentials, Samba "Authentication ... FAILED",
# MongoDB "Failed to authenticate"). A cluster still needs >= 10 in a window.
_AUTH_NOUN = r"(?:authenticat\w*|log[ -]?in|logon|password|passwd|credentials?)"
_AUTH_FAIL = r"(?:fail\w*|denied|invalid|incorrect|wrong|rejected|unauthori[sz]ed|mismatch)"
_AUTH_GENERIC_RE = re.compile(
    rf"\b{_AUTH_NOUN}\b[^\n]{{0,80}}?\b{_AUTH_FAIL}\b|\b{_AUTH_FAIL}\b[^\n]{{0,80}}?\b{_AUTH_NOUN}\b",
    re.I,
)


def _is_auth_failure(event: ParsedEvent) -> bool:
    msg = event.message.lower()
    if any(kw in msg for kw in _AUTH_KEYWORDS):
        return True
    return _AUTH_GENERIC_RE.search(event.message) is not None


# The JVM error class, not the -XX:+HeapDumpOnOutOfMemoryError family of
# flags that every Elasticsearch/Kafka start prints in its JVM arguments line.
_JVM_OOM_RE = re.compile(r"\bjava\.lang\.OutOfMemoryError\b|(?<![A-Za-z+])OutOfMemoryError:")


# gunicorn kills a hung worker itself, then guesses (real gunicorn 23 in a
# container, 2026-10-20):
#   [CRITICAL] WORKER TIMEOUT (pid:11)
#   [ERROR] Worker (pid:11) was sent SIGKILL! Perhaps out of memory?
# The question is not evidence of an OOM — read as one, a request timeout
# became a CRITICAL "Out of Memory". The timeout is its own crash signal.
_OOM_SPECULATION = "perhaps out of memory?"
_WORKER_TIMEOUT_RE = re.compile(r"\bWORKER TIMEOUT \(pid:\d+\)")


# `docker inspect` of every container carries the flag, true or false:
#   "OOMKilled": false,      <- a healthy container (real docker 29, lab/apps10:
#                               reported CRITICAL "Out of Memory" before this)
_OOMKILLED_FALSE_RE = re.compile(r"oomkilled\"?\s*[:=]\s*\"?false", re.I)


def _is_oom_event(event: ParsedEvent) -> bool:
    msg = event.message.lower()
    if _OOM_SPECULATION in msg or _OOMKILLED_FALSE_RE.search(msg):
        return False
    if any(kw in msg for kw in _OOM_KEYWORDS):
        return True
    return "outofmemoryerror" in msg and _JVM_OOM_RE.search(event.message) is not None


def _is_service_crash(event: ParsedEvent) -> bool:
    if _WORKER_TIMEOUT_RE.search(event.message):
        return True
    msg = event.message.lower()
    if any(kw in msg for kw in _SERVICE_CRASH_KEYWORDS) or _PG_CRASH_RE.search(msg):
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


# A parser that understands a job's lifecycle (backup tools first: restic)
# declares how the run ended in ``extra["outcome"]``. A job that fails is
# usually ONE line — "Fatal: wrong password or no key found" — which no
# volume/burst detector can see: on 12 real distros every induced restic
# failure was reported CLEAN. This trusts the parser's explicit declaration
# rather than any severity keyword, so it cannot fire on prose.
_FAILED_OUTCOMES = frozenset({"aborted", "interrupted", "failed"})
_DEGRADED_OUTCOMES = frozenset({"partial"})


def analyze_job_outcomes(events: list[ParsedEvent]) -> list[AnomalySignal]:
    failed = [e for e in events if e.extra.get("outcome") in _FAILED_OUTCOMES]
    degraded = [e for e in events if e.extra.get("outcome") in _DEGRADED_OUTCOMES]
    matched, severity = (failed, Severity.ERROR) if failed else (degraded, Severity.WARNING)
    if not matched:
        return []
    return [AnomalySignal(
        kind="job_failure",
        window=_make_window(matched),
        event_count=len(matched),
        baseline_count=None,
        severity=severity,
        representative_events=matched[:20],
    )]


# SELinux enforcing a denial — the record auditd writes (and the kernel relays
# to the journal as "audit: type=1400 ... avc: denied"):
#   avc:  denied  { name_bind } for pid=5452 comm="nginx" src=8081
#     scontext=system_u:system_r:httpd_t:s0
#     tcontext=system_u:object_r:transproxy_port_t:s0 tclass=tcp_socket permissive=0
# Real, on RHEL/Rocky/Alma/CentOS (GCP, 2026-10-13): a service on a non-standard
# port and a mislabelled docroot — both reported CLEAN before, though the first
# stops nginx from starting. permissive=1 records are logged but not enforced,
# so they are not counted.
_AVC_DENIED_RE = re.compile(
    r"avc:\s+denied\s+\{\s*(?P<perm>[^}]+?)\s*\}.*?comm=\"(?P<comm>[^\"]+)\""
    r".*?tcontext=[^:\s]+:[^:\s]+:(?P<ttype>[A-Za-z0-9_]+)\S*\s+tclass=(?P<tclass>\S+)"
    r"(?:.*?permissive=(?P<permissive>[01]))?"
)


def avc_denial(event: ParsedEvent) -> re.Match[str] | None:
    m = _AVC_DENIED_RE.search(event.message)
    if m is None or m["permissive"] == "1":
        return None
    return m


# AppArmor (Debian/Ubuntu/SUSE), from the kernel audit record:
#   audit: type=1400 ...: apparmor="DENIED" operation="open" profile="/usr/local/bin/lcread"
#     name="/etc/hostname" comm="lcread" requested_mask="r" denied_mask="r"
# Unlike SELinux, stock Ubuntu boots carry a few benign denials (dhclient
# refused exec of /usr/bin/true; an ubuntu_pro profile refused a capability):
# at most 4 per profile+operation across 6 healthy GCP boots, against 9 for an
# induced, persistent denial (30 attempts, compressed by audit rate limiting).
# So AppArmor counts only when one profile is refused the same operation
# _APPARMOR_MIN times.
_APPARMOR_RE = re.compile(
    r'apparmor="DENIED" operation="(?P<op>[^"]+)".*?profile="(?P<profile>[^"]+)"'
    r'(?:.*?name="(?P<name>[^"]*)")?(?:.*?comm="(?P<comm>[^"]*)")?'
)
_APPARMOR_MIN = 5


def apparmor_denial(event: ParsedEvent) -> re.Match[str] | None:
    return _APPARMOR_RE.search(event.message)


def analyze_policy_denials(events: list[ParsedEvent]) -> list[AnomalySignal]:
    matched = [e for e in events if avc_denial(e)]
    groups: dict[tuple[str, str], list[ParsedEvent]] = {}
    for e in events:
        m = apparmor_denial(e)
        if m:
            groups.setdefault((m["profile"], m["op"]), []).append(e)
    for denied in groups.values():
        if len(denied) >= _APPARMOR_MIN:
            matched.extend(denied)
    if not matched:
        return []
    return [AnomalySignal(
        kind="policy_denial",
        window=_make_window(matched),
        event_count=len(matched),
        baseline_count=None,
        severity=Severity.ERROR,
        representative_events=matched[:20],
    )]


# Kernel storage faults — wordings captured on real GCP VMs (2026-10-13) from
# a dm-error device, an mdadm RAID-1 member failure and ext4 on dm-flakey:
#   Buffer I/O error on dev dm-0, logical block 2544, async page read
#   md/raid1:md127: Disk failure on loop1, disabling device.
#   EXT4-fs error (device dm-0) in __ext4_new_inode:1093: IO failure
#   JBD2: I/O error when updating journal superblock for dm-0-8.
#   EXT4-fs (dm-0): Remounting filesystem read-only
# All were reported CLEAN on every distro: one or two kernel lines, no burst,
# and none of the 7 legacy categories is "the disk is failing".
_STORAGE_RAID_RE = re.compile(r"md/raid\d+:\S+: Disk failure on ")
_STORAGE_RO_RE = re.compile(r"Remounting filesystem read-only")
_STORAGE_IO_RE = re.compile(
    r"Buffer I/O error on dev |EXT4-fs error \(device |JBD2: I/O error |"
    r"EXT4-fs \(\S+\): I/O error "
)


def storage_fault_kind(event: ParsedEvent) -> str | None:
    msg = event.message
    if _STORAGE_RAID_RE.search(msg):
        return "raid"
    if _STORAGE_RO_RE.search(msg):
        return "readonly"
    if _STORAGE_IO_RE.search(msg):
        return "io"
    return None


def analyze_storage_faults(events: list[ParsedEvent]) -> list[AnomalySignal]:
    matched = [e for e in events if storage_fault_kind(e)]
    if not matched:
        return []
    return [AnomalySignal(
        kind="storage_fault",
        window=_make_window(matched),
        event_count=len(matched),
        baseline_count=None,
        severity=Severity.CRITICAL,
        representative_events=matched[:20],
    )]


# A service refusing its own configuration. nginx, real RHEL/Alma/Rocky VMs:
#   nginx: [emerg] unknown directive "lcbogus_directive" in /etc/nginx/conf.d/lc-bad.conf:1
#   nginx: configuration file /etc/nginx/nginx.conf test failed
# The unit failure that follows matched service_crash and named the incident
# a crash; the config error is the cause, so it is its own signal.
# Kubernetes refusing a pod spec's image reference (real k3s 1.31 kubelet,
# `kubectl describe pod` / `get events`): a typo'd tag or a private registry
# without credentials — configuration, and the pod never starts.
# Tomcat refusing its server.xml (real 10.1 container, lab/apps3):
#   SEVERE [main] ...Digester.fatalError Parse fatal error at line [163] column [1]
#   SEVERE [main] ...Catalina.start Cannot start server, server instance is not configured
_CONFIG_ERROR_RE = re.compile(
    r"\[emerg\] unknown directive|configuration file \S+ test failed"
    r"|Parse fatal error at line \[\d+\]|server instance is not configured"
    # Prometheus / Alertmanager refusing prometheus.yml (real 2.55, lab/apps5):
    #   level=error msg="Error loading config (--config.file=/etc/prometheus/prometheus.yml)"
    r"|Error loading config \(--config\.file="
    # BIND 9 refusing a zone file (real 9.20, lab/apps9):
    #   zone example.lan/IN: loading from master file ... failed: bad dotted quad
    #   zone example.lan/IN: not loaded due to errors.
    r"|\bzone \S+: not loaded due to errors|loading from (?:master|primary) file \S+ failed"
    r"|\bErrImagePull\b|\bImagePullBackOff\b|\bInvalidImageName\b|Failed to pull image \""
)


def analyze_config_errors(events: list[ParsedEvent]) -> list[AnomalySignal]:
    matched = [e for e in events if _CONFIG_ERROR_RE.search(e.message)]
    if not matched:
        return []
    return [AnomalySignal(
        kind="config_error",
        window=_make_window(matched),
        event_count=len(matched),
        baseline_count=None,
        severity=Severity.ERROR,
        representative_events=matched[:20],
    )]


# A load balancer losing its backends — the cause behind a 5xx flood, logged
# once while the flood is logged per request. haproxy (real 3.0 container):
#   [WARNING]  (8) : Server be/app1 is DOWN, reason: Layer4 connection problem, ...
#   [ALERT]    (8) : backend 'be' has no server available!
# nginx: "no live upstreams while connecting to upstream".
_BACKEND_DOWN_RE = re.compile(
    r"\bServer \S+/\S+ is DOWN\b|\bbackend '?\S+?'? has no server available"
    r"|\bno live upstreams while connecting to upstream"
)


_SERVER_STATE_RE = re.compile(r"\bServer (?P<srv>(?P<be>[^/\s]+)/\S+) is (?P<state>UP|DOWN)\b")
_NO_SERVER_RE = re.compile(r"\bbackend '?(?P<be>[^'\s]+?)'? has no server available")


def is_backend_down(event: ParsedEvent) -> bool:
    return _BACKEND_DOWN_RE.search(event.message) is not None


def analyze_backend_down(events: list[ParsedEvent]) -> list[AnomalySignal]:
    # Only a server that is still down by the end of the log counts. A healthy
    # start logs "Server be/s1 is DOWN" when the proxy comes up before its
    # backend, then "is UP" two seconds later (real Debian/RHEL VMs, 2026-10-13):
    # alarming on that was 6 false alarms across the healthy captures.
    last_state: dict[str, str] = {}
    up_backends: set[str] = set()
    for e in events:
        for m in _SERVER_STATE_RE.finditer(e.message):
            last_state[m["srv"]] = m["state"]
            if m["state"] == "UP":
                up_backends.add(m["be"])
    still_down = {s for s, st in last_state.items() if st == "DOWN"}

    def counts(e: ParsedEvent) -> bool:
        m = _SERVER_STATE_RE.search(e.message)
        if m:
            return m["srv"] in still_down
        m = _NO_SERVER_RE.search(e.message)
        if m:
            backend = m["be"]
            # A backend with any server still down, or never seen coming up.
            return backend not in up_backends or any(
                s.split("/", 1)[0] == backend for s in still_down)
        return is_backend_down(e)

    matched = [e for e in events if is_backend_down(e) and counts(e)]
    if not matched:
        return []
    return [AnomalySignal(
        kind="backend_down",
        window=_make_window(matched),
        event_count=len(matched),
        baseline_count=None,
        severity=Severity.ERROR,
        representative_events=matched[:20],
    )]


# A process killed by its own unhandled exception — the usual answer to "why
# did my container exit?", and one event, so no burst detector sees it. Real
# `docker logs` captures (python 3.12, node 22, temurin 21; 2026-10-20):
#   Traceback (most recent call last):          <- not right after a log record
#     File "/app.py", line 17, in <module>
#   RuntimeError: could not connect to database after 15 attempts   <- log ends
# node prints the error, its stack and then "Node.js v22.x"; the JVM prints
# 'Exception in thread "main" <class>: <msg>'; Go prints "panic: ..." and
# then "goroutine 1 [running]:".
_PY_TRACEBACK = "Traceback (most recent call last):"
_PY_EXC_LINE = re.compile(r"^(?:[A-Za-z_][\w.]*\.)?[A-Z]\w*(?:Error|Exception|Exit|Interrupt|Fault|"
                          r"Failure|Warning|Iteration|NotFound|Timeout)\b(?::.*)?$")
_PY_CHAIN = ("During handling of the above exception", "The above exception was the direct")
# The line above a log.exception() traceback is a log record: it carries a
# level token or opens with a timestamp. dnf (real EL8-10 VMs) logs handled
# tracebacks at its own SUBDEBUG level.
_PY_LOGGED = re.compile(
    r"\b(?:ERROR|CRITICAL|FATAL|EXCEPTION|WARNING|WARN|INFO|DEBUG|SUBDEBUG|DDEBUG|TRACE"
    r"|error|critical|exception)\b|^\[?\d{4}-\d\d-\d\d[T ]\d|^\[?\w{3} [ \d]\d \d\d:"
)
_NODE_TRAILER = re.compile(r"^Node\.js v\d+\.\d+")
_NODE_EXC = re.compile(
    r"^(?:Uncaught )?(?:[A-Z]\w*)?(?:Error|Exception)(?: \[\w+\])?: .+|^\[\w+Error\]"
)
_JAVA_MAIN = re.compile(r"Exception in thread \"main\" (?P<exc>\S+.*)")
_GO_PANIC = re.compile(r"^(?:panic: |fatal error: )(?P<msg>.+)")
_GO_GOROUTINE = re.compile(r"^goroutine \d+ \[")
_TAIL_LINES = 400


def _text_lines(events: list[ParsedEvent]) -> list[tuple[str, ParsedEvent]]:
    """The input's last lines as written, each with the event that holds it
    (a folded traceback lives in its log record's message)."""
    out: list[tuple[str, ParsedEvent]] = []
    for e in events[-_TAIL_LINES:]:
        out.append((e.raw, e))
        out += [(ln, e) for ln in e.message.split("\n")[1:]]
    return out


def _python_crash(lines: list[tuple[str, ParsedEvent]]) -> tuple[ParsedEvent, str] | None:
    starts = [i for i, (t, _) in enumerate(lines) if t.strip() == _PY_TRACEBACK
              or t.rstrip().endswith(" " + _PY_TRACEBACK)]
    if not starts:
        return None
    i = starts[-1]
    exc_at = None
    for j in range(i + 1, len(lines)):
        t = lines[j][0]
        if not t.strip() or t[0].isspace() or t.startswith(_PY_CHAIN):
            continue
        if _PY_EXC_LINE.match(t.strip()):
            exc_at = j
            break
        return None  # an unrelated line inside the "traceback": not one
    if exc_at is None:
        return None
    # The process ended with it: nothing (or a line or two) follows.
    if sum(1 for t, _ in lines[exc_at + 1:] if t.strip()) > 2:
        return None
    # log.exception() writes its record line right above the traceback; an
    # unhandled exception follows whatever the program printed last.
    prev = next((t for t, _ in reversed(lines[:i]) if t.strip()), "")
    if prev and not prev[0].isspace() and not _PY_EXC_LINE.match(prev.strip()) \
            and _PY_LOGGED.search(prev):
        return None
    return lines[exc_at][1], lines[exc_at][0].strip()


def _node_crash(lines: list[tuple[str, ParsedEvent]]) -> tuple[ParsedEvent, str] | None:
    tail = [(t, e) for t, e in lines if t.strip()][-40:]
    if not tail or not _NODE_TRAILER.match(tail[-1][0].strip()):
        return None
    for t, e in tail:
        if _NODE_EXC.match(t.strip()) or "FATAL ERROR:" in t:
            return e, t.strip()
    return tail[-1][1], tail[-1][0].strip()


def _java_crash(lines: list[tuple[str, ParsedEvent]]) -> tuple[ParsedEvent, str] | None:
    for t, e in lines:
        m = _JAVA_MAIN.search(t)
        if m:
            return e, m[0]
    return None


# Rust (real rust 1.x binary, lab/apps11): only a panic on the main thread
# ends the process; the reason is the next line.
#   thread 'main' (1) panicked at src/main.rs:3:59:
#   cannot read /etc/ingest.toml: Os { code: 2, kind: NotFound, ... }
_RUST_PANIC = re.compile(r"^thread 'main'(?: \(\d+\))? panicked at (?P<loc>\S+?):?$"
                         r"|^thread 'main'(?: \(\d+\))? panicked at '(?P<old>.*)', (?P<loc2>\S+)$")


def _rust_crash(lines: list[tuple[str, ParsedEvent]]) -> tuple[ParsedEvent, str] | None:
    for k, (t, e) in enumerate(lines):
        m = _RUST_PANIC.match(t.strip())
        if not m:
            continue
        if m["old"]:                                    # Rust < 1.73 one-line form
            return e, f"panicked at {m['loc2']}: {m['old']}"
        reason = next((u.strip() for u, _ in lines[k + 1:k + 3] if u.strip()), "")
        return e, f"panicked at {m['loc']}: {reason}"[:300]
    return None


def _go_crash(lines: list[tuple[str, ParsedEvent]]) -> tuple[ParsedEvent, str] | None:
    for k, (t, e) in enumerate(lines):
        m = _GO_PANIC.match(t.strip())
        if m and any(_GO_GOROUTINE.match(u.strip()) for u, _ in lines[k + 1:k + 8]):
            return e, t.strip()
    return None


def analyze_uncaught_exception(events: list[ParsedEvent]) -> list[AnomalySignal]:
    if not events:
        return []
    lines = _text_lines(sorted(events[-_TAIL_LINES:], key=lambda e: e.line_number))
    for probe in (_python_crash, _node_crash, _java_crash, _go_crash, _rust_crash):
        hit = probe(lines)
        if hit is None:
            continue
        event, what = hit
        rep = event.model_copy(update={"message": what})
        return [AnomalySignal(
            kind="uncaught_exception",
            window=_make_window([event]),
            event_count=1,
            baseline_count=None,
            severity=Severity.ERROR,
            representative_events=[rep],
        )]
    return []


# The input is short and its last record is an error: what a container or a
# job printed before it stopped (`kubectl logs --previous`, `docker logs` of
# an exited container). Real k3s pod: "starting api v2.3" then "ERROR: cannot
# connect to postgres at db:5432: connection refused", exit 1 — CLEAN before.
# Shown on a CLEAN result only (never alarmed on), and only for short inputs:
# in a long live log the latest line being an error says little.
# A container's whole output is a handful of lines; a sample of a service's
# log ending on some error is not this. Measured on the 2,260-file corpus: at
# 200 events and any ERROR line it fired on 85 short parser samples.
_FINAL_ERROR_MAX_EVENTS = 30
_FATAL_WORDING = re.compile(
    r"\b(?:cannot|can't|could not|couldn't|unable to|failed to|fatal|panic|exiting|"
    r"aborting|giving up|connection refused|no such file|not found|permission denied)\b",
    re.I,
)


def final_error_event(events: list[ParsedEvent]) -> ParsedEvent | None:
    if not events or len(events) > _FINAL_ERROR_MAX_EVENTS:
        return None
    ordered = sorted(events, key=lambda e: e.line_number)
    last = ordered[-1]
    if last.severity not in (Severity.ERROR, Severity.CRITICAL):
        return None
    if not _FATAL_WORDING.search(last.message):
        return None
    # One terminal complaint, not a log that is mostly errors (bursts and
    # parsers already judge those).
    if sum(1 for e in ordered[:-1] if e.severity in (Severity.ERROR, Severity.CRITICAL)) > 2:
        return None
    return last


# Hitting an OS or server limit. One line each, and none of the 7 legacy
# categories is "out of file descriptors". Real captures (lab/apps6):
#   [crit] accept4() failed (24: No file descriptors available)      nginx, musl
#   [crit] accept4() failed (24: Too many open files)                nginx, glibc
#   bash: fork: retry: Resource temporarily unavailable              pids limit
_RESOURCE_LIMIT_RE = re.compile(
    r"\(24: (?:Too many open files|No file descriptors available)\)"
    r"|\bToo many open files\b|\bEMFILE\b"
    r"|\bfork: (?:retry: )?Resource temporarily unavailable"
    r"|\bcan't fork\b|\bfork failed\b.*\b(?:Resource temporarily unavailable|EAGAIN)"
    r"|worker_connections are not enough|\bToo many connections\b"
    # Capacity limits (real httpd 2.4 / postgres 16, lab/apps8):
    #   [mpm_event:error] AH00484: server reached MaxRequestWorkers setting, ...
    #   FATAL:  sorry, too many clients already
    r"|server reached MaxRequestWorkers setting|consider raising the MaxRequestWorkers setting"
    r"|server reached pm\.max_children setting"
    r"|sorry, too many clients already|remaining connection slots are reserved"
    # Kubernetes cannot place a pod (real k3s, lab/k8s2):
    #   FailedScheduling ... 0/1 nodes are available: 1 Insufficient memory.
    r"|nodes are available: \d+ Insufficient (?:memory|cpu|ephemeral-storage|pods)"
    r"|\bthread creation failed\b|unable to create (?:new )?native thread",
    re.I,
)


def resource_limit_kind(event: ParsedEvent) -> str | None:
    m = _RESOURCE_LIMIT_RE.search(event.message)
    if m is None:
        return None
    t = m[0].lower()
    if "24:" in t or "open files" in t or "emfile" in t:
        return "open files"
    if "fork" in t:
        return "processes"
    if "thread" in t:
        return "threads"
    if "maxrequestworkers" in t or "max_children" in t:
        return "workers"
    if "nodes are available" in t:
        return "cluster capacity"
    return "connections"


def analyze_resource_limits(events: list[ParsedEvent]) -> list[AnomalySignal]:
    matched = [e for e in events if resource_limit_kind(e)]
    if not matched:
        return []
    return [AnomalySignal(
        kind="resource_limit",
        window=_make_window(matched),
        event_count=len(matched),
        baseline_count=None,
        severity=Severity.ERROR,
        representative_events=matched[:20],
    )]


# A TLS peer's certificate refused (real python 3.12 client, lab/apps6):
#   ... [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: certificate has expired
# Go: "x509: certificate has expired or is not yet valid"; curl/openssl:
# "SSL certificate problem: certificate has expired".
_TLS_CERT_RE = re.compile(
    r"certificate has expired|certificate is not yet valid|x509: certificate"
    r"|CERTIFICATE_VERIFY_FAILED|SSL certificate problem"
    r"|self[- ]signed certificate in certificate chain|unable to get local issuer certificate"
    r"|certificate verify failed|hostname mismatch|doesn't match any of the subject"
)


def is_tls_cert_error(event: ParsedEvent) -> bool:
    return _TLS_CERT_RE.search(event.message) is not None


def analyze_tls_errors(events: list[ParsedEvent]) -> list[AnomalySignal]:
    matched = [e for e in events if is_tls_cert_error(e)]
    if not matched:
        return []
    return [AnomalySignal(
        kind="tls_error",
        window=_make_window(matched),
        event_count=len(matched),
        baseline_count=None,
        severity=Severity.ERROR,
        representative_events=matched[:20],
    )]


# A mail server refusing mail in bulk — spam, a relay attempt or a broken
# sender (real Postfix 3, lab/apps6: 20 in a second):
#   postfix/smtpd[1425]: NOQUEUE: reject: RCPT from host[172.23.0.3]: 450 4.1.2
#     <victim@elsewhere.invalid>: Recipient address rejected: Domain not found; ...
# A few rejects a day are normal on any MX; a dense cluster is the incident.
_MAIL_REJECT_RE = re.compile(r"\bNOQUEUE: reject: |\bRelay access denied\b")
_MAIL_REJECT_MIN = 10


def is_mail_reject(event: ParsedEvent) -> bool:
    return _MAIL_REJECT_RE.search(event.message) is not None


def analyze_mail_rejects(
    events: list[ParsedEvent], window_size: timedelta = _DEFAULT_WINDOW,
) -> list[AnomalySignal]:
    matched = [e for e in events if is_mail_reject(e)]
    if len(matched) < _MAIL_REJECT_MIN:
        return []
    if any(e.timestamp is not None for e in matched):
        densest = densest_window(matched, window_size, _MAIL_REJECT_MIN)
        if densest is None:
            return []
        # A public MX rejects spam all day: in a long log the burst has to
        # stand out from the file's own reject rate (as error bursts do).
        bounds = event_time_bounds(matched)
        if bounds is not None:
            from logcrux.analysis.error_rate import _steady_state
            if _steady_state(len(densest[0]), len(matched), bounds[1] - bounds[0], window_size):
                return []
        matched, w_start, w_end = densest
        window = TimeWindow(start=w_start, end=w_end,
                            duration_seconds=(w_end - w_start).total_seconds())
    else:
        window = _make_window(matched)
    return [AnomalySignal(
        kind="mail_reject_cluster",
        window=window,
        event_count=len(matched),
        baseline_count=None,
        severity=Severity.WARNING,
        representative_events=matched[:20],
    )]


# A structured logger's last record is FATAL/CRITICAL: the program logged why
# it was giving up and stopped (real pino level 60 and structlog "critical"
# apps, lab/apps7). Only for JSON records (the level came from a level field,
# not a keyword guessed from prose), and only when it is the final record: a
# fatal followed by more logging is something else.
def analyze_fatal_exit(events: list[ParsedEvent]) -> list[AnomalySignal]:
    if len(events) < 3:
        return []
    last = max(events, key=lambda e: e.line_number)
    # A JSON record from a structured logger. Text formats are excluded: their
    # CRITICAL often means "this command failed" (dnf's "CRITICAL Error: Unable
    # to find a match"), and in the verdict diff 40 such files turned into
    # "process exited" crashes before this guard.
    # Application loggers only (the parser marks them): in Suricata, Wazuh or
    # ModSecurity JSON "critical" is an alert's severity, not a process exiting.
    if last.severity != Severity.CRITICAL or not last.extra.get("app_logger"):
        return []
    return [AnomalySignal(
        kind="fatal_exit",
        window=_make_window([last]),
        event_count=1,
        baseline_count=None,
        severity=Severity.ERROR,
        representative_events=[last],
    )]


# The system clock jumped (real chrony on RHEL 9, Rocky 10, SLES 15, Ubuntu
# 24.04 x86/arm64 VMs, GCP phase 4, after `date -s "+2 hours"`):
#   chronyd[675]: Forward time jump detected!
#   chronyd[21463]: System clock wrong by -7199.999913 seconds
#   chronyd[21463]: System clock was stepped by -7199.999913 seconds
# Every timestamp after it is off, TLS and Kerberos start failing. Boots
# routinely log corrections of a fraction of a second; only |offset| >= 60 s
# (or chrony's own jump detection) counts.
_CLOCK_OFFSET_RE = re.compile(
    r"System clock (?:wrong by|was stepped by) (?P<off>[-+]?\d+(?:\.\d+)?) seconds"
    r"|\bstep time server \S+ offset (?P<off2>[-+]?\d+(?:\.\d+)?) sec"
    r"|\btime reset (?P<off3>[-+]?\d+(?:\.\d+)?) s\b"
)
_CLOCK_JUMP_RE = re.compile(r"\b(?:Forward|Backward) time jump detected")
_CLOCK_MIN_OFFSET = 60.0


def clock_offset(event: ParsedEvent) -> float | None:
    m = _CLOCK_OFFSET_RE.search(event.message)
    if m is None:
        return None
    return float(m["off"] or m["off2"] or m["off3"])


def is_clock_jump(event: ParsedEvent) -> bool:
    if _CLOCK_JUMP_RE.search(event.message):
        return True
    off = clock_offset(event)
    return off is not None and abs(off) >= _CLOCK_MIN_OFFSET


def analyze_clock_jumps(events: list[ParsedEvent]) -> list[AnomalySignal]:
    matched = [e for e in events if is_clock_jump(e)]
    if not matched:
        return []
    return [AnomalySignal(
        kind="clock_jump",
        window=_make_window(matched),
        event_count=len(matched),
        baseline_count=None,
        severity=Severity.WARNING,
        representative_events=matched[:20],
    )]


# Another package-manager run holds the lock, so this one did nothing (real
# SLES 15 SP7, GCP phase 4):
#   System management is locked by the application with pid 4242 (zypper).
#   Close this application before trying again.
# apt: "Could not get lock /var/lib/dpkg/lock-frontend ... is held by process".
# Not dnf's "Waiting for process with pid N to finish.": dnf waits, then runs
# (a healthy Alma 8 dnf.log has it; matching it was a false alarm).
_PKG_LOCK_RE = re.compile(
    r"System management is locked by the application with pid \d+"
    r"|Could not get lock /var/lib/(?:dpkg|apt)/\S+"
    r"|Unable to acquire the dpkg frontend lock"
)


def analyze_package_locks(events: list[ParsedEvent]) -> list[AnomalySignal]:
    matched = [e for e in events if _PKG_LOCK_RE.search(e.message)]
    if not matched:
        return []
    first = matched[0]
    rep = first.model_copy(update={"extra": {**first.extra, "outcome": "failed",
                                             "detail": first.message.strip()}})
    return [AnomalySignal(
        kind="job_failure",
        window=_make_window(matched),
        event_count=len(matched),
        baseline_count=None,
        severity=Severity.ERROR,
        representative_events=[rep, *matched[1:20]],
    )]


# Kubernetes health checks (real k3s 1.31 events / describe, lab/k8s2):
#   Warning  Unhealthy  pod/liveness-kill  Liveness probe failed: cat: can't open '/tmp/alive' ...
#   Normal   Killing    pod/liveness-kill  Container api failed liveness probe, will be restarted
#   Warning  Unhealthy  pod/never-ready    Readiness probe failed: ...
# A liveness/startup failure restarts the container: always reported. A pod
# briefly not-ready during its own start is normal, so readiness counts only
# when it repeats (>= 3 lines, or describe's "(x3 over ...)" aggregate).
_PROBE_RE = re.compile(r"\b(?P<kind>Liveness|Readiness|Startup) probe failed"
                       r"|failed (?P<kind2>liveness|startup) probe, will be restarted")
_AGG_RE = re.compile(r"\(x(?P<n>\d+) over ")
_READINESS_MIN = 3


def analyze_probe_failures(events: list[ParsedEvent]) -> list[AnomalySignal]:
    restart: list[ParsedEvent] = []
    readiness: list[ParsedEvent] = []
    seen_ready = 0
    for e in events:
        m = _PROBE_RE.search(e.message)
        if not m:
            continue
        kind = (m["kind"] or m["kind2"] or "").lower()
        if kind == "readiness":
            readiness.append(e)
            agg = _AGG_RE.search(e.message)
            seen_ready += int(agg["n"]) if agg else 1
        else:
            restart.append(e)
    matched = restart + (readiness if seen_ready >= _READINESS_MIN else [])
    if not matched:
        return []
    matched.sort(key=lambda e: e.line_number)
    return [AnomalySignal(
        kind="probe_failure",
        window=_make_window(matched),
        event_count=len(matched),
        baseline_count=None,
        severity=Severity.WARNING,
        representative_events=matched[:20],
    )]
