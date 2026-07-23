from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Generator, Iterable
from pathlib import Path
from typing import ClassVar

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity

# Generic RFC3164 syslog prefix: "Mon DD HH:MM:SS host tag..."
_SYSLOG_PREFIX_RE = re.compile(r"\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2} \S+ ")

# Stack-trace continuation lines: Python tracebacks, Java/JVM stack frames,
# chained-exception headers, and the bare exception line that ends a Python
# traceback ("KeyError: 'key'"). App-logger parsers (pylogging, log4j,
# springboot) set ``CONTINUATION`` to this so tracebacks fold into the event
# that raised them instead of being dropped as unparsed — which both loses the
# most diagnostic lines of the log and pushes coverage below the generic-parser
# fallback threshold, costing timestamps and levels on the whole file.
TRACEBACK_CONTINUATION = re.compile(
    r"^(?:\s+\S"                                    # indented frame/source line
    r"|Traceback \(most recent call last\):"        # Python header
    r"|Caused by: |Suppressed: "                    # Java chained exceptions
    r"|\.\.\. \d+ (?:more|common frames omitted)"   # Java frame elision
    r"|[A-Za-z_][\w.]*(?:Error|Exception|Warning|Exit|Interrupt):?(?:\s|$))"
)

# Cap on continuation lines appended to an event's message: keeps a deep or
# repeated traceback from ballooning memory / classifier input. Lines past the
# cap still count as consumed (meta_lines), just aren't stored.
_MAX_CONTINUATION_LINES = 20

# Canonical level-string → Severity map shared by the many structured parsers
# (zap/zerolog/logrus/logfmt/glog/...) whose log levels all draw from the same
# vocabulary. Centralizing it keeps a single source of truth instead of a
# per-parser copy that can drift.
_LEVEL_SEVERITY: dict[str, Severity] = {
    "trace": Severity.DEBUG,
    "debug": Severity.DEBUG,
    "dbug": Severity.DEBUG,
    "info": Severity.INFO,
    "information": Severity.INFO,
    "informational": Severity.INFO,
    "notice": Severity.INFO,
    "default": Severity.INFO,
    "warn": Severity.WARNING,
    "warning": Severity.WARNING,
    "wrn": Severity.WARNING,
    "error": Severity.ERROR,
    "err": Severity.ERROR,
    "eror": Severity.ERROR,
    "severe": Severity.ERROR,
    "crit": Severity.CRITICAL,
    "critical": Severity.CRITICAL,
    "alert": Severity.CRITICAL,
    "emerg": Severity.CRITICAL,
    "emergency": Severity.CRITICAL,
    "fatal": Severity.CRITICAL,
    "panic": Severity.CRITICAL,
    "dpanic": Severity.CRITICAL,
}


# Classic Log4j/Logback line: "ts LEVEL [thread] logger: msg" or the log4j2
# "ts LEVEL logger [] - msg" variant. Shared by the JVM big-data parsers
# (HBase/Hive/Flink/Druid) which all emit this shape and are disambiguated only
# by a project-specific logger/vocabulary marker in their can_parse.
_LOG4J_CLASSIC_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[,.]\d{3}) "
    r"(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL)\s+(?P<rest>.*)$"
)
_LOG4J_THREAD_RE = re.compile(r"^\[(?P<thread>[^\]]*)\]\s+(?P<rest>.*)$")
_LOG4J_LOGGER_RE = re.compile(r"([a-zA-Z][\w$]*(?:\.[\w$]+)+)")


def log4j_classic_fields(line: str) -> dict[str, str | None] | None:
    """Parse a classic Log4j/Logback line into ts/level/thread/logger/message.

    Returns ``None`` when the line does not match the classic shape. Used by the
    JVM big-data parsers, each of which still vocabulary-gates detection so it
    never poaches a neighbouring (or the generic ``log4j``) format.
    """
    m = _LOG4J_CLASSIC_RE.match(line)
    if not m:
        return None
    rest = m["rest"]
    thread: str | None = None
    tm = _LOG4J_THREAD_RE.match(rest)
    if tm:
        thread = tm["thread"]
        rest = tm["rest"]
    logger_m = _LOG4J_LOGGER_RE.search(rest)
    return {
        "ts": m["ts"],
        "level": m["level"],
        "thread": thread,
        "logger": logger_m.group(1) if logger_m else None,
        "message": rest.strip(),
    }


def level_to_severity(level: str | None, default: Severity = Severity.INFO) -> Severity:
    """Map a textual log level (``info``, ``WARN``, ``E``, ...) to a Severity.

    Accepts the single-letter glog/klog forms (I/W/E/F) and the common word
    forms (case-insensitive). Returns ``default`` for anything unrecognized.
    """
    if not level:
        return default
    key = level.strip().lower()
    if key in _LEVEL_SEVERITY:
        return _LEVEL_SEVERITY[key]
    single = {
        "d": Severity.DEBUG,
        "i": Severity.INFO,
        "n": Severity.INFO,
        "w": Severity.WARNING,
        "e": Severity.ERROR,
        "c": Severity.CRITICAL,
        "f": Severity.CRITICAL,
    }
    return single.get(key, default)

# Aggregate, multiplexed system logs. A dedicated service writes to its own
# file (cron, kern.log, ...), so a per-service tag parser must not claim these
# even when a sampled line happens to carry its tag — they belong to syslog.
_AGGREGATE_SYSLOG_NAMES = frozenset(["messages", "syslog"])


def syslog_tag_dominant(
    sample_lines: list[str],
    pattern: re.Pattern[str],
    *,
    path: Path | None = None,
    limit: int = 20,
) -> bool:
    """Return True when ``pattern`` (a specific syslog program-tag matcher)
    accounts for at least half of the syslog-shaped lines in the sample.

    This keeps a per-service parser (cron, sudo, dovecot, ...) from hijacking a
    mixed ``/var/log/syslog`` where its tag appears only occasionally, while
    still claiming a dedicated single-service log file.
    """
    if path is not None and path.name in _AGGREGATE_SYSLOG_NAMES:
        return False
    syslog_lines = [
        line for line in sample_lines[:limit] if _SYSLOG_PREFIX_RE.match(line)
    ]
    if not syslog_lines:
        return False
    tagged = sum(1 for line in syslog_lines if pattern.match(line))
    # Require a true majority: ``tagged * 2 >= len`` means at least half,
    # rounding so an exact half passes but a minority cannot. Integer floor
    # (``len // 2``) used to let 1-of-3 tagged lines hijack a mixed syslog.
    return tagged > 0 and tagged * 2 >= len(syslog_lines)


def make_syslog_tag_re(tag_pattern: str) -> re.Pattern[str]:
    """Build an RFC3164 matcher for a specific program tag (with optional pid)."""
    return re.compile(
        r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
        r"(?P<host>\S+) (?P<prog>" + tag_pattern + r")(?:\[(?P<pid>\d+)\])?: "
        r"(?P<message>.*)"
    )


class LogParser(ABC):
    FORMAT_NAME: ClassVar[str]
    # Override in parsers where multiple raw lines produce a single event
    # (e.g. MySQL slow query log: Time + User@Host + Query_time + SQL = 1 event).
    # _parse_with_fallback uses this to avoid incorrectly falling back to the
    # generic parser when the low event-per-line ratio is intentional.
    MIN_COVERAGE: ClassVar[float] = 0.6

    # Count of non-blank lines the parser consumed as *structure* rather than
    # events: W3C/Zeek "#Fields"-style headers, Oracle's standalone timestamp
    # lines, slow-query block headers. Incremented by stateful parsers inside
    # parse_line. These lines are neither events nor data loss, so
    # _parse_with_fallback credits them toward coverage and the CLI excludes
    # them from the "N line(s) unparsed" footer.
    meta_lines: int = 0

    # When set (usually to TRACEBACK_CONTINUATION), a non-parsing line that
    # matches is folded into the preceding event rather than dropped.
    CONTINUATION: ClassVar[re.Pattern[str] | None] = None

    @classmethod
    @abstractmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool: ...

    @abstractmethod
    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None: ...

    def parse_stream(
        self, stream: Iterable[str]
    ) -> Generator[ParsedEvent, None, None]:
        pending: ParsedEvent | None = None
        pending_extra = 0
        for i, line in enumerate(stream, start=1):
            stripped = line.rstrip("\n")
            try:
                event = self.parse_line(stripped, i)
            except Exception:
                event = None
            if event is not None:
                if pending is not None:
                    yield pending
                pending, pending_extra = event, 0
                continue
            if (
                pending is not None
                and self.CONTINUATION is not None
                and stripped.strip()
                and self.CONTINUATION.match(stripped)
            ):
                if pending_extra < _MAX_CONTINUATION_LINES:
                    pending.message = f"{pending.message}\n{stripped}"
                pending_extra += 1
                self.meta_lines += 1
        if pending is not None:
            yield pending


class SyslogKeywordParser(LogParser):
    """Base for syslog-tagged daemons whose severity is inferred from message
    keywords (dbus, polkit, snapd, ...). Subclasses set ``TAG_PATTERN`` (a
    program-tag regex alternation), ``SOURCE``, and optional ``ERROR_KW`` /
    ``WARN_KW`` keyword tuples. Detection is majority-gated via
    ``syslog_tag_dominant`` so a stray tagged line in a mixed syslog can't poach.
    """

    TAG_PATTERN: ClassVar[str]
    SOURCE: ClassVar[str]
    ERROR_KW: ClassVar[tuple[str, ...]] = ()
    WARN_KW: ClassVar[tuple[str, ...]] = ()
    _RE: ClassVar[re.Pattern[str]]

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        if getattr(cls, "TAG_PATTERN", None):
            cls._RE = make_syslog_tag_re(cls.TAG_PATTERN)

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return syslog_tag_dominant(sample_lines, cls._RE, path=path)

    def _severity(self, message: str) -> Severity:
        low = message.lower()
        if any(k in low for k in self.WARN_KW):
            sev = Severity.WARNING
        else:
            sev = Severity.INFO
        if any(k in low for k in self.ERROR_KW):
            sev = Severity.ERROR
        return sev

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = self._RE.match(line)
        if not m:
            return None
        from datetime import datetime

        try:
            ts: object = dateparser.parse(
                f"{m['month']} {m['day']} {datetime.now().year} {m['time']}"
            )
        except Exception:
            ts = None
        message = m["message"].strip()
        extra: dict[str, object] = {"program": m["prog"]}
        if m["pid"]:
            extra["pid"] = m["pid"]
        return ParsedEvent(
            timestamp=ts,  # type: ignore[arg-type]
            severity=self._severity(message),
            source=self.SOURCE,
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
