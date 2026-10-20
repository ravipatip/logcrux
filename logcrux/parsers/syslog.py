from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import INDENTED_CONTINUATION, LogParser

# The optional fraction is `journalctl -o short-precise` ("Oct 19 19:37:47.887957
# host kernel: ..."): generic on all 6 phase-3 GCP VMs (2026-10-20) without it.
_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?) "
    r"(?P<host>\S+) "
    r"(?P<source>[^:\[]+?)(?:\[(?P<pid>\d+)\])?: "
    r"(?P<message>.*)"
)

# `journalctl -o short-iso` / `short-iso-precise` and rsyslog's ISO RFC3339
# template emit the same host/tag/message shape but with an ISO-8601 timestamp
# instead of the RFC3164 "Mon DD HH:MM:SS". Extremely common in DevOps captures
# (`journalctl --since … -o short-iso > out.log`), so syslog must claim it rather
# than letting it fall to the generic parser (which leaves the ts+host+tag prefix
# polluting the message and never strips the source).
_ISO_PATTERN = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?) "
    r"(?P<host>\S+) "
    r"(?P<source>[^:\[]+?)(?:\[(?P<pid>\d+)\])?: "
    r"(?P<message>.*)"
)

# Specific OOM-killer tokens only. A bare "oom" substring would mis-flag
# ordinary words like "room", "zoom", or "broom" as CRITICAL.
_OOM_KEYWORDS = frozenset(
    ["out of memory", "oom-kill", "oom_kill", "oom-killer", "oom_killer",
     "oom_reaper", "killed process"]
)
# Whole-word patterns so "error" inside identifiers like ReturningError,
# NSError, or errorDomain does not trigger ERROR severity.
_ERROR_RE = re.compile(r"\b(?:error|fail|failed|fatal|critical|emerg)\b", re.I)
_WARN_RE = re.compile(r"\b(?:warn|warning)\b", re.I)
_CURRENT_YEAR = datetime.now().year

# Guards against false positives — same logic as generic.py:
# "0 error", "5 failed" — keyword immediately after a count is a quantity, not a level.
_COUNT_PREFIX = re.compile(r"\d+\s*$")
# "error 30", "err 0xb" — keyword followed by a number is an error code reference.
_CODE_SUFFIX = re.compile(r"^\s*[0-9]")


# systemd status lines quote a unit's *description*, which can contain any word:
#   Starting grub-initrd-fallback.service - GRUB failed boot detection...
#   apport-autoreport.timer - Process error reports when automatic reporting is enabled
#   Started update-notifier-download.timer - Download data for packages that failed ...
# On healthy Ubuntu 22.04/24.04 GCP boots these alone made a 12-"error" burst.
# A unit that really fails is logged as "Failed to start", "Failed with result",
# "Main process exited" — none of which start with these verbs.
_SYSTEMD_STATUS_RE = re.compile(
    r"^(?:Starting|Started|Finished|Stopping|Stopped|Reached target|Listening on|"
    r"Mounting|Mounted|Condition check resulted in|Reloading|Reloaded)\b"
    r"|^[\w@.\\-]+\.(?:service|timer|path|socket|target|mount) - "
)


def _infer_severity(source: str, message: str) -> Severity:
    text = (source + " " + message).lower()
    if any(k in text for k in _OOM_KEYWORDS):
        return Severity.CRITICAL
    if source == "systemd" and _SYSTEMD_STATUS_RE.match(message):
        return Severity.INFO
    combined = source + " " + message
    for pattern, sev in ((_ERROR_RE, Severity.ERROR), (_WARN_RE, Severity.WARNING)):
        for m in pattern.finditer(combined):
            before = combined[: m.start()]
            after = combined[m.end() :]
            if _COUNT_PREFIX.search(before):
                continue
            if sev is Severity.ERROR and _CODE_SUFFIX.match(after):
                continue
            return sev
    return Severity.INFO


class SyslogParser(LogParser):
    FORMAT_NAME = "syslog"
    CONTINUATION = INDENTED_CONTINUATION

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and path.name in ("messages", "syslog"):
            return True
        return any(
            _PATTERN.match(line) or _ISO_PATTERN.match(line) for line in sample_lines[:10]
        )

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _PATTERN.match(line)
        if m:
            try:
                ts = dateparser.parse(
                    f"{m['month']} {m['day']} {_CURRENT_YEAR} {m['time']}"
                )
            except Exception:
                ts = None
        else:
            m = _ISO_PATTERN.match(line)
            if not m:
                return None
            try:
                ts = dateparser.parse(m["ts"])
            except Exception:
                ts = None
        source = m["source"].strip()
        message = m["message"].strip()
        extra: dict[str, str] = {}
        if m["pid"]:
            extra["pid"] = m["pid"]
        return ParsedEvent(
            timestamp=ts,
            severity=_infer_severity(source, message),
            source=source,
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
