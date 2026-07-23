from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# PingIntelligence for APIs — the on-prem API Security Enforcer (ASE). Its
# access_log, controller.log, and balancer.log (under /opt/pingidentity/ase/logs)
# share one bracketed layout: a ctime-style date, a thread id, a level, then the
# message / request fields:
#   [Tue Aug 14 22:51:49:707 2018] [thread:209] [info] [connectionid:1804289383]
#       [connectinfo:100.100.1.1:36663] [type:connection_drop] [api:decoy]
#       [request_payload_length:0] GET /decoy/test HTTP/1.1 User-Agent: curl/7.35
#   [Tue Aug 14 22:52:03:114 2018] [thread:12] [error] failed to connect to backend
#
# The "[Www Mon DD HH:MM:SS:mmm YYYY] [thread:N] [level]" prefix (note the colon
# before the milliseconds, unlike syslog) is distinctive to ASE.
_PATTERN = re.compile(
    r"^\[(?P<ts>[A-Za-z]{3} [A-Za-z]{3} +\d{1,2} \d{2}:\d{2}:\d{2}:\d{3} \d{4})\] "
    r"\[thread:(?P<thread>\d+)\] "
    r"\[(?P<level>fatal|error|warning|warn|info|debug)\]\s*(?P<message>.*)$"
)
# Optional bracketed access-log fields we surface when present.
_TYPE_RE = re.compile(r"\[type:(?P<type>[^\]]+)\]")
_API_RE = re.compile(r"\[api:(?P<api>[^\]]+)\]")
_CONNINFO_RE = re.compile(r"\[connectinfo:(?P<conn>[^\]]+)\]")

_LEVEL_SEVERITY = {
    "debug": Severity.DEBUG,
    "info": Severity.INFO,
    "warn": Severity.WARNING,
    "warning": Severity.WARNING,
    "error": Severity.ERROR,
    "fatal": Severity.CRITICAL,
}

# ASE access-log event types that signal an attack/abuse decision — worth raising
# above the raw INFO level ASE logs them at.
_ATTACK_TYPES = frozenset(
    {"connection_drop", "attack", "abuse", "blocked", "decoy", "backend_error"}
)


def _parse_ts(raw: str) -> datetime | None:
    # "Tue Aug 14 22:51:49:707 2018": the ms is joined to the time by a colon;
    # swap the last ':' before the year-adjacent millis to a '.' for dateutil.
    fixed = re.sub(r"(\d{2}:\d{2}:\d{2}):(\d{3})", r"\1.\2", raw)
    try:
        return dateparser.parse(fixed)
    except (ValueError, TypeError, OverflowError):
        return None


class PingIntelligenceParser(LogParser):
    FORMAT_NAME = "pingintelligence"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for ln in sample_lines[:20]:
            if _PATTERN.match(ln):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        message = m["message"].strip()
        severity = _LEVEL_SEVERITY.get(m["level"].lower(), Severity.INFO)
        extra: dict[str, object] = {"level": m["level"].lower(), "thread": m["thread"]}
        type_m = _TYPE_RE.search(message)
        if type_m:
            evt_type = type_m["type"]
            extra["type"] = evt_type
            if evt_type in _ATTACK_TYPES and severity in (Severity.DEBUG, Severity.INFO):
                severity = Severity.WARNING
        api_m = _API_RE.search(message)
        if api_m:
            extra["api"] = api_m["api"]
        conn_m = _CONNINFO_RE.search(message)
        if conn_m:
            extra["client"] = conn_m["conn"]
        return ParsedEvent(
            timestamp=_parse_ts(m["ts"]),
            severity=severity,
            source="pingintelligence",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
