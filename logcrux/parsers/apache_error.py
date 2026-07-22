from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

_PATTERN = re.compile(
    r"\[(?P<timestamp>[^\]]+)\] "
    r"\[(?P<level>[^\]]+)\] "
    r"(?:\[pid (?P<pid>\d+)\] )?"
    r"(?:\[client (?P<client>[^\]]+)\] )?"
    r"(?P<message>.*)"
)

_LEVEL_MAP: dict[str, Severity] = {
    "emerg": Severity.CRITICAL, "alert": Severity.CRITICAL,
    "crit": Severity.CRITICAL, "error": Severity.ERROR,
    "warn": Severity.WARNING, "notice": Severity.INFO,
    "info": Severity.INFO, "debug": Severity.DEBUG,
    **{f"trace{i}": Severity.DEBUG for i in range(1, 9)},
}

# An Apache error-log level token: an optional "module:" prefix followed by a
# severity word (e.g. "core:error", "php7:notice", or bare "error"). Requiring
# this in detection stops the parser claiming other "[a] [b] msg" logs such as
# Gunicorn's "[2026-06-20 ...] [123] [INFO] ...".
_LEVEL_TOKEN_RE = re.compile(
    r"^(?:\w+:)?(?:emerg|alert|crit|error|warn|notice|info|debug|trace\d?)$"
)


class ApacheErrorParser(LogParser):
    FORMAT_NAME = "apache-error"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and ("apache" in str(path) or "httpd" in str(path)) and "error" in path.name:
            return True
        for line in sample_lines[:5]:
            m = _PATTERN.match(line)
            if m and _LEVEL_TOKEN_RE.match(m["level"].strip().lower()):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _PATTERN.match(line)
        if not m:
            return None
        level = m["level"].strip().lower().split(":")[-1]
        severity = _LEVEL_MAP.get(level, Severity.UNKNOWN)
        try:
            ts = dateparser.parse(m["timestamp"], fuzzy=True)
        except Exception:
            ts = None
        extra: dict[str, str] = {}
        if m["pid"]:
            extra["pid"] = m["pid"]
        if m["client"]:
            extra["client_ip"] = m["client"].rsplit(":", 1)[0]
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="apache",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
