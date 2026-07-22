from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Most common log_line_prefix formats:
# %t [%p]: [%l-1] user=%u,db=%d ...
# %m [%p] %q%u@%d
# Flexible pattern that handles the two most widely deployed variants:

# Variant A: 2024-12-04 08:25:00.123 UTC [1234] user@db LOG:  message
_PATTERN_A = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?) "
    r"(?P<tz>[A-Z]{2,5}|[+-]\d{4}) "
    r"\[(?P<pid>\d+)\] "
    r"(?:(?P<user>\S+)@(?P<db>\S+) )?"
    r"(?P<level>LOG|INFO|NOTICE|WARNING|ERROR|FATAL|PANIC|DEBUG\d*"
    r"|DETAIL|HINT|STATEMENT|CONTEXT|LOCATION): "
    r" *(?P<message>.*)"
)

# Variant B: 2024-12-04 08:25:00 [12345]: [1-1] user=root,db=mydb LOG:  message
_PATTERN_B = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?) "
    r"\[(?P<pid>\d+)\]: \[\d+-\d+\] "
    r"(?:user=(?P<user>[^,]+),db=(?P<db>[^,]+)(?:,[^ ]+)* )?"
    r"(?P<level>LOG|INFO|NOTICE|WARNING|ERROR|FATAL|PANIC|DEBUG\d*): "
    r" *(?P<message>.*)"
)

_DETECT_A = re.compile(
    r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)? [A-Z]{2,5} \[\d+\]"
)
_DETECT_B = re.compile(
    r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \[\d+\]: \[\d+-\d+\]"
)

_LEVEL_MAP: dict[str, Severity] = {
    "log": Severity.INFO,
    "info": Severity.INFO,
    "notice": Severity.INFO,
    "warning": Severity.WARNING,
    "error": Severity.ERROR,
    "fatal": Severity.CRITICAL,
    "panic": Severity.CRITICAL,
}


def _pg_severity(level: str) -> Severity:
    return _LEVEL_MAP.get(level.lower(), Severity.INFO)


class PostgreSQLParser(LogParser):
    FORMAT_NAME = "postgresql"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path:
            p = str(path).lower()
            if "postgres" in p or "pgsql" in p or "pg_log" in p:
                return True
        return any(
            _DETECT_A.match(line) or _DETECT_B.match(line)
            for line in sample_lines[:10]
        )

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _PATTERN_A.match(line) or _PATTERN_B.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["ts"], fuzzy=True)
        except Exception:
            ts = None
        user = m["user"] or ""
        db = m["db"] or ""
        level = m["level"]
        message = m["message"].strip()
        extra: dict[str, object] = {"level": level, "pid": m["pid"]}
        if user:
            extra["user"] = user
        if db:
            extra["db"] = db
        return ParsedEvent(
            timestamp=ts,
            severity=_pg_severity(level),
            source="postgresql",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
