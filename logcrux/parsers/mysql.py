from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# MySQL 8+ / MariaDB 10.5+ error log
# 2024-12-04T08:25:00.123456Z 0 [ERROR] [MY-010116] [Server] message
_NEW_PATTERN = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z?) "
    r"\d+ \[(?P<level>[A-Za-z]+)\]"
    r"(?: \[[^\]]+\])?(?: \[[^\]]+\])? "
    r"(?P<message>.*)"
)

# Older MySQL / MariaDB error log
# 2024-12-04  8:25:00 0 [ERROR] message
_OLD_PATTERN = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{1,2}:\d{2}:\d{2}) "
    r"\d+ \[(?P<level>[A-Za-z]+)\] "
    r"(?P<message>.*)"
)

# Slow query header: # User@Host: root[root] @ localhost []  Id: 12
_SLOW_USER = re.compile(
    r"# User@Host: (?P<user>\S+) @ (?P<host>\S+)"
)
# Slow query timing: # Query_time: 5.123  Lock_time: 0.001 Rows_sent: 1  Rows_examined: 100000
_SLOW_TIME = re.compile(
    r"# Query_time: (?P<qtime>[\d.]+)\s+Lock_time: (?P<ltime>[\d.]+)"
    r"\s+Rows_sent: (?P<rows_sent>\d+)\s+Rows_examined: (?P<rows_examined>\d+)"
)
# Slow query timestamp comment: # Time: 2024-12-04T08:25:00.123456Z
_SLOW_TS = re.compile(r"# Time: (?P<ts>\S+)")

_LEVEL_MAP: dict[str, Severity] = {
    "error": Severity.ERROR,
    "warning": Severity.WARNING,
    "warn": Severity.WARNING,
    "note": Severity.INFO,
    "information": Severity.INFO,
    "info": Severity.INFO,
    "system": Severity.INFO,
}

_DETECT = re.compile(
    r"(?:\d{4}-\d{2}-\d{2}[T ]\s*\d{1,2}:\d{2}:\d{2}.*\[(ERROR|Warning|Note|System)\])"
    r"|(?:# User@Host:)"
    r"|(?:# Query_time:)"
)


class MySQLParser(LogParser):
    FORMAT_NAME = "mysql"
    # Slow query logs emit 1 event per ~5 lines (Time/User/Query_time/SET/SQL);
    # the default 0.6 threshold would incorrectly trigger a generic fallback.
    MIN_COVERAGE = 0.1

    def __init__(self) -> None:
        super().__init__()
        self._pending_slow_ts: str | None = None
        self._pending_slow_user: str | None = None
        # True after a slow-query timing event: the SQL statement lines that
        # follow belong to that event, so they count as consumed, not unparsed.
        self._in_slow_body = False

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path:
            p = str(path).lower()
            if "mysql" in p or "mariadb" in p:
                return True
        return any(_DETECT.search(line) for line in sample_lines[:10])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        if line.startswith("SET timestamp=") or line.startswith("use "):
            self.meta_lines += 1
            return None

        # Slow query: # Time: header → remember for next event
        m = _SLOW_TS.match(line)
        if m:
            self._pending_slow_ts = m["ts"]
            self._in_slow_body = False
            self.meta_lines += 1
            return None

        # Slow query: # User@Host: header
        m = _SLOW_USER.match(line)
        if m:
            self._pending_slow_user = f"{m['user']}@{m['host']}"
            self.meta_lines += 1
            return None

        # Slow query timing line → emit as event
        m = _SLOW_TIME.match(line)
        if m:
            qtime = float(m["qtime"])
            ts = None
            if self._pending_slow_ts:
                try:
                    ts = dateparser.parse(self._pending_slow_ts, fuzzy=True)
                except Exception:
                    pass
            severity = Severity.ERROR if qtime >= 5 else Severity.WARNING
            user = self._pending_slow_user or "?"
            event = ParsedEvent(
                timestamp=ts,
                severity=severity,
                source="mysql",
                message=f"Slow query {qtime:.3f}s by {user} "
                        f"(rows_examined={m['rows_examined']})",
                raw=line,
                line_number=line_number,
                extra={
                    "query_time": qtime,
                    "lock_time": float(m["ltime"]),
                    "rows_sent": int(m["rows_sent"]),
                    "rows_examined": int(m["rows_examined"]),
                    "user": user,
                },
            )
            self._pending_slow_ts = None
            self._pending_slow_user = None
            self._in_slow_body = True
            return event

        # MySQL 8+ / MariaDB 10.5+
        m = _NEW_PATTERN.match(line)
        if m:
            return self._make_event(m["ts"], m["level"], m["message"], line, line_number)

        # Older format
        m = _OLD_PATTERN.match(line)
        if m:
            return self._make_event(m["ts"], m["level"], m["message"], line, line_number)

        if self._in_slow_body:
            self.meta_lines += 1
            return None

        return None

    def _make_event(
        self, ts_str: str, level: str, message: str, line: str, line_number: int
    ) -> ParsedEvent:
        try:
            ts = dateparser.parse(ts_str, fuzzy=True)
        except Exception:
            ts = None
        severity = _LEVEL_MAP.get(level.lower(), Severity.INFO)
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="mysql",
            message=message,
            raw=line,
            line_number=line_number,
            extra={"level": level},
        )
