from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Go standard-library "log" package default output. Layout is
# "YYYY/MM/DD HH:MM:SS[.ffffff] [file.go:line:] message":
#   2026/06/28 10:15:01 starting server on :8080
#   2026/06/28 10:15:02.123456 main.go:42: cache miss for key=abc
#   2026/06/28 10:15:03 ERROR failed to connect to database
# The "YYYY/MM/DD HH:MM:SS" slash-date prefix is the Go-log signature. Detection
# is majority-gated so a stray slash-date line can't hijack another format.
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?) "
    r"(?:(?P<src>[\w./-]+\.go:\d+): )?"
    r"(?P<message>.*)$"
)
_ERROR_KW = ("error", "err:", "failed", "fatal", "panic", "cannot", "unable")
_WARN_KW = ("warn", "warning", "retry", "retrying", "timeout", "deprecated")


class GoStdlibParser(LogParser):
    FORMAT_NAME = "gostdlib"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        nonblank = [ln for ln in sample_lines[:25] if ln.strip()]
        if not nonblank:
            return False
        matched = sum(bool(_PATTERN.match(ln)) for ln in nonblank)
        # Require a clear majority — the slash-date prefix is broad, so only a
        # log that is overwhelmingly this shape should claim the format.
        return matched * 2 >= len(nonblank) and matched >= 2

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["ts"].replace("/", "-"))
        except (ValueError, TypeError, OverflowError):
            ts = None
        message = m["message"].strip()
        low = message.lower()
        severity = Severity.INFO
        if any(k in low for k in _ERROR_KW):
            severity = Severity.ERROR
        elif any(k in low for k in _WARN_KW):
            severity = Severity.WARNING
        extra: dict[str, object] = {}
        if m["src"]:
            extra["src"] = m["src"]
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="gostdlib",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
