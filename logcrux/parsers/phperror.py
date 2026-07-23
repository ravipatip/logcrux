from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# PHP error_log format (php_errors.log, WordPress wp-content/debug.log, and the
# default PHP-FPM per-pool error output). Layout is "[dd-Mon-yyyy HH:MM:SS TZ] msg":
#   [28-Jun-2026 10:15:01 UTC] PHP Notice:  Undefined index: id in /var/www/x.php on line 5
#   [28-Jun-2026 10:15:02 UTC] PHP Warning:  fopen(): failed to open stream
#   [28-Jun-2026 10:15:03 UTC] PHP Fatal error:  Uncaught Error: Class not found
# The "[dd-Mon-yyyy HH:MM:SS TZ] PHP <Level>:" shape is the signature.
_PATTERN = re.compile(
    r"^\[(?P<ts>\d{1,2}-\w{3}-\d{4} \d{2}:\d{2}:\d{2}(?: \w+)?)\] "
    r"(?P<message>.*)$"
)


def _severity(message: str) -> Severity:
    low = message.lower()
    if "fatal error" in low or "parse error" in low and "fatal" in low:
        return Severity.CRITICAL
    if "parse error" in low:
        return Severity.ERROR
    if low.startswith("php error") or " error:" in low or low.startswith("php recoverable"):
        return Severity.ERROR
    if "warning" in low:
        return Severity.WARNING
    if "notice" in low or "deprecated" in low:
        return Severity.INFO
    return Severity.INFO


class PHPErrorParser(LogParser):
    FORMAT_NAME = "phperror"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        matched = [ln for ln in sample_lines[:25] if _PATTERN.match(ln)]
        if not matched:
            return False
        # Require the PHP error-log vocabulary so the "[date] msg" bracket shape
        # can't poach another bracket-prefixed format.
        return any(
            "PHP " in ln or "Stack trace" in ln or "thrown in" in ln
            for ln in matched
        )

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["ts"].replace("-", " ", 2))
        except (ValueError, TypeError, OverflowError):
            ts = None
        message = m["message"].strip()
        extra: dict[str, object] = {}
        kind = re.match(r"PHP (\w[\w ]*?):", message)
        if kind:
            extra["error_type"] = kind.group(1)
        return ParsedEvent(
            timestamp=ts,
            severity=_severity(message),
            source="phperror",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
