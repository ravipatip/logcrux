from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, syslog_tag_dominant

# firewalld logs through syslog and prefixes its own level word:
#   Jun 20 10:23:45 host firewalld[1234]: WARNING: ZONE_ALREADY_SET: public
#   Jun 20 10:23:45 host firewalld[1234]: ERROR: COMMAND_FAILED: ... iptables ...
#   Jun 20 10:23:45 host firewalld[1234]: INFO: Reloading firewall rules.
_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"(?P<prog>firewalld)(?:\[(?P<pid>\d+)\])?: "
    r"(?P<message>.*)"
)

_LEVEL_RE = re.compile(r"^(?P<level>DEBUG\d?|INFO\d?|WARNING|ERROR):\s*")
_CURRENT_YEAR = datetime.now().year

_LEVEL_MAP: dict[str, Severity] = {
    "DEBUG": Severity.DEBUG,
    "INFO": Severity.INFO,
    "WARNING": Severity.WARNING,
    "ERROR": Severity.ERROR,
}

_ERROR_KEYWORDS = frozenset([
    "command_failed", "exception", "traceback", "not enabled",
    "invalid", "failed", "no such",
])


def _firewalld_severity(message: str) -> Severity:
    m = _LEVEL_RE.match(message)
    if m:
        word = re.sub(r"\d", "", m["level"])
        base = _LEVEL_MAP.get(word, Severity.INFO)
    else:
        base = Severity.INFO
    if base in (Severity.INFO, Severity.DEBUG):
        low = message.lower()
        if any(kw in low for kw in _ERROR_KEYWORDS):
            return Severity.ERROR
    return base


class FirewalldParser(LogParser):
    FORMAT_NAME = "firewalld"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "firewalld" in path.name.lower():
            return True
        return syslog_tag_dominant(sample_lines, _PATTERN, path=path)

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(f"{m['month']} {m['day']} {_CURRENT_YEAR} {m['time']}")
        except (ValueError, TypeError, OverflowError):
            ts = None
        raw_message = m["message"].strip()
        severity = _firewalld_severity(raw_message)
        message = _LEVEL_RE.sub("", raw_message)
        extra: dict[str, object] = {"program": "firewalld"}
        if m["pid"]:
            extra["pid"] = m["pid"]
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="firewalld",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
