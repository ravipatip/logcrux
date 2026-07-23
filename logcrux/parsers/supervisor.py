from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# supervisord activity log:
#   2026-06-20 10:23:45,123 INFO spawned: 'web' with pid 1234
#   2026-06-20 10:23:45,123 INFO success: web entered RUNNING state
#   2026-06-20 10:23:45,123 WARN received SIGTERM indicating exit request
#   2026-06-20 10:23:45,123 ERRO pool web event buffer overflowed
#   2026-06-20 10:23:45,123 CRIT could not write pidfile /var/run/supervisord.pid
# supervisord uses its own level words: BLAT/TRAC/DEBG/INFO/WARN/ERRO/CRIT.
_PATTERN = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) "
    r"(?P<level>BLAT|TRAC|DEBG|INFO|WARN|ERRO|CRIT) "
    r"(?P<message>.*)"
)

_LEVEL_MAP: dict[str, Severity] = {
    "BLAT": Severity.DEBUG,
    "TRAC": Severity.DEBUG,
    "DEBG": Severity.DEBUG,
    "INFO": Severity.INFO,
    "WARN": Severity.WARNING,
    "ERRO": Severity.ERROR,
    "CRIT": Severity.CRITICAL,
}

# supervisord vocabulary used to confirm detection (the timestamp+level shape
# alone is shared with other tools).
_VOCAB = (
    "spawned:", "exited:", "entered RUNNING", "entered FATAL", "entered BACKOFF",
    "entered STOPPED", "gave up:", "stopped:", "success:", "received SIG",
    "supervisord started", "event buffer", "pidfile", "RPC", "waiting for",
)

# A process that gives up or enters FATAL is a crash-loop signal.
_ERROR_HINTS = frozenset(["entered fatal", "gave up", "abnormal termination"])


def _supervisor_severity(level: str, message: str) -> Severity:
    base = _LEVEL_MAP.get(level, Severity.INFO)
    low = message.lower()
    if base in (Severity.INFO, Severity.WARNING) and any(h in low for h in _ERROR_HINTS):
        return Severity.ERROR
    return base


class SupervisorParser(LogParser):
    FORMAT_NAME = "supervisor"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "supervisor" in str(path).lower():
            return True
        for line in sample_lines[:10]:
            m = _PATTERN.match(line)
            if m and any(v in m["message"] for v in _VOCAB):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["ts"].replace(",", "."))
        except (ValueError, TypeError, OverflowError):
            ts = None
        message = m["message"].strip()
        return ParsedEvent(
            timestamp=ts,
            severity=_supervisor_severity(m["level"], message),
            source="supervisord",
            message=message,
            raw=line,
            line_number=line_number,
            extra={"level": m["level"]},
        )
