from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, syslog_tag_dominant

# cron / crond logs ride on the syslog format. The program tag is one of
# CROND, crond, cron, CRON, or anacron. Examples:
#   May 19 10:15:01 host CROND[12345]: (root) CMD (run-parts /etc/cron.hourly)
#   May 19 10:17:01 host crond[1234]: (CRON) bad minute (/etc/crontab)
#   May 19 10:18:01 host CRON[2345]: pam_unix(cron:session): session opened for user root
_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"(?P<prog>CROND|crond|cron|CRON|anacron)(?:\[(?P<pid>\d+)\])?: "
    r"(?P<message>.*)"
)

# (user) ACTION (command) — the canonical execution record
_CMD_RE = re.compile(r"\((?P<user>[^)]+)\) (?P<action>[A-Z]+) \((?P<command>.*)\)")
_CURRENT_YEAR = datetime.now().year

# Words that promote a cron line above INFO.
_ERROR_KEYWORDS = frozenset(
    ["error", "cannot", "can't", "failed",
     "unable", "no such", "permission denied", "fatal"]
)
_WARN_KEYWORDS = frozenset(
    ["bad", "orphaned", "deprecated", "skipping", "warning", "not allowed"]
)


def _cron_severity(action: str, message: str) -> Severity:
    low = message.lower()
    if any(k in low for k in _ERROR_KEYWORDS):
        return Severity.ERROR
    if any(k in low for k in _WARN_KEYWORDS):
        return Severity.WARNING
    return Severity.INFO


class CronParser(LogParser):
    FORMAT_NAME = "cron"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path:
            name = path.name.lower()
            if name in ("cron", "cron.log") or "cron" in name:
                return True
        return syslog_tag_dominant(sample_lines, _PATTERN, path=path)

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(
                f"{m['month']} {m['day']} {_CURRENT_YEAR} {m['time']}"
            )
        except Exception:
            ts = None
        message = m["message"].strip()
        extra: dict[str, object] = {"program": m["prog"]}
        if m["pid"]:
            extra["pid"] = m["pid"]
        action = ""
        cmd = _CMD_RE.search(message)
        if cmd:
            action = cmd["action"]
            extra["user"] = cmd["user"]
            extra["action"] = action
            extra["command"] = cmd["command"]
        return ParsedEvent(
            timestamp=ts,
            severity=_cron_severity(action, message),
            source="cron",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
