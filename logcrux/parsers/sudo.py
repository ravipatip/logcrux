from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, syslog_tag_dominant

# sudo audit lines in syslog/auth.log. The program tag is "sudo".
#   May 19 10:15:01 host sudo:  alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat
#   May 19 10:16:01 host sudo:      bob : 3 incorrect password attempts ; TTY=pts/1 ; ...
#   May 19 10:17:01 host sudo:      eve : user NOT in sudoers ; TTY=pts/2 ; ...
#   May 19 10:18:01 host sudo: pam_unix(sudo:auth): authentication failure; logname=eve uid=1003
_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"sudo(?:\[(?P<pid>\d+)\])?: "
    r"(?P<message>.*)"
)

# "    alice : TTY=... ; ... ; USER=root ; COMMAND=/bin/..."
_SESSION_RE = re.compile(
    r"^\s*(?P<user>[\w.\-]+) : "
    r"(?P<detail>.*?)"
    r"(?:;\s*USER=(?P<target>\S+))?"
    r"(?:\s*;\s*COMMAND=(?P<command>.*))?$"
)
_CURRENT_YEAR = datetime.now().year

# Failure / abuse signals that raise severity.
_FAIL_KEYWORDS = frozenset(
    ["incorrect password", "authentication failure", "not in the sudoers",
     "not in sudoers", "command not allowed", "auth could not identify",
     "a password is required", "unable to", "no tty present"]
)


def _sudo_severity(message: str) -> Severity:
    low = message.lower()
    if any(k in low for k in _FAIL_KEYWORDS):
        return Severity.WARNING
    return Severity.INFO


class SudoParser(LogParser):
    FORMAT_NAME = "sudo"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
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
        extra: dict[str, object] = {}
        if m["pid"]:
            extra["pid"] = m["pid"]
        sess = _SESSION_RE.match(message)
        if sess and sess["user"]:
            extra["user"] = sess["user"]
            if sess["target"]:
                extra["target_user"] = sess["target"]
            if sess["command"]:
                extra["command"] = sess["command"].strip()
        return ParsedEvent(
            timestamp=ts,
            severity=_sudo_severity(message),
            source="sudo",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
