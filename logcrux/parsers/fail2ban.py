from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# 2024-12-04 08:25:07,305 fail2ban.actions [8765]: NOTICE  [sshd] Ban 192.168.1.100
# 2024-12-04 08:25:08,128 fail2ban.filter  [8765]: INFO     [sshd] Found 192.168.1.100
# 2024-12-04 08:25:00,101 fail2ban.server  [8765]: INFO    Starting Fail2ban v1.0.2
# NOTICE is the level fail2ban actually uses for Ban/Unban actions — the most
# important lines in the log; the jail prefix is absent on fail2ban.server lines.
_PATTERN = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+ "
    r"fail2ban\.(?P<component>[\w.]+)\s+\[(?P<pid>\d+)\]: "
    r"(?P<level>DEBUG|HEAVYDEBUG|TRACEDEBUG|INFO|NOTICE|WARNING|ERROR|CRITICAL)\s+"
    r"(?:\[(?P<jail>[^\]]+)\] )?"
    r"(?P<message>.*)"
)

_DETECT = re.compile(r"fail2ban\.\w+\s+\[\d+\]:")


_BAN_WORD = re.compile(r"\bban(?:ned)?\b")


def _f2b_severity(level: str, message: str) -> Severity:
    # Word-boundary match: a bare substring check reads "ban" inside
    # "Fail2ban"/"Unban" and misclassifies startup and unban lines.
    low = message.lower()
    if _BAN_WORD.search(low) and "unban" not in low:
        return Severity.WARNING
    if level == "WARNING":
        return Severity.WARNING
    if level in ("ERROR", "CRITICAL"):
        return Severity.ERROR
    return Severity.INFO


class Fail2BanParser(LogParser):
    FORMAT_NAME = "fail2ban"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "fail2ban" in path.name.lower():
            return True
        return any(_DETECT.search(line) for line in sample_lines[:10])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["ts"])
        except Exception:
            ts = None
        message = m["message"].strip()
        jail = m["jail"]
        level = m["level"]

        # Extract banned/unbanned IP
        ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", message)
        extra: dict[str, object] = {
            "component": m["component"],
            "level": level,
        }
        if jail:
            extra["jail"] = jail
        if ip_match:
            extra["ip"] = ip_match.group(1)
        action = None
        if message.startswith("Ban "):
            action = "ban"
        elif message.startswith("Unban "):
            action = "unban"
        elif message.startswith("Found "):
            action = "found"
        if action:
            extra["action"] = action

        return ParsedEvent(
            timestamp=ts,
            severity=_f2b_severity(level, message),
            source="fail2ban",
            message=f"[{jail}] {message}" if jail else message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
