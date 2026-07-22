from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, syslog_tag_dominant

# SSSD (System Security Services Daemon) — central auth/identity on enterprise
# Linux (FreeIPA/AD/LDAP). Logs through syslog with an "sssd" family tag whose
# responder/backend is in brackets:
#   Jun 28 10:15:01 host sssd[be[example.com]][1234]: Backend is online
#   Jun 28 10:15:02 host sssd[pam][1234]: Requesting info for [user@dom]
#   Jun 28 10:15:03 host sssd[nss][1234]: Enumeration requested but not enabled
#   Jun 28 10:15:04 host sssd[1234]: Starting up
_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"(?P<prog>sssd(?:\[[^:]+\])?)\[(?P<pid>\d+)\]: "
    r"(?P<message>.*)"
)
_CURRENT_YEAR = datetime.now().year

_ERROR_MARKERS = ("offline", "cannot", "failed", "unable to", "error",
                  "no such", "connection refused", "timed out", "ldap_",
                  "could not", "denied", "fatal", "critical")
_WARN_MARKERS = ("retrying", "going offline", "not available", "unavailable",
                 "expired", "lock", "skipping", "ignoring", "no servers")


def _severity(message: str) -> Severity:
    low = message.lower()
    # A transient "going offline, retrying" is a warning; check the warn
    # markers first so the generic "offline" → ERROR rule doesn't swallow them.
    if any(m in low for m in _WARN_MARKERS):
        return Severity.WARNING
    if any(m in low for m in _ERROR_MARKERS):
        return Severity.ERROR
    return Severity.INFO


class SssdParser(LogParser):
    FORMAT_NAME = "sssd"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return syslog_tag_dominant(sample_lines, _PATTERN, path=path)

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
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
        extra: dict[str, object] = {"program": m["prog"], "pid": m["pid"]}
        comp = re.match(r"sssd\[([^\]]+)\]", m["prog"])
        if comp:
            extra["component"] = comp.group(1)
        return ParsedEvent(
            timestamp=ts,
            severity=_severity(message),
            source="sssd",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
