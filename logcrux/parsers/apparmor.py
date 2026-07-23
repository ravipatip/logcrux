from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# AppArmor mandatory-access-control audit records (kernel/auditd). The
# distinctive token is apparmor="DENIED"/"ALLOWED"/"STATUS" inside a type=1400
# audit line, usually carried over syslog with a kernel/audit prefix:
#   ... audit: type=1400 ...: apparmor="DENIED" operation="open" profile="/usr/sbin/mysqld"
#   ... kernel: audit: type=1400 ...: apparmor="STATUS" operation="profile_load" name="/usr/bin/man"
# Matched ahead of the kernel/auditd parsers because apparmor="…" is unique.
# Detection requires apparmor lines to *dominate* the sample: a kern.log or
# syslog with one stray denial among ordinary kernel lines must stay with the
# kernel/syslog parser, which handles every line, not just the denials.
_APPARMOR_RE = re.compile(r'apparmor="(?P<mode>\w+)"')
_FIELD_RE = re.compile(r'(\w+)="([^"]*)"')
_SYSLOG_TS_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
)
_MODE_SEVERITY = {
    "DENIED": Severity.WARNING,
    "ALLOWED": Severity.INFO,
    "AUDIT": Severity.INFO,
    "STATUS": Severity.INFO,
    "ERROR": Severity.ERROR,
    "HINT": Severity.INFO,
}


class AppArmorParser(LogParser):
    FORMAT_NAME = "apparmor"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        sample = [ln for ln in sample_lines[:25] if ln.strip()]
        if not sample:
            return False
        hits = sum(1 for ln in sample if _APPARMOR_RE.search(ln))
        return hits * 2 > len(sample)

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        mode_m = _APPARMOR_RE.search(line)
        if not mode_m:
            return None
        ts = None
        ts_m = _SYSLOG_TS_RE.match(line)
        if ts_m:
            try:
                ts = dateparser.parse(
                    f"{ts_m['month']} {ts_m['day']} {datetime.now().year} {ts_m['time']}"
                )
            except Exception:
                ts = None
        fields = dict(_FIELD_RE.findall(line))
        mode = mode_m.group("mode")
        extra: dict[str, object] = {"apparmor": mode}
        for key in ("operation", "profile", "name", "comm", "pid", "denied_mask"):
            if key in fields:
                extra[key] = fields[key]
        return ParsedEvent(
            timestamp=ts,
            severity=_MODE_SEVERITY.get(mode, Severity.INFO),
            source="apparmor",
            message=line.split("audit:", 1)[-1].strip() if "audit:" in line else line.strip(),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
