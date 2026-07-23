from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, syslog_tag_dominant

# Samba supports two layouts.
#
# A) syslog-tagged (smbd/nmbd/winbindd logging through syslog):
#    May 19 10:15:01 host smbd[1234]: [2024/05/19 10:15:01.123456,  0] auth/auth.c:319
#    May 19 10:15:01 host smbd[1234]:   Auth: user [WG]\[alice] FAILED NT_STATUS_WRONG_PASSWORD
#
# B) native debug log (log.smbd) — the bracketed timestamp + debug level:
#    [2024/05/19 10:15:01.123456,  0] ../source3/smbd/server.c:1320(main)
#      NT_STATUS_LOGON_FAILURE
_SYSLOG_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"(?P<prog>smbd|nmbd|winbindd|samba)(?:\[(?P<pid>\d+)\])?: "
    r"(?P<message>.*)"
)
_NATIVE_PATTERN = re.compile(
    r"\[(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)?,\s*(?P<level>\d+)\] "
    r"(?P<message>.*)"
)

_NT_STATUS_RE = re.compile(r"(NT_STATUS_[A-Z_]+)")
_CURRENT_YEAR = datetime.now().year

# Authentication-failure NT statuses → brute-force signal territory.
_AUTH_FAIL_STATUSES = frozenset(
    ["NT_STATUS_LOGON_FAILURE", "NT_STATUS_WRONG_PASSWORD",
     "NT_STATUS_ACCOUNT_LOCKED_OUT", "NT_STATUS_NO_SUCH_USER",
     "NT_STATUS_ACCESS_DENIED", "NT_STATUS_PASSWORD_EXPIRED"]
)
_ERROR_KEYWORDS = frozenset(
    ["error", "failed", "fatal", "panic", "corrupt", "cannot", "unable",
     "could not", "smb_panic", "internal error"]
)


def _samba_severity(level: int | None, message: str) -> Severity:
    up = message.upper()
    status = _NT_STATUS_RE.search(up)
    if status and status.group(1) in _AUTH_FAIL_STATUSES:
        return Severity.WARNING
    if "FAILED" in up and "NT_STATUS" in up:
        return Severity.WARNING
    low = message.lower()
    if "panic" in low or "internal error" in low:
        return Severity.CRITICAL
    if any(k in low for k in _ERROR_KEYWORDS):
        return Severity.ERROR
    if level is not None and level == 0 and message.strip():
        # debug level 0 carries operator-facing errors/warnings
        return Severity.WARNING
    return Severity.INFO


class SambaParser(LogParser):
    FORMAT_NAME = "samba"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path:
            name = path.name.lower()
            if "smbd" in name or "samba" in name or "nmbd" in name or "winbind" in name:
                return True
        if any(_NATIVE_PATTERN.match(line) for line in sample_lines[:10]):
            return True
        return syslog_tag_dominant(sample_lines, _SYSLOG_PATTERN, path=path)

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _SYSLOG_PATTERN.match(line)
        if m:
            return self._make_syslog(m, line, line_number)
        m = _NATIVE_PATTERN.match(line)
        if m:
            return self._make_native(m, line, line_number)
        return None

    def _make_syslog(self, m: re.Match[str], line: str, line_number: int) -> ParsedEvent:
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
        status = _NT_STATUS_RE.search(message.upper())
        if status:
            extra["nt_status"] = status.group(1)
        return ParsedEvent(
            timestamp=ts,
            severity=_samba_severity(None, message),
            source=m["prog"],
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )

    def _make_native(self, m: re.Match[str], line: str, line_number: int) -> ParsedEvent:
        try:
            ts = dateparser.parse(m["ts"].replace("/", "-"), fuzzy=True)
        except Exception:
            ts = None
        message = m["message"].strip()
        level = int(m["level"])
        extra: dict[str, object] = {"debug_level": level}
        status = _NT_STATUS_RE.search(message.upper())
        if status:
            extra["nt_status"] = status.group(1)
        return ParsedEvent(
            timestamp=ts,
            severity=_samba_severity(level, message),
            source="samba",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
