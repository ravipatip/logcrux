from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, syslog_tag_dominant
from logcrux.parsers.syslog import _ISO_PATTERN as _SYSLOG_ISO_PATTERN
from logcrux.parsers.syslog import _infer_severity as _syslog_severity

# Auth-program syslog tags (sshd/sudo/su/login + PAM). Used to decide whether a
# file is *really* an auth log, not just a mixed /var/log/syslog that happens to
# mention sshd once.
_AUTH_TAG_PATTERN = re.compile(
    r"\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2} \S+ "
    r"(?:sshd|sudo|su|login|systemd-logind|polkitd)(?:\[\d+\])?: "
)

# Reuse syslog pattern — auth logs use the same syslog format
_SYSLOG_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"(?P<source>[^:\[]+?)(?:\[(?P<pid>\d+)\])?: "
    r"(?P<message>.*)"
)
_CURRENT_YEAR = __import__("datetime").datetime.now().year

_IP_RE = re.compile(
    r"from ((?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}|(?:\d{1,3}\.){3}\d{1,3})"
)
_USER_RE = re.compile(r"(?:for|user) (\S+) from")
_AUTH_FAILURES = frozenset(["failed password", "invalid user", "connection closed by invalid"])
_AUTH_SUCCESS = frozenset(["accepted password", "accepted publickey", "accepted keyboard"])


def _auth_severity(source: str, message: str) -> Severity:
    low = message.lower()
    if any(k in low for k in _AUTH_FAILURES):
        return Severity.WARNING
    if any(k in low for k in _AUTH_SUCCESS):
        return Severity.INFO
    # For messages not matching any auth pattern, fall back to generic keyword
    # detection so sshd errors ("error connecting to database") aren't silently
    # dropped to INFO.
    return _syslog_severity(source, message)


class SecureParser(LogParser):
    FORMAT_NAME = "secure"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and path.name in ("secure", "auth.log"):
            return True
        # Claim the file only when auth-program tags *dominate* the syslog lines.
        # A loose any("sshd"/"Accepted") check hijacked any mixed /var/log/syslog
        # containing a single sshd line, mislabeling a clean host log as an SSH
        # auth log. syslog_tag_dominant requires a true majority and skips
        # aggregate syslog filenames. (It only inspects syslog-shaped lines, so a
        # JSON logger quoting "Failed password" is excluded automatically.)
        return syslog_tag_dominant(sample_lines, _AUTH_TAG_PATTERN, path=path)

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _SYSLOG_PATTERN.match(line)
        if m:
            try:
                ts = dateparser.parse(
                    f"{m['month']} {m['day']} {_CURRENT_YEAR} {m['time']}"
                )
            except Exception:
                ts = None
        else:
            m = _SYSLOG_ISO_PATTERN.match(line)
            if not m:
                return None
            try:
                ts = dateparser.parse(m["ts"])
            except Exception:
                ts = None
        source = m["source"].strip()
        message = m["message"].strip()
        extra: dict[str, str] = {}
        if m["pid"]:
            extra["pid"] = m["pid"]
        ip_match = _IP_RE.search(message)
        if ip_match:
            extra["client_ip"] = ip_match.group(1)
        user_match = _USER_RE.search(message)
        if user_match:
            extra["user"] = user_match.group(1)
        return ParsedEvent(
            timestamp=ts,
            severity=_auth_severity(source, message),
            source=source,
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
