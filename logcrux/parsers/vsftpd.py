from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, syslog_tag_dominant

# vsftpd with syslog_enable=YES routes session/auth events through syslog,
# tagged "vsftpd". This is distinct from the native vsftpd.log / xferlog
# transfer records handled by the `ftp` parser.
#   May 19 10:15:01 host vsftpd[1234]: CONNECT: Client "1.2.3.4"
#   May 19 10:15:02 host vsftpd[1234]: [alice] OK LOGIN: Client "1.2.3.4"
#   May 19 10:15:03 host vsftpd[1235]: [anonymous] FAIL LOGIN: Client "5.6.7.8"
#   May 19 10:15:04 host vsftpd[1234]: [bob] OK DOWNLOAD: Client "1.2.3.4", "/pub/f.iso", 1024 bytes
_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"vsftpd(?:\[(?P<pid>\d+)\])?: "
    r"(?:\[(?P<user>[^\]]+)\] )?"
    r"(?P<status>OK|FAIL|CONNECT)?\s?"
    r"(?P<event>[A-Z_ ]+?): (?P<message>.*)"
)

_CLIENT_IP_RE = re.compile(r'"(\d{1,3}(?:\.\d{1,3}){3})"')
_CURRENT_YEAR = datetime.now().year


def _vsftpd_severity(status: str, event: str) -> Severity:
    if status == "FAIL":
        return Severity.WARNING
    return Severity.INFO


class VsftpdParser(LogParser):
    FORMAT_NAME = "vsftpd"

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
        status = m["status"] or ""
        event = m["event"].strip()
        message = m["message"].strip()
        extra: dict[str, object] = {
            "event": event,
            "status": status,
            "user": m["user"] or "?",
        }
        if m["pid"]:
            extra["pid"] = m["pid"]
        ip = _CLIENT_IP_RE.search(message)
        if ip:
            extra["client_ip"] = ip.group(1)
        label = f"{status} {event}" if status else event
        return ParsedEvent(
            timestamp=ts,
            severity=_vsftpd_severity(status, event),
            source="vsftpd",
            message=f"{label}: {message}",
            raw=line,
            line_number=line_number,
            extra=extra,
        )
