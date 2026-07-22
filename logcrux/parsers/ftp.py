from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# vsftpd native format:
# Mon Dec  4 08:25:00 2024 [pid 1234] CONNECT: Client "1.2.3.4"
# Mon Dec  4 08:25:05 2024 [pid 1234] [username] OK LOGIN: Client "1.2.3.4"
# Mon Dec  4 08:25:05 2024 [pid 1235] [anonymous] FAIL LOGIN: Client "1.2.3.4"
_VSFTPD = re.compile(
    r"\w{3} \w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2} \d{4} "
    r"\[pid (?P<pid>\d+)\] "
    r"(?:\[(?P<user>[^\]]+)\] )?"
    r"(?P<status>OK|FAIL|CONNECT)? ?"
    r"(?P<event>[A-Z_ ]+): (?P<message>.*)"
)

# xferlog / wu-ftpd / ProFTPD transfer log:
# Mon Dec  4 08:25:13 2024 1 192.168.1.100 551 /path/to/file.tgz b _ o r username ftp 0 * c
_XFERLOG = re.compile(
    r"(?P<ts>\w{3} \w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2} \d{4}) "
    r"(?P<duration>\d+) "
    r"(?P<remote_host>\S+) "
    r"(?P<filesize>\d+) "
    r"(?P<filename>\S+) "
    r"(?P<transfer_type>[ab]) "
    r"(?P<special_action>[_\w]) "
    r"(?P<direction>[io]) "
    r"(?P<access_mode>[agr]) "
    r"(?P<username>\S+) "
    r"(?P<service>\S+) "
    r"(?P<auth_method>\d+) "
    r"(?P<auth_user>\S+) "
    r"(?P<completion>[ci])"
)

_DETECT_VSFTPD = re.compile(r"\[pid \d+\] (?:OK|FAIL|CONNECT)")
_DETECT_XFER = re.compile(r"\w{3} \w{3}\s+\d+ \d{2}:\d{2}:\d{2} \d{4} \d+ \S+ \d+ /")


class FTPParser(LogParser):
    FORMAT_NAME = "ftp"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path:
            p = str(path).lower()
            if "vsftpd" in p or "proftpd" in p or "xferlog" in p or "ftpd" in p:
                return True
        return any(
            _DETECT_VSFTPD.search(line) or _DETECT_XFER.match(line)
            for line in sample_lines[:10]
        )

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _VSFTPD.match(line)
        if m:
            return self._parse_vsftpd(m, line, line_number)
        m = _XFERLOG.match(line)
        if m:
            return self._parse_xferlog(m, line, line_number)
        return None

    def _parse_vsftpd(self, m: re.Match[str], line: str, line_number: int) -> ParsedEvent:
        status = m["status"] or ""
        event = m["event"].strip()
        message = m["message"].strip()
        user = m["user"] or "?"
        severity = Severity.WARNING if status == "FAIL" else Severity.INFO
        ip_match = re.search(r'"([\d.]+)"', message)
        extra: dict[str, object] = {
            "user": user,
            "event": event,
            "status": status,
            "pid": m["pid"],
        }
        if ip_match:
            extra["client_ip"] = ip_match.group(1)
        try:
            # timestamp is embedded in line prefix before [pid ...]
            ts_str = line.split("[pid")[0].strip()
            ts = dateparser.parse(ts_str, fuzzy=True)
        except Exception:
            ts = None
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="vsftpd",
            message=f"{status} {event}: {message}" if status else f"{event}: {message}",
            raw=line,
            line_number=line_number,
            extra=extra,
        )

    def _parse_xferlog(self, m: re.Match[str], line: str, line_number: int) -> ParsedEvent:
        direction = "upload" if m["direction"] == "i" else "download"
        completed = m["completion"] == "c"
        try:
            ts = dateparser.parse(m["ts"], fuzzy=True)
        except Exception:
            ts = None
        severity = Severity.INFO if completed else Severity.WARNING
        status = "OK" if completed else "INTERRUPTED"
        message = (
            f"{direction} {m['filename']} {m['filesize']}B "
            f"by {m['username']}@{m['remote_host']} {status}"
        )
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="ftp",
            message=message,
            raw=line,
            line_number=line_number,
            extra={
                "remote_host": m["remote_host"],
                "filename": m["filename"],
                "filesize": int(m["filesize"]),
                "direction": direction,
                "username": m["username"],
                "transfer_type": "ascii" if m["transfer_type"] == "a" else "binary",
                "access_mode": {"a": "anonymous", "g": "guest", "r": "real"}.get(
                    m["access_mode"], m["access_mode"]
                ),
                "completed": completed,
                "duration_sec": int(m["duration"]),
            },
        )
