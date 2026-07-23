from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# rsync daemon (rsyncd) log. Each line is "YYYY/MM/DD HH:MM:SS [pid] message":
#   2026/06/28 10:15:01 [1234] rsyncd version 3.2.7 starting, listening on port 873
#   2026/06/28 10:15:02 [1234] connect from client (1.2.3.4)
#   2026/06/28 10:15:03 [1234] rsync: failed to connect to host: Connection refused
#   2026/06/28 10:15:04 [1234] sent 1024 bytes  received 64 bytes  total size 4096
# The "YYYY/MM/DD HH:MM:SS [pid]" + rsync vocabulary is the signature.
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) "
    r"\[(?P<pid>\d+)\] (?P<message>.*)$"
)
_RSYNC_MARKERS = ("rsync", "connect from", "sent ", "received ", "rsyncd",
                  "building file list", "total size", "auth failed",
                  "module", "transfer", "@ERROR", "deleting", "delta-transmission")
_ERROR_MARKERS = ("error", "failed", "refused", "rsync error", "@error",
                  "cannot", "unable", "timeout", "denied", "no route")
_WARN_MARKERS = ("auth failed", "retr", "warning", "skipping", "ignoring",
                 "partial", "vanished")


def _severity(message: str) -> Severity:
    low = message.lower()
    # An auth failure is a warning, not a hard error — check it before the
    # generic "failed" → ERROR rule that would otherwise swallow it.
    if any(m in low for m in _WARN_MARKERS):
        return Severity.WARNING
    if any(m in low for m in _ERROR_MARKERS):
        return Severity.ERROR
    return Severity.INFO


class RsyncdParser(LogParser):
    FORMAT_NAME = "rsyncd"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for ln in sample_lines[:20]:
            m = _PATTERN.match(ln)
            if m and any(mk in m["message"].lower() for mk in _RSYNC_MARKERS):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        if not any(mk in m["message"].lower() for mk in _RSYNC_MARKERS):
            return None
        try:
            ts = dateparser.parse(m["ts"].replace("/", "-", 2))
        except (ValueError, TypeError, OverflowError):
            ts = None
        return ParsedEvent(
            timestamp=ts,
            severity=_severity(m["message"]),
            source="rsyncd",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"pid": m["pid"]},
        )
