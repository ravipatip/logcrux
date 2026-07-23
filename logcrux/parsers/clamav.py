from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# ClamAV antivirus (clamd / freshclam). Lines begin with a ctime-style stamp
# followed by " -> " and the message:
#   Sat Jun 28 10:15:01 2026 -> Limits: Global size limit set to ...
#   Sat Jun 28 10:15:02 2026 -> /home/user/evil.zip: Win.Trojan.Agent FOUND
#   Sat Jun 28 10:15:03 2026 -> Database correctly reloaded (8000000 signatures)
#   Sat Jun 28 10:15:04 2026 -> ERROR: Can't open/parse the config file
# The "Day Mon DD HH:MM:SS YYYY -> " shape is the distinctive signature.
_PATTERN = re.compile(
    r"^(?P<ts>\w{3} \w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2} \d{4}) -> "
    r"(?P<message>.*)$"
)


def _severity(message: str) -> Severity:
    low = message.lower()
    if "found" in low and not low.startswith("found "):
        # "<path>: <Signature> FOUND" — an actual malware detection.
        return Severity.CRITICAL
    if low.startswith("error") or low.startswith("error:") or "error:" in low:
        return Severity.ERROR
    if "can't" in low or "cannot" in low or "failed" in low or "fatal" in low:
        return Severity.ERROR
    if "warning" in low or "outdated" in low or "won't" in low:
        return Severity.WARNING
    return Severity.INFO


class ClamAVParser(LogParser):
    FORMAT_NAME = "clamav"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return any(_PATTERN.match(ln) for ln in sample_lines[:20])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["ts"])
        except (ValueError, TypeError, OverflowError):
            ts = None
        message = m["message"].strip()
        extra: dict[str, object] = {}
        found = re.match(r"(?P<path>.+): (?P<sig>\S+) FOUND$", message)
        if found:
            extra["infected_path"] = found.group("path")
            extra["signature"] = found.group("sig")
        return ParsedEvent(
            timestamp=ts,
            severity=_severity(message),
            source="clamav",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
