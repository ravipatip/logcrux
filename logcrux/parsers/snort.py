from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Snort / Snort3 IDS alert (fast/full alert format). The "[**] [gid:sid:rev]"
# marker is unmistakable:
#   06/20-10:15:01.123456  [**] [1:2001219:20] ET SCAN Potential SSH Scan [**]
#   [Classification: Attempted Information Leak] [Priority: 2] {TCP} 10.0.0.1:55000 -> 10.0.0.2:22
# Priority 1 = high, 2 = medium, 3 = low.
_ALERT_RE = re.compile(
    r"^(?:(?P<ts>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+)?"
    r"\[\*\*\]\s+\[(?P<sid>\d+:\d+:\d+)\]\s+(?P<name>.*?)\s+\[\*\*\]"
    r"(?:.*?\[Classification:\s*(?P<cls>[^\]]+)\])?"
    r"(?:.*?\[Priority:\s*(?P<prio>\d+)\])?"
    r"(?P<rest>.*)$"
)
_FLOW_RE = re.compile(r"\{(?P<proto>\w+)\}\s+(?P<src>\S+)\s+->\s+(?P<dst>\S+)")
_PRIO_MAP = {1: Severity.ERROR, 2: Severity.WARNING, 3: Severity.INFO}


class SnortParser(LogParser):
    FORMAT_NAME = "snort"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for ln in sample_lines[:20]:
            if "[**]" in ln and _ALERT_RE.match(ln):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _ALERT_RE.match(line)
        if not m:
            return None
        ts = None
        if m["ts"]:
            try:
                ts = dateparser.parse(f"{datetime.now().year}/{m['ts'].replace('-', ' ', 1)}")
            except (ValueError, TypeError, OverflowError):
                ts = None
        severity = Severity.WARNING
        if m["prio"]:
            severity = _PRIO_MAP.get(int(m["prio"]), Severity.WARNING)
        extra: dict[str, object] = {"signature": m["sid"]}
        if m["cls"]:
            extra["classification"] = m["cls"].strip()
        if m["prio"]:
            extra["priority"] = int(m["prio"])
        fm = _FLOW_RE.search(m["rest"])
        if fm:
            extra["proto"] = fm["proto"]
            extra["src"] = fm["src"]
            extra["dst"] = fm["dst"]
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="snort",
            message=m["name"].strip(),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
