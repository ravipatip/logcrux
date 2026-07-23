from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# CockroachDB server logs (crdb-v2 format). Each entry is a severity letter +
# 6-digit date + time, goroutine, file:line, a "⋮" tag-redaction marker, then
# optional [tags] and the message:
#   I260628 10:15:01.123456 123 server/server.go:1600 ⋮ [n1] node starting
#   W260628 10:15:02.234567 55 kv/kvserver/replica.go:99 ⋮ [n1,s1,r5] slow ...
#   E260628 10:15:03.345678 7 server/node.go:500 ⋮ [n1] failed to gossip
# The "⋮" marker disambiguates crdb from glog/klog (which share the letter+date
# prefix). The 6-digit YYMMDD date and goroutine column reinforce detection.
_LEVELS = {
    "I": Severity.INFO,
    "W": Severity.WARNING,
    "E": Severity.ERROR,
    "F": Severity.CRITICAL,
}
_PATTERN = re.compile(
    r"^(?P<sev>[IWEF])(?P<date>\d{6}) (?P<time>\d{2}:\d{2}:\d{2}\.\d+) "
    r"(?P<goroutine>\d+) (?P<loc>[\w./-]+:\d+) ⋮ "
    r"(?:\[(?P<tags>[^\]]*)\] )?(?P<message>.*)$"
)


class CockroachDBParser(LogParser):
    FORMAT_NAME = "cockroachdb"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return any(_PATTERN.match(ln) for ln in sample_lines[:20])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        ts = None
        try:
            yy = int(m["date"][0:2])
            mm = int(m["date"][2:4])
            dd = int(m["date"][4:6])
            h, mi, rest = m["time"].split(":")
            sec, _, frac = rest.partition(".")
            micros = int((frac + "000000")[:6]) if frac else 0
            ts = datetime(2000 + yy, mm, dd, int(h), int(mi), int(sec),
                          micros, tzinfo=timezone.utc)
        except (ValueError, IndexError):
            ts = None
        extra: dict[str, object] = {
            "level": m["sev"],
            "loc": m["loc"],
            "goroutine": m["goroutine"],
        }
        if m["tags"]:
            extra["tags"] = m["tags"]
        return ParsedEvent(
            timestamp=ts,
            severity=_LEVELS.get(m["sev"], Severity.INFO),
            source="cockroachdb",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
