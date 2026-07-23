from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Apache ZooKeeper (log4j) server log:
#   2026-06-20 10:23:45,123 [myid:1] - INFO  [main:QuorumPeerMain@123] - msg
#   2026-06-20 10:23:45,123 [myid:] - WARN  [SyncThread:0:SyncRequestProcessor@1] - msg
#   2026-06-20 10:23:45,123 - ERROR [main:Service@99] - Unexpected exception
# The "[thread:Class@line]" segment is the distinctive shape.
_PATTERN = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) "
    r"(?:\[myid:(?P<myid>\d*)\] )?"
    r"- (?P<level>TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s+"
    # thread names can themselves contain brackets (e.g. "QuorumPeer[myid=1]"),
    # so match greedily up to the final ":Class@line" segment.
    r"\[(?P<thread>.+):(?P<cls>[\w.$]+)@(?P<lineno>\d+)\] - "
    r"(?P<message>.*)"
)

_LEVEL_MAP: dict[str, Severity] = {
    "TRACE": Severity.DEBUG,
    "DEBUG": Severity.DEBUG,
    "INFO": Severity.INFO,
    "WARN": Severity.WARNING,
    "ERROR": Severity.ERROR,
    "FATAL": Severity.CRITICAL,
}


class ZookeeperParser(LogParser):
    FORMAT_NAME = "zookeeper"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and ("zookeeper" in str(path).lower() or "zk" == path.stem.lower()):
            return True
        return any(_PATTERN.match(line) for line in sample_lines[:10])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["ts"].replace(",", "."))
        except (ValueError, TypeError, OverflowError):
            ts = None
        extra: dict[str, object] = {
            "level": m["level"],
            "thread": m["thread"],
            "class": m["cls"],
        }
        if m["myid"] is not None and m["myid"] != "":
            extra["myid"] = m["myid"]
        return ParsedEvent(
            timestamp=ts,
            severity=_LEVEL_MAP.get(m["level"], Severity.INFO),
            source="zookeeper",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
