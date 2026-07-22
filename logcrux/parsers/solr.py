from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# Apache Solr search-server log (solr.log). Default layout is
# "ts LEVEL  (thread) [context] logger message":
#   2026-06-28 10:15:01.123 INFO  (main) [   ] o.a.s.c.SolrCore Created core
#   2026-06-28 10:15:02.456 WARN  (qtp123-45) [c:books] o.a.s.h.RequestHandlerBase
#   2026-06-28 10:15:03.789 ERROR (coreLoad-1) [   ] o.a.s.c.CoreContainer error
# The "(qtp…/thread) [context] o.a.s.…" shape is the distinctive signature.
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) "
    r"(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL)\s+"
    r"\((?P<thread>[^)]+)\) "
    r"\[(?P<context>[^\]]*)\] "
    r"(?P<message>.*)$"
)
_SOLR_MARKERS = ("o.a.s.", "org.apache.solr", "SolrCore", "CoreContainer",
                 "qtp", "solr")


class SolrParser(LogParser):
    FORMAT_NAME = "solr"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        matched = [ln for ln in sample_lines[:25] if _PATTERN.match(ln)]
        if not matched:
            return False
        return any(mk in ln for ln in matched for mk in _SOLR_MARKERS)

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["ts"])
        except (ValueError, TypeError, OverflowError):
            ts = None
        message = m["message"].strip()
        extra: dict[str, object] = {
            "level": m["level"].lower(),
            "thread": m["thread"],
        }
        if m["context"].strip():
            extra["context"] = m["context"].strip()
        return ParsedEvent(
            timestamp=ts,
            severity=level_to_severity(m["level"]),
            source="solr",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
