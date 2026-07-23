from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, level_to_severity

# GlusterFS distributed-filesystem logs (glusterd/brick/mount logs). Layout is
# "[ts] <L> [MSGID: nnn] [file.c:line:func] 0-volume: message":
#   [2026-06-28 10:15:01.123456] I [MSGID: 100030] [glusterfsd.c:2867:main] 0-gv0: Started
#   [2026-06-28 10:15:02.234567] W [MSGID: 114031] [client-rpc.c:2860:fn] 0-gv0-client-1: op failed
#   [2026-06-28 10:15:03.345678] E [MSGID: 108006] [afr-common.c:5618:fn] 0-gv0-rep-0: subvols down
# The "[ts] <single-letter-level> [MSGID: n] [src]" shape is the signature.
_PATTERN = re.compile(
    r"^\[(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\] "
    r"(?P<level>[A-Z]) "
    r"(?:\[MSGID: (?P<msgid>\d+)\] )?"
    r"(?:\[(?P<src>[^\]]+)\] )?"
    r"(?P<message>.*)$"
)
# GlusterFS uses single-letter levels: M(emerg/critical) A(alert) C(critical)
# E(error) W(warning) I(info) D(debug) T(trace).
_LEVEL_MAP = {
    "M": Severity.CRITICAL,
    "A": Severity.CRITICAL,
    "C": Severity.CRITICAL,
    "E": Severity.ERROR,
    "W": Severity.WARNING,
    "N": Severity.INFO,
    "I": Severity.INFO,
    "D": Severity.DEBUG,
    "T": Severity.DEBUG,
}


class GlusterFSParser(LogParser):
    FORMAT_NAME = "glusterfs"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        matched = [ln for ln in sample_lines[:25] if _PATTERN.match(ln)]
        if not matched:
            return False
        # Require Gluster vocabulary so the bracket-ts shape can't poach others.
        return any(
            mk in ln
            for ln in matched
            for mk in ("MSGID:", "glusterfs", "glusterd", "0-", "afr-", "brick",
                       "-client-", "-replicate-")
        )

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["ts"])
        except (ValueError, TypeError, OverflowError):
            ts = None
        extra: dict[str, object] = {"level": m["level"]}
        if m["msgid"]:
            extra["msgid"] = m["msgid"]
        if m["src"]:
            extra["src"] = m["src"]
        severity = _LEVEL_MAP.get(m["level"], level_to_severity(m["level"]))
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="glusterfs",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
