from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Ceph distributed-storage daemon logs (ceph-osd / ceph-mon / ceph-mgr). Layout
# is "ts <hex-thread> <prio> <daemon> ... log [CHAN] : msg":
#   2026-06-28T10:15:01.123+0000 7f3c2b1e8700 -1 osd.5 12 log [ERR] : full
#   2026-06-28 10:15:02.456 7f3c2b1e8701  0 mon.a@0 e3 handle_command
# The "<8+hex-thread> <signed-int-prio>" pair after a sub-second timestamp is the
# distinctive Ceph signature; severity comes from the [INF]/[WRN]/[ERR]/[SEC]
# cluster-log channel tag when present, else from message keywords.
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\.\d+(?:[+-]\d{4})?) "
    r"(?P<thread>[0-9a-f]{8,})\s+"
    r"(?P<prio>-?\d+)\s+"
    r"(?P<message>.*)$"
)
_CHANNEL = re.compile(r"\[(?P<chan>INF|DBG|WRN|ERR|SEC)\]")
_ERROR_KW = ("error", "failed", "fail", "corrupt", "full", "down", "lost",
             "inconsistent", "stray", "cannot", "unable")
_WARN_KW = ("slow", "degraded", "scrub", "warn", "near full", "nearfull",
            "backfill", "recover", "laggy", "flapping")


def _severity(message: str) -> Severity:
    chan = _CHANNEL.search(message)
    if chan:
        return {
            "ERR": Severity.ERROR,
            "SEC": Severity.WARNING,
            "WRN": Severity.WARNING,
            "INF": Severity.INFO,
            "DBG": Severity.DEBUG,
        }[chan["chan"]]
    low = message.lower()
    if any(k in low for k in _ERROR_KW):
        return Severity.ERROR
    if any(k in low for k in _WARN_KW):
        return Severity.WARNING
    return Severity.INFO


class CephParser(LogParser):
    FORMAT_NAME = "ceph"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        matched = [ln for ln in sample_lines[:25] if _PATTERN.match(ln)]
        if not matched:
            return False
        # Require Ceph vocabulary so a generic "ts hex int msg" line can't poach.
        return any(
            mk in ln
            for ln in matched
            for mk in ("osd.", "mon.", "mgr", "mds.", "client.", "log [",
                       "pgmap", "rgw", "bluestore", "cephx")
        )

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["ts"])
        except (ValueError, TypeError, OverflowError):
            ts = None
        message = m["message"].strip()
        extra: dict[str, object] = {"thread": m["thread"], "priority": m["prio"]}
        chan = _CHANNEL.search(message)
        if chan:
            extra["channel"] = chan["chan"]
        return ParsedEvent(
            timestamp=ts,
            severity=_severity(message),
            source="ceph",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
