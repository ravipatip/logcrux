from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# macOS unified logging, as `log show` prints it (real capture, macOS 26 on
# Apple Silicon, 2026-10-20). Three styles:
#
#   default  Timestamp                       Thread     Type        Activity             PID    TTL
#            2026-10-20 06:36:28.860109+1100 0x1e1525   Error       0x0      ...
#              ...            0      0    kernel: [com.apple.xnu:vm] ...
#   compact  Timestamp               Ty Process[PID:TID]
#            2026-10-20 06:36:29.350 Df kernel[0:185e4] [com.apple.xnu.net.udp:] udp connect: ...
#   syslog   Timestamp                       (process)[PID]
#            2026-10-20 06:36:27.888749+1100  localhost kernel[0]: (CoreAnalyticsFamily) ...
#
# Message bodies continue on unprefixed lines (plist dumps, "so_gencnt: ..."),
# folded into their record — as separate generic events they carried their
# own embedded dates and stretched a 3-minute capture back a week.
#
# Levels: a healthy Mac writes ~100 "Error"-type records a minute (daemons use
# it for routine conditions: 314 in the 3-minute capture, "launchd: invalid
# client reply port -1"; Finder's "Failed to start plugin" for a sync
# extension), so Error is INFO here and Fault is WARNING — a daemon spamming
# faults still surfaces as a burst naming it; nothing is an ERROR by level.
# Read as keywords instead, routine "... failed for eventName" lines made the
# idle capture a 9,000-error "burst". The syslog style prints no level at
# all; its records are INFO and only the specific detectors (crash, OOM, ...)
# can judge them.
_TS = r"(?P<ts>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)(?P<tz>[+-]\d{4})?"
_DEFAULT = re.compile(
    _TS + r" +0x[0-9a-f]+ +(?P<type>Default|Info|Debug|Error|Fault|Activity|State|Signpost"
    r"|Timesync|Loss) +0x[0-9a-f]+ +(?P<pid>\d+) +\d+ +(?P<proc>[^:]+?): (?P<msg>.*)$"
)
_COMPACT = re.compile(
    _TS + r" (?P<type>Df|I |Db|E |F |A |Sd|Ss|Tm|L ) +(?P<proc>[^\[\s]+)\[(?P<pid>\d+):"
    r"[0-9a-f]+\] (?P<msg>.*)$"
)
_SYSLOG = re.compile(
    _TS + r" +(?P<host>\S+) (?P<proc>[^\[\s]+)\[(?P<pid>\d+)\]: (?P<msg>.*)$"
)
_HEADERS = (
    re.compile(r"^Timestamp +Thread +Type +Activity +PID +TTL"),
    re.compile(r"^Timestamp +Ty Process\[PID:TID\]"),
    re.compile(r"^Timestamp +\(process\)\[PID\]"),
    re.compile(r"^-{20,}|^Log +- +Default:|^Filtering the log data"),
)
_LEVELS = {
    "Fault": Severity.WARNING, "F ": Severity.WARNING,
    "Debug": Severity.DEBUG, "Db": Severity.DEBUG,
}


def _ts(m: re.Match[str]) -> datetime | None:
    try:
        ts = datetime.strptime(m["ts"][:26], "%Y-%m-%d %H:%M:%S.%f")
    except ValueError:
        return None
    if m["tz"]:
        try:
            return ts.replace(tzinfo=datetime.strptime(m["tz"], "%z").tzinfo)
        except ValueError:
            return ts
    return ts


class MacOSUnifiedParser(LogParser):
    FORMAT_NAME = "macos-unified"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if any(h.match(ln) for ln in sample_lines[:3] for h in _HEADERS[:3]):
            return True
        # Headerless (`log show | tail`): the default and compact styles are
        # unmistakable — thread id + macOS log type, or Process[PID:TID].
        hits = sum(1 for ln in sample_lines[:20] if _DEFAULT.match(ln) or _COMPACT.match(ln))
        return hits >= 3

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if any(h.match(line) for h in _HEADERS):
            self.meta_lines += 1
            return None
        for rx in (_DEFAULT, _COMPACT, _SYSLOG):
            m = rx.match(line)
            if m:
                break
        else:
            return None
        typ = m.groupdict().get("type")
        return ParsedEvent(
            timestamp=_ts(m),
            severity=_LEVELS.get(typ or "", Severity.INFO),
            source=m["proc"],
            message=f"{m['proc']}: {m['msg']}",
            raw=line,
            line_number=line_number,
            extra={"pid": m["pid"], **({"type": typ.strip()} if typ else {})},
        )

    def is_continuation(self, line: str) -> bool:
        # Anything that is not a record or a header belongs to the record above.
        return not any(h.match(line) for h in _HEADERS)
