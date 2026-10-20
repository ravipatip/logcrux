from __future__ import annotations

import re
from pathlib import Path

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# kopia's CLI output (kopia 0.18.2, official image, real runs 2026-10-20:
# lab/apps3). A clean run:
#   Snapshotting root@2bbdc9767b0e:/src ...
#   Created snapshot with root k06d25e0a9... and ID d35ea75da7... in 0s
#   Running full maintenance... / GC found 4 in-use contents ... / Finished full maintenance.
# A failed one is one or two ERROR lines (colour stripped by ingest.normalize):
#   ERROR failed to open repository: unable to create format manager: invalid repository password
#   ERROR encountered 2 errors:
#   failed to prepare source: ... lstat /src/does-not-exist: no such file or directory
#   ERROR open repository: unable to open repository: cannot open storage: ...
# Before this parser each was generic and CLEAN: one error line is no burst.
# Like restic, an ERROR line is the job's outcome, so the job-outcome
# detector reports it however short the output.
_MARKERS = re.compile(
    r"^Snapshotting \S+@\S+:\S.* \.\.\.$"
    r"|^Created snapshot with root k[0-9a-f]{8,} and ID [0-9a-f]{8,}"
    r"|^Running full maintenance\.\.\.$"
    r"|^ERROR (?:failed to open repository|error connecting to repository"
    r"|open repository: unable to open repository|encountered \d+ errors:)"
    r"|unable to create format manager|cannot open storage: cannot access storage path"
)
_ERROR = re.compile(r"^ERROR (?P<msg>.+)$")
_WARN = re.compile(r"^WARN(?:ING)? (?P<msg>.+)$")
_CREATED = re.compile(r"^Created snapshot with root (?P<root>k[0-9a-f]+) and ID (?P<id>[0-9a-f]+)")


_ENCOUNTERED = re.compile(r"^encountered \d+ errors?:$")


class KopiaParser(LogParser):
    FORMAT_NAME = "kopia"

    def __init__(self) -> None:
        # Inside "ERROR encountered N errors:" the next lines are the errors.
        self._error_block = 0

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "kopia" in path.name.lower():
            return True
        return any(_MARKERS.search(ln) for ln in sample_lines[:20])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        text = line.replace("\r", " ").strip()
        if not text:
            return None
        extra: dict[str, object] = {}
        m = _ERROR.match(text)
        if m and _ENCOUNTERED.match(m["msg"]):
            # The count line; the reasons follow on unprefixed lines.
            self._error_block = int(m["msg"].split()[1])
            severity = Severity.ERROR
        elif m:
            self._error_block = 0
            severity = Severity.ERROR
            extra = {"outcome": "failed", "detail": m["msg"]}
        elif self._error_block > 0:
            self._error_block -= 1
            severity = Severity.ERROR
            extra = {"outcome": "failed", "detail": text}
        elif _WARN.match(text):
            severity = Severity.WARNING
        else:
            severity = Severity.INFO
            c = _CREATED.match(text)
            if c:
                extra = {"snapshot_id": c["id"], "outcome": "saved"}
        return ParsedEvent(timestamp=None, severity=severity, source="kopia", message=text,
                           raw=line, line_number=line_number, extra=extra)

    def is_continuation(self, line: str) -> bool:
        return False
