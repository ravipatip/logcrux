from __future__ import annotations

import re
from pathlib import Path

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# BorgBackup's CLI output (borg 1.2.8, real runs, lab/apps6, 2026-10-20).
# A clean `borg create --stats --list` prints a stats block:
#   Repository: /repo
#   Archive name: nightly-1
#   Archive fingerprint: 89f3c8175124dba8d142f4e68dad3fe47a226410db1e7871f0be07d7fedddf78
#   A /src/a.bin
# A failed run is one line (each was generic and CLEAN before this parser):
#   passphrase supplied in BORG_PASSPHRASE, by BORG_PASSCOMMAND or via ... is incorrect.
#   Repository /repo does not exist.
# A source that cannot be read is a warning (rc 1) — the archive is still made:
#   /src/does-not-exist: stat: [Errno 2] No such file or directory: '/src/does-not-exist'
_MARKERS = re.compile(
    r"^Archive fingerprint: [0-9a-f]{64}$|^Archive name: \S"
    r"|passphrase supplied in BORG_PASSPHRASE"
    r"|^Repository \S+ does not exist\.$|is not a valid repository\. Check repo config"
    r"|^Failed to create/acquire the lock \S+"
    r"|^terminating with (?:error|warning) status, rc \d+$"
    r"|^Utilization of max\. archive size: "
)
# Wordings borg uses for a run that did not happen. Message text from borg's
# own error classes (helpers/errors.py), confirmed on the three real captures
# above; the others are borg's documented strings (confidence: low).
_FATAL = re.compile(
    r"passphrase supplied in BORG_PASSPHRASE.* is incorrect"
    r"|^Repository \S+ does not exist\.$|is not a valid repository"
    r"|^Failed to create/acquire the lock|^Archive \S+ already exists$"
    r"|^Connection closed by remote host|^Remote: .*(?:Error|error)"
    r"|^terminating with error status, rc \d+$|^Error: "
)
_PARTIAL = re.compile(r"^\S.*: (?:stat|open|read|scandir|lstat): \[Errno \d+\] "
                      r"|^terminating with warning status, rc \d+$")


class BorgParser(LogParser):
    FORMAT_NAME = "borg"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "borg" in path.name.lower():
            return True
        return any(_MARKERS.search(ln) for ln in sample_lines[:20])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        text = line.strip()
        if not text:
            return None
        extra: dict[str, object] = {}
        if _FATAL.search(text):
            severity, extra = Severity.ERROR, {"outcome": "failed", "detail": text}
        elif _PARTIAL.search(text):
            severity, extra = Severity.WARNING, {"outcome": "partial", "detail": text}
        else:
            severity = Severity.INFO
        return ParsedEvent(timestamp=None, severity=severity, source="borg", message=text,
                           raw=line, line_number=line_number, extra=extra)
