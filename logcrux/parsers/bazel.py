from __future__ import annotations

import re
from pathlib import Path

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Bazel build output. Lines are "<LEVEL>: <message>"; detection additionally
# requires a Bazel-specific phrase so a generic "INFO:" log can't be hijacked:
#   INFO: Analyzed target //src:app (3 packages loaded, 12 targets configured).
#   ERROR: /workspace/src/BUILD:10:11: Compiling src/main.cc failed: ...
#   INFO: Elapsed time: 12.345s, Critical Path: 5.67s
#   FAILED: Build did NOT complete successfully
_PATTERN = re.compile(r"^(?P<level>INFO|WARNING|ERROR|DEBUG|FAILED): (?P<message>.*)$")
_LEVEL_MAP = {
    "DEBUG": Severity.DEBUG,
    "INFO": Severity.INFO,
    "WARNING": Severity.WARNING,
    "ERROR": Severity.ERROR,
    "FAILED": Severity.CRITICAL,
}
_MARKERS = ("Analyzed target", "Critical Path", "total action", "Build completed",
            "did NOT complete", "Loading:", "Analyzing:", "Elapsed time:",
            "bazel", "packages loaded", "targets configured")

# Compiler diagnostics interleaved with the build output ("file.cc:42:5:
# error: ..."). These carry the actual failure cause, so dropping them as
# unparsed would hide the most useful lines of a failed build.
_DIAG = re.compile(
    r"^(?P<file>\S+?):(?P<line>\d+)(?::\d+)?: (?P<kind>error|warning|note): (?P<message>.*)$"
)
_DIAG_SEVERITY = {
    "error": Severity.ERROR,
    "warning": Severity.WARNING,
    "note": Severity.INFO,
}


class BazelParser(LogParser):
    FORMAT_NAME = "bazel"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        head = sample_lines[:30]
        has_level = any(_PATTERN.match(ln) for ln in head)
        has_marker = any(mk in ln for ln in head for mk in _MARKERS)
        return has_level and has_marker

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            d = _DIAG.match(line)
            if d is None:
                return None
            return ParsedEvent(
                timestamp=None,
                severity=_DIAG_SEVERITY[d["kind"]],
                source=d["file"],
                message=line.strip(),
                raw=line,
                line_number=line_number,
                extra={"level": d["kind"]},
            )
        return ParsedEvent(
            timestamp=None,
            severity=_LEVEL_MAP.get(m["level"], Severity.INFO),
            source="bazel",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"level": m["level"].lower()},
        )
