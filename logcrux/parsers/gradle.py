from __future__ import annotations

import re
from pathlib import Path

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Gradle build console output (untimestamped). Recognised by its task lines and
# build-result banners:
#   > Task :app:compileJava
#   > Task :app:test FAILED
#   FAILURE: Build failed with an exception.
#   * What went wrong:
#   BUILD FAILED in 12s
#   BUILD SUCCESSFUL in 8s
_TASK_RE = re.compile(r"^> Task (?P<task>\S+)(?:\s+(?P<status>[A-Z\-]+))?\s*$")
_MARKERS = ("> Task ", "BUILD SUCCESSFUL", "BUILD FAILED", "FAILURE:",
            "> Configure project", "What went wrong:")
_ERROR_MARKERS = ("BUILD FAILED", "FAILURE:", "What went wrong:", "* Exception is:")


class GradleParser(LogParser):
    FORMAT_NAME = "gradle"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return any(any(mk in ln for mk in _MARKERS) for ln in sample_lines[:30])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line.strip():
            return None
        stripped = line.rstrip()
        severity = Severity.INFO
        extra: dict[str, object] = {}
        tm = _TASK_RE.match(stripped)
        if tm:
            extra["task"] = tm["task"]
            status = tm["status"]
            if status:
                extra["status"] = status
                if status == "FAILED":
                    severity = Severity.ERROR
        elif stripped.startswith("BUILD SUCCESSFUL"):
            severity = Severity.INFO
        elif any(mk in stripped for mk in _ERROR_MARKERS):
            severity = Severity.ERROR
        elif stripped.lower().startswith("w: ") or "warning:" in stripped.lower():
            severity = Severity.WARNING
        elif stripped.lower().startswith("e: ") or stripped.startswith("> "):
            if stripped.startswith("> ") and "warning" not in stripped.lower():
                severity = Severity.INFO
            else:
                severity = Severity.ERROR
        return ParsedEvent(
            timestamp=None,
            severity=severity,
            source="gradle",
            message=stripped,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
