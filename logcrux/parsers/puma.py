from __future__ import annotations

import re
from pathlib import Path

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Puma Ruby application-server log. Cluster-mode lines are prefixed "[PID]" with
# a "-"/"!" marker, plus the startup banner lines:
#   [12345] Puma starting in cluster mode...
#   [12345] - Worker 0 (PID: 12346) booted in 0.01s, phase: 0
#   [12345] ! Unable to load application: RuntimeError: boom
#   [12345] === puma startup ===
# The leading "[PID]" with Puma vocabulary is the distinctive signature.
_PATTERN = re.compile(r"^\[(?P<pid>\d+)\] (?P<marker>[-!*=])?\s*(?P<message>.*)$")
_MARKERS = ("Puma", "puma", "Worker", "cluster mode", "phase:", "booted",
            "Listening on", "Gracefully")


class PumaParser(LogParser):
    FORMAT_NAME = "puma"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        matched = [ln for ln in sample_lines[:25] if _PATTERN.match(ln)]
        if not matched:
            return False
        return any(mk in ln for ln in matched for mk in _MARKERS)

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        marker = m["marker"]
        message = m["message"].strip()
        low = message.lower()
        severity = Severity.INFO
        if marker == "!" or "unable" in low or "error" in low or "failed" in low:
            severity = Severity.ERROR
        elif "terminating" in low or "restart" in low or "shutdown" in low:
            severity = Severity.WARNING
        extra: dict[str, object] = {"pid": m["pid"]}
        if marker:
            extra["marker"] = marker
        return ParsedEvent(
            timestamp=None,
            severity=severity,
            source="puma",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
