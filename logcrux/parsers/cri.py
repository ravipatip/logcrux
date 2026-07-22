from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser
from logcrux.parsers.docker import _infer_severity, _level_from_message

# The CRI (Container Runtime Interface) log format is what containerd and CRI-O
# write for every container on a modern Kubernetes node (the json-file Docker
# format went away with dockershim in k8s 1.24). Each line is:
#
#   <RFC3339Nano timestamp> <stream> <tag> <message>
#
# e.g.  2026-06-29T08:41:02.551239871Z stderr F java.lang.OutOfMemoryError
#
# stream is "stdout"/"stderr"; tag is "F" (full line) or "P" (partial line that
# the runtime split at the 16KiB read boundary and will continue on the next
# entry). This is the on-disk shape of /var/log/containers/*.log and
# /var/log/pods/<ns>_<pod>_<uid>/<container>/*.log.
_CRI_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))"
    r"\s+(?P<stream>stdout|stderr)"
    r"\s+(?P<tag>[FP])"
    r"\s(?P<msg>.*)$"
)


def parse_cri_line(line: str, line_number: int, source: str) -> ParsedEvent | None:
    m = _CRI_RE.match(line)
    if not m:
        return None
    msg = m["msg"]
    stream = m["stream"]
    try:
        ts = dateparser.parse(m["ts"])
    except (ValueError, OverflowError):
        ts = None
    severity = _level_from_message(msg) or _infer_severity(msg, stream)
    return ParsedEvent(
        timestamp=ts,
        severity=severity,
        source=source,
        message=msg or "(empty)",
        raw=line,
        line_number=line_number,
        extra={"stream": stream, "partial": m["tag"] == "P"},
    )


class CRIParser(LogParser):
    """Containerd / CRI-O container logs (the modern k8s node log format)."""

    FORMAT_NAME = "cri"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path:
            p = str(path)
            if "/var/log/containers/" in p or "/var/log/pods/" in p:
                if any(_CRI_RE.match(line) for line in sample_lines[:10] if line.strip()):
                    return True
        return any(_CRI_RE.match(line) for line in sample_lines[:10] if line.strip())

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        return parse_cri_line(line, line_number, "cri")
