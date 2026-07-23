from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Podman event-stream output ("podman events"). Each line is
# "ts +offset TZ <type> <action> <id> (key=val, ...)":
#   2026-06-28 10:15:01.12 +0000 UTC container create 0a1b2c (image=nginx, name=web)
#   2026-06-28 10:15:02.234567890 +0000 UTC container start 0a1b2c (image=nginx, name=web)
#   2026-06-28 10:15:03.34 +0000 UTC container died 0a1b2c (image=nginx, name=web, exitCode=1)
# The "ns-precision ts +offset TZ <type> <action>" shape is the signature.
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ [+-]\d{4} \w+) "
    r"(?P<type>container|image|pod|volume|network|system|secret) "
    r"(?P<action>\S+) "
    r"(?P<message>.*)$"
)
_TYPES = ("container", "image", "pod", "volume", "network", "system", "secret")
_ERROR_ACTIONS = ("oom", "died", "remove", "kill")
_WARN_ACTIONS = ("stop", "pause", "health_status", "unhealthy", "prune")


class PodmanParser(LogParser):
    FORMAT_NAME = "podman"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return sum(bool(_PATTERN.match(ln)) for ln in sample_lines[:25]) >= max(
            1, len([ln for ln in sample_lines[:25] if ln.strip()]) // 2
        )

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["ts"].replace(" UTC", " +0000"))
        except (ValueError, TypeError, OverflowError):
            ts = None
        action = m["action"]
        extra: dict[str, object] = {"type": m["type"], "action": action}
        severity = Severity.INFO
        low = (action + " " + m["message"]).lower()
        if any(a in low for a in _ERROR_ACTIONS):
            severity = Severity.ERROR
        elif any(a in low for a in _WARN_ACTIONS):
            severity = Severity.WARNING
        name_m = re.search(r"name=([^,)]+)", m["message"])
        if name_m:
            extra["name"] = name_m.group(1)
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="podman",
            message=f"{m['type']} {action} {m['message']}".strip(),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
