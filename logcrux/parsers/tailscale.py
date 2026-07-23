from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Tailscale daemon (tailscaled). Uses Go's standard logger: a "YYYY/MM/DD
# HH:MM:SS" timestamp followed by a subsystem-tagged message:
#   2026/06/28 10:15:01 magicsock: home is now derp-10 (sfo)
#   2026/06/28 10:15:02 wgengine: Reconfig: configuring userspace WireGuard
#   2026/06/28 10:15:03 control: NetInfo: ...
#   2026/06/28 10:15:04 netcheck: report: udp=true v4=true ...
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?) (?P<message>.*)$"
)
# Subsystems/markers unique to tailscaled (distinguishes it from any other
# Go-logger "YYYY/MM/DD" log such as rsync or wireguard-go).
_TS_MARKERS = ("magicsock", "wgengine", "tailscaled", "control:", "netcheck",
               "tsnet", "portmapper", "derp", "ipnlocal", "health(",
               "LinkChange", "Accept: ", "tailscale", "peerapi", "tka:")
_WARN_MARKERS = ("error", "failed", "timeout", "timed out", "could not",
                 "unreachable", "no DERP", "lost", "retrying", "warning",
                 "rejected", "unhealthy")


class TailscaleParser(LogParser):
    FORMAT_NAME = "tailscale"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        hits = 0
        for ln in sample_lines[:20]:
            if _PATTERN.match(ln) and any(mk in ln for mk in _TS_MARKERS):
                hits += 1
        return hits > 0

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        if not any(mk in line for mk in _TS_MARKERS):
            return None
        try:
            ts = dateparser.parse(m["ts"].replace("/", "-", 2))
        except (ValueError, TypeError, OverflowError):
            ts = None
        message = m["message"].strip()
        severity = Severity.INFO
        low = message.lower()
        if any(mk in low for mk in _WARN_MARKERS):
            severity = Severity.WARNING
        extra: dict[str, object] = {}
        sub = re.match(r"([a-z][\w]*?):", message)
        if sub:
            extra["subsystem"] = sub.group(1)
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="tailscaled",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
