from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# WireGuard userspace log (wireguard-go / boringtun). A plain "YYYY/MM/DD
# HH:MM:SS" timestamp followed by a peer(...) / interface message:
#   2026/06/20 10:15:01 peer(HIgo…/abc) - Sending handshake initiation
#   2026/06/20 10:15:02 peer(HIgo…/abc) - Handshake did not complete after 5
#       seconds, retrying (try 2)
#   2026/06/20 10:15:03 Interface state was Down, requested Up, now Up
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)? (?P<message>.*)$"
)
# Markers that identify the wireguard-go logger (vs. any other "YYYY/MM/DD" log).
_WG_MARKERS = ("peer(", "Interface state", "handshake", "Handshake", "keypair",
               "Routine:", "wireguard", "Receiving", "Sending keepalive")
_WARN_MARKERS = ("did not complete", "retrying", "failed", "Failed", "timed out",
                 "invalid", "Invalid", "dropping", "no known endpoint")


class WireGuardParser(LogParser):
    FORMAT_NAME = "wireguard"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        hits = 0
        for ln in sample_lines[:20]:
            if _PATTERN.match(ln) and any(mk in ln for mk in _WG_MARKERS):
                hits += 1
        return hits > 0

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        if not any(mk in line for mk in _WG_MARKERS):
            return None
        try:
            ts = dateparser.parse(m["ts"].replace("/", "-", 2))
        except (ValueError, TypeError, OverflowError):
            ts = None
        message = m["message"].strip()
        severity = Severity.INFO
        if any(mk in message for mk in _WARN_MARKERS):
            severity = Severity.WARNING
        extra: dict[str, object] = {}
        pm = re.search(r"peer\(([^)]+)\)", message)
        if pm:
            extra["peer"] = pm.group(1)
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="wireguard",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
