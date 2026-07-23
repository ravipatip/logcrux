from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Palo Alto Networks PAN-OS firewall logs — comma-separated values, optionally
# behind a syslog header. The field layout varies by log type and PAN-OS
# version, so we key off stable anchors rather than fixed positions:
#   <hdr> 1,2026/06/20 10:15:01,001801011111,TRAFFIC,end,...,allow,...
#   <hdr> 1,2026/06/20 10:15:02,0019...,THREAT,vulnerability,...,high,...
# A receive-time field (YYYY/MM/DD HH:MM:SS) plus a known log-type token make
# the format unmistakable.
_TYPES = frozenset(
    {
        "TRAFFIC",
        "THREAT",
        "SYSTEM",
        "CONFIG",
        "HIPMATCH",
        "HIP-MATCH",
        "GLOBALPROTECT",
        "USERID",
        "CORRELATION",
        "AUTHENTICATION",
        "DECRYPTION",
    }
)
_RECV_TIME_RE = re.compile(r"\b(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\b")
_IPV4_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_SEV_WORDS = {
    "critical": Severity.CRITICAL,
    "high": Severity.ERROR,
    "medium": Severity.WARNING,
    "low": Severity.INFO,
    "informational": Severity.INFO,
    "information": Severity.INFO,
}
_DENY_ACTIONS = frozenset({"deny", "drop", "reset-both", "reset-client", "reset-server", "block"})


def _classify(fields: list[str]) -> tuple[str, list[str]] | None:
    for idx, tok in enumerate(fields[:6]):
        if tok in _TYPES:
            return tok, fields[idx:]
    return None


class PaloAltoParser(LogParser):
    FORMAT_NAME = "paloalto"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for ln in sample_lines[:20]:
            if "," not in ln or not _RECV_TIME_RE.search(ln):
                continue
            if _classify(ln.split(",")) is not None:
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        fields = line.split(",")
        classified = _classify(fields)
        if classified is None:
            return None
        log_type, rest = classified
        ts = None
        tm = _RECV_TIME_RE.search(line)
        if tm:
            try:
                ts = dateparser.parse(tm.group(1).replace("/", "-", 2))
            except (ValueError, TypeError, OverflowError):
                ts = None
        lowered = {f.strip().lower() for f in fields}
        severity = Severity.INFO
        for word, sev in _SEV_WORDS.items():
            if word in lowered:
                severity = sev
                break
        else:
            if lowered & _DENY_ACTIONS:
                severity = Severity.WARNING
        subtype = rest[1] if len(rest) > 1 else ""
        ips = _IPV4_RE.findall(line)
        extra: dict[str, object] = {"log_type": log_type, "subtype": subtype}
        if len(ips) >= 2:
            extra["src"], extra["dst"] = ips[0], ips[1]
        message = f"{log_type} {subtype}".strip()
        if len(ips) >= 2:
            message += f" {ips[0]} -> {ips[1]}"
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="paloalto",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
