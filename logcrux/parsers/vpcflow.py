from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# AWS VPC Flow Logs, default (version 2) layout, space-separated:
#   version account-id interface-id srcaddr dstaddr srcport dstport protocol
#   packets bytes start end action log-status
# e.g.
#   2 123456789012 eni-1235b8ca123456789 172.31.16.139 172.31.16.21 20641 22 6 \
#     20 4249 1418530010 1418530070 ACCEPT OK
#   2 123456789012 eni-1235b8ca123456789 - - - - - - - 1431280876 1431280934 - NODATA
_HEADER_RE = re.compile(r"^version\s+account-id\s+interface-id")
_LINE_RE = re.compile(
    r"^(?P<version>2)\s+(?P<account>\d{12})\s+(?P<eni>eni-[0-9a-f]+)\s+"
    r"(?P<rest>.+)$"
)
_ACTIONS = {"ACCEPT", "REJECT"}
_STATUSES = {"OK", "NODATA", "SKIPDATA"}


class VPCFlowParser(LogParser):
    FORMAT_NAME = "vpcflow"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for line in sample_lines[:10]:
            if _HEADER_RE.match(line) or _LINE_RE.match(line):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if _HEADER_RE.match(line):
            return None
        m = _LINE_RE.match(line)
        if not m:
            return None
        fields = m["rest"].split()
        # version(1) account(1) eni(1) already consumed; default layout has 11
        # more fields: src dst sport dport proto packets bytes start end action status
        if len(fields) < 11:
            return None
        (srcaddr, dstaddr, srcport, dstport, proto, packets, _bytes,
         start, _end, action, status) = fields[:11]
        if action not in _ACTIONS and action != "-":
            return None
        if status not in _STATUSES:
            return None
        ts: datetime | None = None
        if start.isdigit():
            try:
                ts = datetime.fromtimestamp(int(start), tz=timezone.utc)
            except (ValueError, OSError, OverflowError):
                ts = None
        # A REJECT is the security-relevant signal flow logs are mined for
        # (blocked/denied traffic); ACCEPT is benign.
        severity = Severity.WARNING if action == "REJECT" else Severity.INFO
        message = (
            f"{action} {proto} {srcaddr}:{srcport} -> {dstaddr}:{dstport} "
            f"({packets} pkts) [{status}]"
        )
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="vpc-flow",
            message=message,
            raw=line,
            line_number=line_number,
            extra={
                "interface_id": m["eni"],
                "action": action,
                "srcaddr": srcaddr,
                "dstaddr": dstaddr,
                "dstport": dstport,
                "protocol": proto,
            },
        )
