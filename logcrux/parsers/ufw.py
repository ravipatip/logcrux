from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

_CURRENT_YEAR = __import__("datetime").datetime.now().year

# UFW entries embed kernel syslog header then key=value pairs
_HEADER = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) kernel: "
    r"(?:\[\s*[\d.]+\] )?"
    r"\[UFW (?P<action>BLOCK|ALLOW|LIMIT|AUDIT)\] "
    r"(?P<kvpairs>.*)"
)

_KV_RE = re.compile(r"(\w+)=(\S*)")


class UFWParser(LogParser):
    FORMAT_NAME = "ufw"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "ufw" in path.name.lower():
            return True
        return any("[UFW " in line for line in sample_lines[:10])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _HEADER.match(line)
        if not m:
            return None
        action = m["action"]
        kv: dict[str, str] = dict(_KV_RE.findall(m["kvpairs"]))
        src = kv.get("SRC", "?")
        dst = kv.get("DST", "?")
        proto = kv.get("PROTO", "?")
        dpt = kv.get("DPT", "?")
        try:
            ts = dateparser.parse(
                f"{m['month']} {m['day']} {_CURRENT_YEAR} {m['time']}"
            )
        except Exception:
            ts = None
        severity = Severity.WARNING if action == "BLOCK" else Severity.INFO
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="ufw",
            message=f"UFW {action} {proto} {src} → {dst}:{dpt}",
            raw=line,
            line_number=line_number,
            extra={
                "action": action,
                "src_ip": src,
                "dst_ip": dst,
                "proto": proto,
                "src_port": kv.get("SPT"),
                "dst_port": dpt,
                "in_iface": kv.get("IN"),
                "out_iface": kv.get("OUT"),
            },
        )
