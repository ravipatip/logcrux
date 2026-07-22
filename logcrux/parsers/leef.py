from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# IBM QRadar Log Event Extended Format (LEEF). Like CEF but the attributes are
# delimited (tab by default; LEEF:2.0 may declare a single-char delimiter after
# the EventID). One event per line, optionally behind a syslog header:
#   LEEF:1.0|Vendor|Product|Version|EventID|src=10.0.0.1\tdst=2.1.2.2\tsev=5
#   LEEF:2.0|Lancope|StealthWatch|2.0|41|^|src=10.0.0.1^dst=10.0.0.2^sev=8

_SYSLOG_HDR_RE = re.compile(
    r"^(?P<ts>(?:\w{3}\s+\d{1,2}\s+(?:\d{4}\s+)?\d{2}:\d{2}:\d{2}))\s+\S+\s+"
)
_CURRENT_YEAR = datetime.now().year
_LEEF_RE = re.compile(
    r"LEEF:(?P<ver>\d+\.\d+)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|"
    r"(?P<version>[^|]*)\|(?P<eventid>[^|]*)\|(?P<rest>.*)$"
)


def _leef_severity(attrs: dict[str, str]) -> Severity:
    raw = attrs.get("sev") or attrs.get("severity")
    if raw is None:
        return Severity.INFO
    try:
        num = int(raw)
    except ValueError:
        return Severity.INFO
    # QRadar sev scale is 1-10.
    if num >= 9:
        return Severity.CRITICAL
    if num >= 7:
        return Severity.ERROR
    if num >= 4:
        return Severity.WARNING
    return Severity.INFO


class LEEFParser(LogParser):
    FORMAT_NAME = "leef"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for ln in sample_lines[:20]:
            if _LEEF_RE.search(ln):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _LEEF_RE.search(line)
        if not m:
            return None
        rest = m["rest"]
        # LEEF 2.0 may prefix the attributes with a one-char delimiter spec.
        delim = "\t"
        if m["ver"] == "2.0" and rest[:1] and not rest[:1].isalnum() and rest[1:2] != "=":
            delim, rest = rest[0], rest[1:]
        # Fall back to the delimiter actually present (tab, ^, |, or space).
        if delim not in rest:
            for cand in ("\t", "^", "|"):
                if cand in rest:
                    delim = cand
                    break
            else:
                delim = " "
        attrs: dict[str, str] = {}
        for tok in rest.split(delim):
            if "=" in tok:
                k, _, v = tok.partition("=")
                attrs[k.strip()] = v.strip()
        extra: dict[str, object] = {
            "vendor": m["vendor"],
            "product": m["product"],
            "event_id": m["eventid"],
        }
        for key in ("src", "dst", "usrName", "sev"):
            if key in attrs:
                extra[key] = attrs[key]
        # Timestamp resolution order:
        # 1. devTime attribute (ISO or epoch ms string from the device)
        # 2. Syslog header before LEEF: (RFC3164 date, optionally with year)
        ts = None
        dev_time = attrs.get("devTime")
        if dev_time:
            try:
                ts = dateparser.parse(dev_time)
            except (ValueError, TypeError, OverflowError):
                ts = None
        if ts is None:
            hdr = _SYSLOG_HDR_RE.match(line)
            if hdr:
                raw_ts = hdr["ts"]
                if not re.search(r"\d{4}", raw_ts):
                    raw_ts = f"{raw_ts} {_CURRENT_YEAR}"
                try:
                    ts = dateparser.parse(raw_ts)
                except (ValueError, TypeError, OverflowError):
                    ts = None
        message = attrs.get("msg") or attrs.get("cat") or m["eventid"]
        return ParsedEvent(
            timestamp=ts,
            severity=_leef_severity(attrs),
            source=m["vendor"].strip() or "leef",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
