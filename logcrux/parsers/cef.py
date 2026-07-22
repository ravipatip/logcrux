from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# ArcSight Common Event Format (CEF) — the de-facto SIEM interchange format,
# emitted by firewalls, IDS/IPS and endpoint products. One event per line:
#   CEF:0|Vendor|Product|1.0|100|Worm stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232
# A syslog header ("Jun 20 10:15:01 host ") may precede the "CEF:" marker, so we
# locate the marker rather than anchoring at the start of the line.
#   header := CEF:Ver|Vendor|Product|DevVersion|SignatureID|Name|Severity|
#   extension := space-separated key=value pairs (the part after the 7th "|")

# Optional syslog header before CEF: — two common shapes:
#   "Jun 20 10:15:01 host " (no year, RFC3164)
#   "Jun 20 2026 10:15:01 host " (with year)
_SYSLOG_HDR_RE = re.compile(
    r"^(?P<ts>(?:\w{3}\s+\d{1,2}\s+(?:\d{4}\s+)?\d{2}:\d{2}:\d{2}))\s+\S+\s+"
)
_CURRENT_YEAR = datetime.now().year
_CEF_RE = re.compile(
    r"CEF:\d+\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<version>[^|]*)\|"
    r"(?P<sig>[^|]*)\|(?P<name>[^|]*)\|(?P<severity>[^|]*)\|(?P<ext>.*)$"
)

# CEF severity is 0-10 (or the words Unknown/Low/Medium/High/Very-High).
_WORD_SEVERITY = {
    "unknown": Severity.INFO,
    "low": Severity.INFO,
    "medium": Severity.WARNING,
    "high": Severity.ERROR,
    "very-high": Severity.CRITICAL,
}


def _cef_severity(raw: str) -> Severity:
    raw = raw.strip().lower()
    if raw in _WORD_SEVERITY:
        return _WORD_SEVERITY[raw]
    try:
        num = int(raw)
    except ValueError:
        return Severity.INFO
    if num >= 9:
        return Severity.CRITICAL
    if num >= 7:
        return Severity.ERROR
    if num >= 4:
        return Severity.WARNING
    return Severity.INFO


class CEFParser(LogParser):
    FORMAT_NAME = "cef"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for ln in sample_lines[:20]:
            if _CEF_RE.search(ln):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _CEF_RE.search(line)
        if not m:
            return None
        extra: dict[str, object] = {
            "vendor": m["vendor"],
            "product": m["product"],
            "signature_id": m["sig"],
            "cef_severity": m["severity"].strip(),
        }
        # Pull a couple of high-value extension fields if present.
        for key in ("src", "dst", "suser", "act"):
            em = re.search(rf"(?:^|\s){key}=(\S+)", m["ext"])
            if em:
                extra[key] = em.group(1)
        # Timestamp resolution order:
        # 1. Extension field rt= (receipt time, epoch milliseconds)
        # 2. Syslog header before CEF: (RFC3164 date, optionally with year)
        ts = None
        rt_m = re.search(r"(?:^|\s)rt=(\d+)", m["ext"])
        if rt_m:
            try:
                ts = datetime.fromtimestamp(int(rt_m.group(1)) / 1000.0, tz=timezone.utc)
            except (ValueError, OSError, OverflowError):
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
        message = m["name"].strip() or m["ext"].strip()
        return ParsedEvent(
            timestamp=ts,
            severity=_cef_severity(m["severity"]),
            source=m["vendor"].strip() or "cef",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
