from __future__ import annotations

from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# AWS CloudFront access logs — W3C extended format, TAB-separated, with two
# leading comment lines declaring the columns:
#   #Version: 1.0
#   #Fields: date time x-edge-location sc-bytes c-ip cs-method cs(Host) cs-uri-stem sc-status ...
#   2026-06-20\t10:15:01\tIAD79-C1\t1234\t1.2.3.4\tGET\td.cloudfront.net\t/index.html\t200 ...
# The "#Fields:" header naming x-edge-location distinguishes CloudFront from IIS.


class CloudFrontParser(LogParser):
    FORMAT_NAME = "cloudfront"

    def __init__(self) -> None:
        self._fields: list[str] = []

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for ln in sample_lines[:10]:
            if ln.startswith("#Fields:") and "x-edge-location" in ln:
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if line.startswith("#Fields:"):
            self._fields = line[len("#Fields:"):].split()
            self.meta_lines += 1
            return None
        if line.startswith("#"):
            self.meta_lines += 1
            return None
        if not line.strip():
            return None
        parts = line.split("\t")
        if not self._fields or len(parts) < 2:
            return None
        row = dict(zip(self._fields, parts, strict=False))
        ts = None
        if "date" in row and "time" in row:
            try:
                ts = dateparser.parse(f'{row["date"]} {row["time"]}')
            except (ValueError, TypeError, OverflowError):
                ts = None
        status_raw = row.get("sc-status", "")
        try:
            status = int(status_raw)
        except ValueError:
            status = 0
        if status >= 500:
            severity = Severity.ERROR
        elif status >= 400:
            severity = Severity.WARNING
        else:
            severity = Severity.INFO
        method = row.get("cs-method", "")
        uri = row.get("cs-uri-stem", "")
        extra: dict[str, object] = {"status": status}
        for k_src, k_dst in (("c-ip", "client"), ("x-edge-location", "edge"),
                             ("x-edge-result-type", "result")):
            if row.get(k_src):
                extra[k_dst] = row[k_src]
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="cloudfront",
            message=f"{method} {uri} -> {status}".strip(),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
