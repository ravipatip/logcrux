from __future__ import annotations

from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Microsoft IIS W3C extended log — SPACE-separated, with a "#Fields:" header:
#   #Software: Microsoft Internet Information Services 10.0
#   #Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username
#            c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status time-taken
#   2026-06-20 10:15:01 10.0.0.1 GET /index.html - 80 - 1.2.3.4 Mozilla 200 0 0 15
# Distinguished from CloudFront (also W3C) by space separation + s-ip/time-taken
# columns and the absence of CloudFront's x-edge-location field.


class IISParser(LogParser):
    FORMAT_NAME = "iis"

    def __init__(self) -> None:
        self._fields: list[str] = []

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for ln in sample_lines[:10]:
            if (
                ln.startswith("#Fields:")
                and "x-edge-location" not in ln
                and ("s-ip" in ln or "time-taken" in ln or "sc-status" in ln)
                and "\t" not in ln.strip()
            ):
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
        parts = line.split()
        if not self._fields or len(parts) < 2:
            return None
        row = dict(zip(self._fields, parts, strict=False))
        ts = None
        if "date" in row and "time" in row:
            try:
                ts = dateparser.parse(f'{row["date"]} {row["time"]}')
            except (ValueError, TypeError, OverflowError):
                ts = None
        try:
            status = int(row.get("sc-status", ""))
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
        if row.get("c-ip"):
            extra["client"] = row["c-ip"]
        if row.get("time-taken"):
            extra["time_taken_ms"] = row["time-taken"]
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="iis",
            message=f"{method} {uri} -> {status}".strip(),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
