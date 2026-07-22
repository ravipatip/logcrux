from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, level_to_severity

# PingAccess (Ping Identity web/API access-management gateway). Two log shapes
# ship by default from <PA_HOME>/log:
#
# 1. pingaccess.log — Log4j2 with the default PingAccess pattern
#    "%d{ISO8601} %5p [%X{exchangeId}] %c:%L - %m%n":
#      2025-09-02T11:02:32,869  INFO [exchange-42] com.pingidentity.pa.core.Foo:88 - Started
#    The "[exchangeId] logger:line - msg" tail plus a com.pingidentity /
#    com.pingaccess logger makes it unambiguous against generic log4j.
#
# 2. pingaccess_engine_audit.log / pingaccess_api_audit.log — the pipe-delimited
#    transaction audit with a trailing HTTP response code:
#      2025-09-02T11:02:32,869| exchange-42| track-9| 12 ms| user@ex.com|
#          OAuth| 10.0.0.5| GET| /api/v1/orders| 200
#    The " NN ms|" round-trip field is the distinctive marker; the final numeric
#    field is the HTTP response code, which drives severity (4xx WARN, 5xx ERROR).
_ISO_TS = r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[,.]\d{3}"

_SERVER_RE = re.compile(
    r"^(?P<ts>" + _ISO_TS + r")\s+"
    r"(?P<level>TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s+"
    r"\[(?P<exchange>[^\]]*)\]\s+"
    r"(?P<logger>[\w.$]+):(?P<lineno>\d+)\s+-\s+(?P<message>.*)$"
)

_AUDIT_RE = re.compile(
    r"^(?P<ts>" + _ISO_TS + r")\s*\|\s*(?P<rest>.*\d+\s*ms\s*\|.*)$"
)


class PingAccessParser(LogParser):
    FORMAT_NAME = "pingaccess"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for ln in sample_lines[:20]:
            m = _SERVER_RE.match(ln)
            if m and (
                "pingidentity" in m["logger"] or "pingaccess" in m["logger"].lower()
            ):
                return True
            if _AUDIT_RE.match(ln):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _SERVER_RE.match(line)
        if m and ("pingidentity" in m["logger"] or "pingaccess" in m["logger"].lower()):
            try:
                ts = dateparser.parse(m["ts"].replace(",", "."))
            except (ValueError, TypeError, OverflowError):
                ts = None
            return ParsedEvent(
                timestamp=ts,
                severity=level_to_severity(m["level"]),
                source="pingaccess",
                message=m["message"].strip(),
                raw=line,
                line_number=line_number,
                extra={
                    "level": m["level"].lower(),
                    "logger": m["logger"],
                    "exchange_id": m["exchange"],
                },
            )

        m = _AUDIT_RE.match(line)
        if m:
            try:
                ts = dateparser.parse(m["ts"].replace(",", "."))
            except (ValueError, TypeError, OverflowError):
                ts = None
            fields = [f.strip() for f in m["rest"].split("|")]
            severity = Severity.INFO
            resp = fields[-1].strip() if fields else ""
            if resp.isdigit():
                code = int(resp)
                if 500 <= code < 600:
                    severity = Severity.ERROR
                elif 400 <= code < 500:
                    severity = Severity.WARNING
            return ParsedEvent(
                timestamp=ts,
                severity=severity,
                source="pingaccess-audit",
                message=m["rest"].strip(),
                raw=line,
                line_number=line_number,
                extra={"fields": fields, "response_code": resp},
            )
        return None
