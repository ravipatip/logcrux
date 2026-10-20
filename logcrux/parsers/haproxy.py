from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Syslog header shared by HAProxy lines
_SYSLOG_HDR = (
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) haproxy\[(?P<pid>\d+)\]: "
)
_CURRENT_YEAR = __import__("datetime").datetime.now().year

# HTTP mode: includes status code + request
# The syslog header is optional: the official container image's documented
# config is `log stdout format raw`, which writes the bare access line
# (real haproxy 3.0 container, 2026-10-20).
_HTTP_PATTERN = re.compile(
    "(?:" + _SYSLOG_HDR + ")?"
    + r"(?P<client_ip>[\d.]+):(?P<client_port>\d+) "
    r"\[(?P<req_date>[^\]]+)\] "
    r"(?P<frontend>\S+) (?P<backend>\S+)/(?P<server>\S+) "
    r"(?P<Tq>-?\d+)/(?P<Tw>-?\d+)/(?P<Tc>-?\d+)/(?P<Tr>-?\d+)/(?P<Tt>\d+) "
    r"(?P<status>\d{3}) (?P<bytes>\d+) "
    r".+? "
    r"(?P<termination>\S{4}) "
    r"(?P<actconn>\d+)/(?P<feconn>\d+)/(?P<beconn>\d+)/(?P<srvconn>\d+)/(?P<retries>\d+) "
    r"(?P<srv_queue>\d+)/(?P<backend_queue>\d+)"
    r'(?: "(?P<request>[^"]*)")?'
)

# TCP mode: no status code
_TCP_PATTERN = re.compile(
    "(?:" + _SYSLOG_HDR + ")?"
    + r"(?P<client_ip>[\d.]+):(?P<client_port>\d+) "
    r"\[(?P<req_date>[^\]]+)\] "
    r"(?P<frontend>\S+) (?P<backend>\S+)/(?P<server>\S+) "
    r"(?P<Tw>-?\d+)/(?P<Tc>-?\d+)/(?P<Tt>\d+) "
    r"(?P<bytes>\d+) "
    r"(?P<termination>\S{2})"
)

# Admin / state-change lines share the syslog header but not the access-log
# layout ("Server web/web1 is DOWN, reason: ...", "backend web has no server
# available!", "Proxy http-in started."). These are the root-cause lines of an
# outage, so dropping them as unparsed would hide exactly the events that matter.
_ADMIN_PATTERN = re.compile(_SYSLOG_HDR + r"(?P<message>.+)")

# The master/worker's own stderr in a container, and the same state changes
# written raw to stdout:
#   [WARNING]  (8) : Server be/app1 is DOWN, reason: Layer4 connection problem, ...
#   [ALERT]    (8) : backend 'be' has no server available!
#   Server be/app1 is DOWN, reason: Layer4 connection problem, ...
_STDERR_PATTERN = re.compile(
    r"^\[(?P<level>NOTICE|WARNING|ALERT|EMERG)\]\s+\(\d+\) : (?P<message>.+)"
)
_RAW_ADMIN_PATTERN = re.compile(
    r"^(?P<message>(?:Server|Backup Server) \S+/\S+ is (?:UP|DOWN|going DOWN)\b.*"
    r"|backend \S+ has no server available!.*|Proxy \S+ (?:started|stopped)\b.*)"
)
# The HTTP log's "<client>:<port> [dd/Mon/yyyy:HH:MM:SS.mmm] <fe> <be>/<srv> Tq/Tw/..."
# shape is haproxy's own; nothing else writes backend/server plus five timers.
_RAW_HTTP_DETECT = re.compile(
    r"^\S+:\d+ \[\d\d/\w{3}/\d{4}:\d\d:\d\d:\d\d\.\d{3}\] \S+ \S+/\S+ -?\d+/-?\d+/"
)

# Simple detect: haproxy process field
_DETECT = re.compile(r"\bhaproxy\[\d+\]:")


def _admin_severity(message: str) -> Severity:
    low = message.lower()
    if " is down" in low or "no server available" in low or "emerg" in low:
        return Severity.ERROR
    warn_keywords = (
        "error", "failed", "cannot ", "timeout", "limit reached", "stopping", "paused",
    )
    if any(kw in low for kw in warn_keywords):
        return Severity.WARNING
    return Severity.INFO


def _http_severity(status: int, termination: str) -> Severity:
    if status >= 500:
        return Severity.ERROR
    if status >= 400:
        return Severity.WARNING
    if termination and termination[0] not in ("-", "C"):
        return Severity.WARNING
    return Severity.INFO


class HAProxyParser(LogParser):
    FORMAT_NAME = "haproxy"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "haproxy" in str(path).lower():
            return True
        return any(_DETECT.search(line) or _STDERR_PATTERN.match(line)
                   or _RAW_HTTP_DETECT.match(line) for line in sample_lines[:10])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _HTTP_PATTERN.match(line)
        if m:
            return self._parse_http(m, line, line_number)
        m = _TCP_PATTERN.match(line)
        if m:
            return self._parse_tcp(m, line, line_number)
        m = _STDERR_PATTERN.match(line)
        if m:
            message = m["message"].strip()
            sev = {"NOTICE": Severity.INFO, "WARNING": Severity.WARNING,
                   "ALERT": Severity.ERROR, "EMERG": Severity.CRITICAL}[m["level"]]
            if sev is not Severity.CRITICAL and _admin_severity(message) is Severity.ERROR:
                sev = Severity.ERROR
            return ParsedEvent(timestamp=None, severity=sev, source="haproxy", message=message,
                               raw=line, line_number=line_number, extra={"kind": "admin"})
        m = _ADMIN_PATTERN.match(line) or _RAW_ADMIN_PATTERN.match(line)
        if m:
            message = m["message"].strip()
            return ParsedEvent(
                timestamp=self._ts(m),
                severity=_admin_severity(message),
                source="haproxy",
                message=message,
                raw=line,
                line_number=line_number,
                extra={"kind": "admin"},
            )
        return None

    def _ts(self, m: re.Match[str]) -> datetime | None:
        groups = m.groupdict()
        if groups.get("month") is None:
            req = groups.get("req_date")
            if not req:
                return None
            try:
                return datetime.strptime(req[:20], "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                return None
        try:
            return dateparser.parse(
                f"{m['month']} {m['day']} {_CURRENT_YEAR} {m['time']}"
            )
        except Exception:
            return None

    def _parse_http(self, m: re.Match[str], line: str, line_number: int) -> ParsedEvent:
        status = int(m["status"])
        termination = m["termination"]
        request = m["request"] or ""
        return ParsedEvent(
            timestamp=self._ts(m),
            severity=_http_severity(status, termination),
            source="haproxy",
            message=f"{request} {status}" if request else f"HTTP {status}",
            raw=line,
            line_number=line_number,
            extra={
                "client_ip": m["client_ip"],
                "frontend": m["frontend"],
                "backend": m["backend"],
                "server": m["server"],
                "status_code": status,
                "bytes": int(m["bytes"]),
                "response_time_ms": int(m["Tt"]),
                "termination_state": termination,
                "request": request,
                **({"path": request.split()[1]} if len(request.split()) > 1 else {}),
            },
        )

    def _parse_tcp(self, m: re.Match[str], line: str, line_number: int) -> ParsedEvent:
        termination = m["termination"]
        severity = Severity.WARNING if termination[0] not in ("-", "C") else Severity.INFO
        return ParsedEvent(
            timestamp=self._ts(m),
            severity=severity,
            source="haproxy",
            message=f"TCP {m['frontend']} → {m['backend']}/{m['server']} [{termination}]",
            raw=line,
            line_number=line_number,
            extra={
                "client_ip": m["client_ip"],
                "frontend": m["frontend"],
                "backend": m["backend"],
                "server": m["server"],
                "bytes": int(m["bytes"]),
                "response_time_ms": int(m["Tt"]),
                "termination_state": termination,
            },
        )
