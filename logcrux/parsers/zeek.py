from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Zeek (formerly Bro) network-security logs — tab-separated values with a
# self-describing "#fields" header. The canonical conn.log / dns.log / http.log
# / notice.log shape:
#   #separator \x09
#   #fields ts  uid id.orig_h  id.orig_p  id.resp_h  id.resp_p  proto ...
#   1592654701.123  CwjjYU  10.0.0.1  1234  10.0.0.2  80  tcp  http  ...
# The "#fields" header makes the column layout explicit, so the parser stays
# robust across Zeek log types. conn_state values signal failed/aborted flows.
_DEFAULT_CONN_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state",
]
# conn_state values that indicate a rejected/reset/half-open connection.
_BAD_CONN_STATES = frozenset({"S0", "REJ", "RSTO", "RSTR", "RSTOS0", "RSTRH", "SH", "SHR"})


class ZeekParser(LogParser):
    FORMAT_NAME = "zeek"

    def __init__(self) -> None:
        self._fields: list[str] = list(_DEFAULT_CONN_FIELDS)
        self._path: str = "conn"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for ln in sample_lines[:15]:
            if ln.startswith("#fields") and "\t" in ln:
                return True
            if ln.startswith("#separator") or ln.startswith("#path"):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if line.startswith("#"):
            if line.startswith("#fields"):
                self._fields = line.split("\t")[1:]
            elif line.startswith("#path"):
                parts = line.split("\t")
                if len(parts) > 1:
                    self._path = parts[1].strip()
            self.meta_lines += 1
            return None
        if not line.strip():
            return None
        values = line.split("\t")
        record = dict(zip(self._fields, values))
        ts = None
        ts_raw = record.get("ts")
        if ts_raw:
            try:
                ts = datetime.fromtimestamp(float(ts_raw), tz=timezone.utc)
            except (ValueError, OverflowError, OSError):
                ts = None
        conn_state = record.get("conn_state", "")
        severity = Severity.INFO
        if conn_state in _BAD_CONN_STATES:
            severity = Severity.WARNING
        # notice.log / weird.log entries are security-relevant by nature.
        if self._path in {"notice", "weird"}:
            severity = Severity.WARNING
        orig = record.get("id.orig_h", "?")
        resp = record.get("id.resp_h", "?")
        rport = record.get("id.resp_p", "?")
        proto = record.get("proto", record.get("service", ""))
        msg_field = record.get("msg") or record.get("note") or record.get("name")
        if msg_field:
            message = str(msg_field)
        else:
            message = f"{proto} {orig} -> {resp}:{rport}".strip()
            if conn_state:
                message += f" [{conn_state}]"
        extra: dict[str, object] = {"zeek_log": self._path, "uid": record.get("uid")}
        if conn_state:
            extra["conn_state"] = conn_state
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source=f"zeek-{self._path}",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
