from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# PingDirectory and the rest of the Ping Data platform — PingDirectoryProxy,
# PingDataSync, PingDataMetrics, and PingAuthorize (formerly PingDataGovernance)
# server logs — share one log shape, inherited from the UnboundID Directory
# Server. Several publishers ship by default:
#
# 1. error log — a bracketed timestamp then category / severity / msgID / msg:
#      [11/Apr/2011:10:31:53.783 -0500] category=CORE severity=NOTICE msgID=458887
#          msg="The Directory Server has started successfully"
#
# 2. PingDataSync sync log — the same record shape, category=SYNC, with sync
#    fields (op / changeNumber / pipe) *between* msgID and msg:
#      [17/Nov/2021:15:57:39.562 -0600] category=SYNC severity=INFORMATION
#          msgID=1893728293 op=7 changeNumber=59 pipe="ds1_to_PingOne" msg="Detected..."
#
# 3. access log — the bracketed timestamp then an LDAP operation and conn=/op=
#    key/value fields; RESULT lines carry an LDAP resultCode:
#      [01/Jun/2011:11:10:19.692 -0500] CONNECT conn=49 from="127.0.0.1" ...
#      [01/Jun/2011:11:10:19.700 -0500] BIND RESULT conn=49 op=0 resultCode=49 ...
#
# The bracketed "[dd/Mon/yyyy:HH:mm:ss.SSS -ZZZZ]" opening every line (with
# category=/severity= or an LDAP operation keyword after it) makes detection
# content-precise; unlike an Apache access line, a Ping Data line *starts* with
# the bracketed timestamp rather than a client IP.
_TS = r"\[(?P<ts>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\.\d{3} [-+]\d{4})\]"

# category / severity / msgID are the fixed leading fields; everything after is
# captured as ``rest`` so sync/extra key=value fields (op, changeNumber, pipe,
# class) between msgID and the trailing msg="..." don't break the match.
_ERROR_RE = re.compile(
    _TS + r"\s+category=(?P<category>\S+)\s+severity=(?P<severity>\S+)\s+"
    r"msgID=(?P<msgid>\S+)\s+(?P<rest>.*)$"
)
_MSG_RE = re.compile(r'\bmsg="(?P<msg>.*)"\s*$|\bmsg=(?P<msg2>.*)$')
_PIPE_RE = re.compile(r'\bpipe="?(?P<pipe>[^"\s]+)"?')

# Access line: timestamp then an LDAP operation keyword (CONNECT, DISCONNECT,
# BIND REQUEST/RESULT, SEARCH REQUEST/RESULT, ADD, MODIFY, DELETE, ...).
_OPERATION = (
    r"CONNECT|DISCONNECT|ABANDON|"
    r"(?:BIND|UNBIND|SEARCH|ADD|MODIFY|MODIFY DN|MODIFYDN|DELETE|COMPARE|"
    r"EXTENDED)(?: REQUEST| RESULT| FORWARD| ENTRY| REFERENCE)?"
)
_ACCESS_RE = re.compile(_TS + r"\s+(?P<op>" + _OPERATION + r")\b(?P<rest>.*)$")
_RESULT_CODE_RE = re.compile(r"\bresultCode=(\d+)")

# PingDirectory error-log severities (from the SEVERE/MILD scale) -> Severity.
_SEVERITY_MAP: dict[str, Severity] = {
    "debug": Severity.DEBUG,
    "information": Severity.INFO,
    "informational": Severity.INFO,
    "info": Severity.INFO,
    "notice": Severity.INFO,
    "mild_warning": Severity.WARNING,
    "severe_warning": Severity.WARNING,
    "warning": Severity.WARNING,
    "mild_error": Severity.ERROR,
    "severe_error": Severity.ERROR,
    "error": Severity.ERROR,
    "fatal_error": Severity.CRITICAL,
    "fatal": Severity.CRITICAL,
}


def _parse_ts(raw: str) -> datetime | None:
    # "01/Jun/2011:11:10:19.692 -0500" -> replace the first ':' (date/time
    # separator) with a space so dateutil reads it.
    try:
        return dateparser.parse(raw.replace(":", " ", 1))
    except (ValueError, TypeError, OverflowError):
        return None


class PingDirectoryParser(LogParser):
    FORMAT_NAME = "pingdirectory"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for ln in sample_lines[:20]:
            if _ERROR_RE.match(ln) or _ACCESS_RE.match(ln):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _ERROR_RE.match(line)
        if m:
            severity = _SEVERITY_MAP.get(m["severity"].lower(), Severity.INFO)
            rest = m["rest"]
            msg_m = _MSG_RE.search(rest)
            message = (
                (msg_m["msg"] if msg_m["msg"] is not None else msg_m["msg2"]).strip()
                if msg_m
                else rest.strip()
            )
            err_extra: dict[str, object] = {
                "category": m["category"],
                "severity": m["severity"].lower(),
                "msgID": m["msgid"],
            }
            pipe_m = _PIPE_RE.search(rest)
            if pipe_m:
                err_extra["pipe"] = pipe_m["pipe"]
            # category=SYNC is unique to the PingDataSync synchronization log.
            source = "pingdatasync" if m["category"].upper() == "SYNC" else "pingdirectory"
            return ParsedEvent(
                timestamp=_parse_ts(m["ts"]),
                severity=severity,
                source=source,
                message=message,
                raw=line,
                line_number=line_number,
                extra=err_extra,
            )

        m = _ACCESS_RE.match(line)
        if m:
            rest = m["rest"]
            severity = Severity.INFO
            extra: dict[str, object] = {"operation": m["op"]}
            rc = _RESULT_CODE_RE.search(rest)
            if rc is not None:
                extra["resultCode"] = rc.group(1)
                # LDAP resultCode 0 == success; any non-zero RESULT is a failed
                # operation (e.g. 49 = invalid credentials on a BIND), which is a
                # security-relevant WARNING for burst/auth analysis.
                if rc.group(1) != "0":
                    severity = Severity.WARNING
            return ParsedEvent(
                timestamp=_parse_ts(m["ts"]),
                severity=severity,
                source="pingdirectory",
                message=f"{m['op']}{rest}".strip(),
                raw=line,
                line_number=line_number,
                extra=extra,
            )
        return None
