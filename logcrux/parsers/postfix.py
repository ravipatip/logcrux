from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

_CURRENT_YEAR = __import__("datetime").datetime.now().year

# Syslog-style header used by Postfix
_SYSLOG_HDR = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"(?P<process>postfix(?:/\w+|-script))(?:\[(?P<pid>\d+)\])?: "
    r"(?P<message>.*)"
)

# Delivery status line: QUEUEID: to=<addr>, relay=..., status=xxx
_DELIVERY = re.compile(
    r"(?P<queue_id>[A-Za-z0-9]+): to=<(?P<to>[^>]*)>, "
    r"relay=(?P<relay>\S+), "
    r".*?status=(?P<status>\w+)"
)

# Sender line: QUEUEID: from=<addr>, size=N, nrcpt=N
_SENDER = re.compile(
    r"(?P<queue_id>[A-Za-z0-9]+): from=<(?P<from>[^>]*)>, size=(?P<size>\d+)"
)

# SASL / auth failure
_AUTH_FAIL = re.compile(r"SASL \w+ authentication failed|warning:.*authentication")

# Bounce / reject
_REJECT = re.compile(r"reject:|NOQUEUE: reject|bounce")


def _postfix_severity(process: str, message: str) -> Severity:
    low = message.lower()
    if "error" in low or "fatal" in low or "panic" in low:
        return Severity.ERROR
    if _AUTH_FAIL.search(message):
        return Severity.WARNING
    if _REJECT.search(low):
        return Severity.WARNING
    dm = _DELIVERY.search(message)
    if dm and dm["status"] not in ("sent", "queued"):
        return Severity.WARNING
    if "warning" in low or "warn" in process:
        return Severity.WARNING
    return Severity.INFO


class PostfixParser(LogParser):
    FORMAT_NAME = "postfix"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path:
            name = path.name.lower()
            if name in ("mail.log", "maillog", "mail.err", "mail.warn"):
                return True
            if "postfix" in str(path).lower():
                return True
        return any(
            "postfix/" in line or "postfix-script" in line
            for line in sample_lines[:10]
        )

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _SYSLOG_HDR.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(
                f"{m['month']} {m['day']} {_CURRENT_YEAR} {m['time']}"
            )
        except Exception:
            ts = None
        process = m["process"]
        message = m["message"].strip()
        extra: dict[str, object] = {"process": process, "pid": m["pid"]}
        dm = _DELIVERY.search(message)
        if dm:
            extra["queue_id"] = dm["queue_id"]
            extra["to"] = dm["to"]
            extra["relay"] = dm["relay"]
            extra["delivery_status"] = dm["status"]
        sm = _SENDER.search(message)
        if sm:
            extra["queue_id"] = sm["queue_id"]
            extra["from"] = sm["from"]
            extra["size"] = int(sm["size"])
        return ParsedEvent(
            timestamp=ts,
            severity=_postfix_severity(process, message),
            source="postfix",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
