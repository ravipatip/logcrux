from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# rspamd spam-filtering daemon log. Layout is
# "ts #pid(worker) <tag>; module; function: message":
#   2026-06-28 10:15:01 #1234(normal) <a1b2c3>; task; rspamd_task_write_log: id: msg
#   2026-06-28 10:15:02 #1234(controller) <d4e5f6>; csession; ...: reject
#   2026-06-28 10:15:03 #1234(rspamd_proxy) <0a0b0c>; proxy; ...: cannot connect
# The "#pid(worker) <hex-tag>; module;" shape is the distinctive signature.
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) "
    r"#(?P<pid>\d+)\((?P<worker>[\w-]+)\) "
    r"(?:<(?P<tag>\w+)>; )?"
    r"(?P<module>\w+); "
    r"(?P<message>.*)$"
)
_ERROR_KW = ("error", "cannot", "failed", "reject", "timeout", "refused",
             "no such", "abort", "fatal")
_WARN_KW = ("greylist", "soft reject", "warn", "retry", "skip", "slow")


class RspamdParser(LogParser):
    FORMAT_NAME = "rspamd"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return any(_PATTERN.match(ln) for ln in sample_lines[:25])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["ts"])
        except (ValueError, TypeError, OverflowError):
            ts = None
        message = m["message"].strip()
        low = message.lower()
        severity = Severity.INFO
        if any(k in low for k in _WARN_KW):
            severity = Severity.WARNING
        if any(k in low for k in _ERROR_KW):
            severity = Severity.ERROR
        extra: dict[str, object] = {
            "pid": m["pid"],
            "worker": m["worker"],
            "module": m["module"],
        }
        if m["tag"]:
            extra["tag"] = m["tag"]
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="rspamd",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
