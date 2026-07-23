from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, syslog_tag_dominant

# Puppet config-management agent logging through syslog under the
# "puppet-agent"/"puppet-server" tag:
#   Jun 28 10:15:01 host puppet-agent[1234]: Applied catalog in 12.34 seconds
#   Jun 28 10:15:02 host puppet-agent[1234]: (/Stage[main]/Ntp/...) created
#   Jun 28 10:15:03 host puppet-agent[1234]: Could not retrieve catalog ...
#   Jun 28 10:15:04 host puppet-server[1234]: Compiled catalog for host ...
_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"(?P<prog>puppet-agent|puppet-server|puppet-master|puppet)"
    r"(?:\[(?P<pid>\d+)\])?: "
    r"(?P<message>.*)"
)
_CURRENT_YEAR = datetime.now().year

_ERROR_MARKERS = ("could not", "cannot", "failed", "error", "err:",
                  "unable to", "evaluation error", "no such", "fatal")
_WARN_MARKERS = ("warning", "deprecat", "skipping", "notice: skip",
                 "will be retried", "retrying", "no candidate", "duplicate")


def _severity(message: str) -> Severity:
    low = message.lower()
    if any(m in low for m in _ERROR_MARKERS):
        return Severity.ERROR
    if any(m in low for m in _WARN_MARKERS):
        return Severity.WARNING
    return Severity.INFO


class PuppetParser(LogParser):
    FORMAT_NAME = "puppet"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return syslog_tag_dominant(sample_lines, _PATTERN, path=path)

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(
                f"{m['month']} {m['day']} {_CURRENT_YEAR} {m['time']}"
            )
        except Exception:
            ts = None
        message = m["message"].strip()
        extra: dict[str, object] = {"program": m["prog"]}
        if m["pid"]:
            extra["pid"] = m["pid"]
        res = re.match(r"\((/[^)]+)\)", message)
        if res:
            extra["resource"] = res.group(1)
        return ParsedEvent(
            timestamp=ts,
            severity=_severity(message),
            source=m["prog"],
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
