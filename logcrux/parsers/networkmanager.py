from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, syslog_tag_dominant

# NetworkManager logs through syslog and embeds its own level marker:
#   Jun 20 10:23:45 host NetworkManager[789]: <info>  [1623.4] device (eth0): \
#       state change: config -> ip-config (reason 'none')
#   Jun 20 10:23:45 host NetworkManager[789]: <warn>  [1623.7] dhcp4 (eth0): \
#       request timed out
#   Jun 20 10:23:45 host NetworkManager[789]: <error> [1623.9] device (eth0): \
#       Activation: failed for connection 'Wired'
_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"(?P<prog>NetworkManager)(?:\[(?P<pid>\d+)\])?: "
    r"(?P<message>.*)"
)

_LEVEL_RE = re.compile(r"^<(?P<level>trace|debug|info|warn|error)>\s*")
_CURRENT_YEAR = datetime.now().year

_LEVEL_MAP: dict[str, Severity] = {
    "trace": Severity.DEBUG,
    "debug": Severity.DEBUG,
    "info": Severity.INFO,
    "warn": Severity.WARNING,
    "error": Severity.ERROR,
}

# The explicit <warn>/<error> marker is authoritative. These keywords only
# escalate an <info>-tagged line that nonetheless describes a real failure
# (NetworkManager logs many activation failures at info level).
_ERROR_KEYWORDS = frozenset([
    "activation: failed", "failed for connection", "carrier lost",
    "link down", "could not", "no route to", "unavailable",
])
_WARN_KEYWORDS = frozenset([
    "request timed out", "deactivating", "retry", "rejected",
    "no suitable", "lease expired", "disconnected",
])


def _nm_severity(message: str) -> Severity:
    m = _LEVEL_RE.match(message)
    base = _LEVEL_MAP.get(m["level"], Severity.INFO) if m else Severity.INFO
    # A marked warn/error/debug line keeps its declared level.
    if base != Severity.INFO:
        return base
    low = message.lower()
    if any(kw in low for kw in _ERROR_KEYWORDS):
        return Severity.ERROR
    if any(kw in low for kw in _WARN_KEYWORDS):
        return Severity.WARNING
    return base


class NetworkManagerParser(LogParser):
    FORMAT_NAME = "networkmanager"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "networkmanager" in path.name.lower():
            return True
        return syslog_tag_dominant(sample_lines, _PATTERN, path=path)

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(f"{m['month']} {m['day']} {_CURRENT_YEAR} {m['time']}")
        except (ValueError, TypeError, OverflowError):
            ts = None
        raw_message = m["message"].strip()
        severity = _nm_severity(raw_message)
        # Strip the leading "<info>  [123.4] " bookkeeping for the readable body.
        message = _LEVEL_RE.sub("", raw_message)
        message = re.sub(r"^\[\d+\.\d+\]\s*", "", message)
        extra: dict[str, object] = {"program": "NetworkManager"}
        if m["pid"]:
            extra["pid"] = m["pid"]
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="NetworkManager",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
