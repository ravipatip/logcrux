from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, syslog_tag_dominant

# Kernel ring-buffer logs (kern.log / dmesg) appear in two shapes.
#
# A) syslog-tagged kern.log line, optionally with a [uptime] prefix in the body:
#    May 19 10:15:01 host kernel: [12345.678901] Out of memory: Killed process 4242 (java)
#    May 19 10:15:01 host kernel: EXT4-fs error (device sda1): ext4_find_entry
#
# B) raw dmesg with a monotonic uptime stamp only:
#    [12345.678901] usb 1-1: new high-speed USB device number 5
_SYSLOG_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"kernel:\s*"
    r"(?:\[\s*(?P<uptime>\d+\.\d+)\]\s*)?"
    r"(?P<message>.*)"
)
_DMESG_PATTERN = re.compile(
    r"\[\s*(?P<uptime>\d+\.\d+)\]\s*(?P<message>.*)"
)
# dmesg -T emits human-readable wall-clock timestamps:
#   [Tue Jun 16 03:41:00 2026] Out of memory: Killed process 4242 (java)
_DMESG_T_PATTERN = re.compile(
    r"\[(?P<ts>[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\]\s*"
    r"(?P<message>.*)"
)

_CURRENT_YEAR = datetime.now().year

# OOM-killer is the headline critical kernel event logcrux already keys on.
_OOM_KEYWORDS = frozenset(
    ["out of memory", "oom-kill", "oom_reaper", "killed process",
     "oom_killer", "memory cgroup out of memory"]
)
# Use specific error tokens: a bare "xfs" matches normal mount lines
# ("XFS (sda1): Mounting...") and a bare "panic" matches unrelated strings
# like "panic_handler". Real XFS faults carry "i/o error"/"corruption".
_CRITICAL_KEYWORDS = frozenset(
    ["kernel panic", "hardware error", "mce:", "machine check",
     "i/o error", "ext4-fs error", "xfs error", "corruption",
     "filesystem error", "bug:",
     "general protection fault", "unable to handle kernel"]
)
_ERROR_KEYWORDS = frozenset(
    ["error", "failed", "fail", "fatal", "segfault", "call trace",
     "link is down", "reset adapter", "abort", "rejected"]
)
_WARN_KEYWORDS = frozenset(
    ["warning", "warn", "deprecated", "throttled", "temperature above",
     "tainted", "dropping", "retrying", "timeout", "timed out"]
)


def _kernel_severity(message: str) -> Severity:
    low = message.lower()
    if any(k in low for k in _OOM_KEYWORDS):
        return Severity.CRITICAL
    if any(k in low for k in _CRITICAL_KEYWORDS):
        return Severity.CRITICAL
    if any(k in low for k in _ERROR_KEYWORDS):
        return Severity.ERROR
    if any(k in low for k in _WARN_KEYWORDS):
        return Severity.WARNING
    return Severity.INFO


class KernelParser(LogParser):
    FORMAT_NAME = "kernel"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path:
            name = path.name.lower()
            if name in ("kern.log", "dmesg") or "kern" in name or "dmesg" in name:
                return True
        if any(
            _DMESG_PATTERN.match(line) or _DMESG_T_PATTERN.match(line)
            for line in sample_lines[:10]
        ):
            return True
        return syslog_tag_dominant(sample_lines, _SYSLOG_PATTERN, path=path)

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _SYSLOG_PATTERN.match(line)
        if m:
            try:
                ts = dateparser.parse(
                    f"{m['month']} {m['day']} {_CURRENT_YEAR} {m['time']}"
                )
            except Exception:
                ts = None
            return self._make(m, ts, line, line_number)
        m = _DMESG_PATTERN.match(line)
        if m:
            # Raw dmesg has no wall-clock time, only monotonic uptime.
            return self._make(m, None, line, line_number)
        m = _DMESG_T_PATTERN.match(line)
        if m:
            try:
                ts = dateparser.parse(m["ts"])
            except Exception:
                ts = None
            return self._make(m, ts, line, line_number)
        return None

    def _make(
        self, m: re.Match[str], ts: datetime | None, line: str, line_number: int
    ) -> ParsedEvent:
        message = m["message"].strip()
        extra: dict[str, object] = {}
        uptime = m.groupdict().get("uptime")
        if uptime:
            extra["uptime"] = float(uptime)
        return ParsedEvent(
            timestamp=ts,
            severity=_kernel_severity(message),
            source="kernel",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
