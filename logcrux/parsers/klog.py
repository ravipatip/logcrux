from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# klog / glog is the logging format used by virtually every Kubernetes
# component (kube-apiserver, kube-controller-manager, kube-scheduler, kubelet,
# kube-proxy) and many controllers (calico, coredns can use it, etc.):
#   I0623 10:23:45.123456   12345 server.go:123] Starting controller
#   E0623 10:23:45.123456   12345 reflector.go:138] Failed to watch *v1.Pod
# Layout: <L><MMDD> <HH:MM:SS.ffffff> <threadid> <file>:<line>] <message>
# The level letter is I/W/E/F (info/warning/error/fatal).
_PATTERN = re.compile(
    r"^(?P<level>[IWEF])(?P<month>\d{2})(?P<day>\d{2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}\.\d{6})\s+"
    r"(?P<thread>\d+)\s+"
    r"(?P<file>[\w.\-/]+:\d+)\]\s?"
    r"(?P<message>.*)$"
)


class KlogParser(LogParser):
    FORMAT_NAME = "klog"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        matched = 0
        considered = 0
        for line in sample_lines[:20]:
            if not line.strip():
                continue
            considered += 1
            if _PATTERN.match(line):
                matched += 1
        # A klog file is overwhelmingly klog lines; require a clear majority so a
        # stray "I0623 ..."-looking line elsewhere can't hijack another format.
        return considered > 0 and matched * 2 >= considered and matched >= 1

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        ts = self._timestamp(m["month"], m["day"], m["time"])
        return ParsedEvent(
            timestamp=ts,
            severity=level_to_severity(m["level"]),
            source="klog",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"caller": m["file"], "level": m["level"], "thread": m["thread"]},
        )

    @staticmethod
    def _timestamp(month: str, day: str, time_str: str) -> datetime | None:
        # glog omits the year; assume the current year (matches journald/syslog
        # handling elsewhere). Time is UTC by klog convention.
        try:
            now = datetime.now(timezone.utc)
            hh, mm, rest = time_str.split(":")
            sec, micro = rest.split(".")
            return datetime(
                now.year, int(month), int(day),
                int(hh), int(mm), int(sec), int(micro),
                tzinfo=timezone.utc,
            )
        except (ValueError, OverflowError):
            return None
