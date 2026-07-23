from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# Sidekiq (Ruby background-job processor) logs. Both the classic and the modern
# pid=/tid= header are supported:
#   2026-06-28T10:15:01.123Z 1 TID-oxyz INFO: Booting Sidekiq 7.0
#   2026-06-28T10:15:02.456Z pid=1 tid=abc class=HardWorker jid=xyz INFO: start
#   2026-06-28T10:15:03.789Z pid=1 tid=abc class=HardWorker jid=xyz ERROR: failed
# The ISO-Z timestamp + "TID-"/("pid="&"tid=") header + "LEVEL:" is distinctive.
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z) "
    r"(?P<header>.*?)"
    r"(?P<level>DEBUG|INFO|WARN|ERROR|FATAL): "
    r"(?P<message>.*)$"
)


def _looks_sidekiq(header: str) -> bool:
    return "TID-" in header or ("pid=" in header and "tid=" in header) or bool(
        re.match(r"^\d+ TID-", header)
    )


class SidekiqParser(LogParser):
    FORMAT_NAME = "sidekiq"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for ln in sample_lines[:20]:
            m = _PATTERN.match(ln)
            if m and _looks_sidekiq(m["header"]):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m or not _looks_sidekiq(m["header"]):
            return None
        try:
            ts = datetime.fromisoformat(m["ts"].replace("Z", "+00:00"))
        except ValueError:
            ts = None
        header = m["header"]
        extra: dict[str, object] = {"level": m["level"].lower()}
        for key in ("pid", "tid", "class", "jid"):
            hit = re.search(rf"\b{key}=(\S+)", header)
            if hit:
                extra[key] = hit.group(1)
        tid_classic = re.match(r"^(\d+) TID-(\S+)", header)
        if tid_classic:
            extra["pid"] = tid_classic.group(1)
            extra["tid"] = tid_classic.group(2)
        return ParsedEvent(
            timestamp=ts,
            severity=level_to_severity(m["level"]),
            source="sidekiq",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
