from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# logrus text formatter — the default for containerd, dockerd, Calico/Felix,
# Argo, and a large fraction of Go services:
#   time="2026-06-23T10:23:45.123456789Z" level=info msg="starting containerd"
#   time="2026-06-23T10:23:45Z" level=error msg="failed to start" error="..."
# Distinguished from logfmt by the leading quoted ``time="..."`` token, and from
# the JSON parsers because it is not a JSON object.
_TIME_RE = re.compile(r'^time="(?P<ts>[^"]+)"\s+level=(?P<level>\w+)\s+')
# key=value or key="quoted value" pairs.
_KV_RE = re.compile(r'(\w[\w.\-]*)=(?:"((?:\\.|[^"\\])*)"|(\S+))')


class LogrusParser(LogParser):
    FORMAT_NAME = "logrus"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for line in sample_lines[:10]:
            if _TIME_RE.match(line):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _TIME_RE.match(line)
        if not m:
            return None
        fields: dict[str, str] = {}
        for key, quoted, bare in _KV_RE.findall(line):
            fields[key] = quoted if quoted != "" else bare
        ts = None
        try:
            ts = dateparser.parse(m["ts"])
        except (ValueError, TypeError, OverflowError):
            ts = None
        level = m["level"].lower()
        message = fields.get("msg", "")
        if "error" in fields and fields["error"]:
            message = f"{message} error={fields['error']}".strip()
        extra: dict[str, object] = {"level": level}
        for key in ("component", "module", "container", "namespace", "pod", "error"):
            if key in fields:
                extra[key] = fields[key]
        return ParsedEvent(
            timestamp=ts,
            severity=level_to_severity(level),
            source=str(fields.get("component") or fields.get("module") or "logrus"),
            message=message.strip().replace("\\n", " ").replace('\\"', '"'),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
