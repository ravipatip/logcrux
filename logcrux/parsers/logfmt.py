from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# logfmt is the structured key=value line format emitted by the go-kit logger
# (Prometheus, Loki, Thanos, Cortex, Vector) and Grafana:
#   level=info ts=2026-06-23T10:23:45.123Z caller=main.go:123 msg="Starting"
#   ts=2026-06-23T10:23:45.123Z caller=head.go:80 level=warn msg="..." err="..."
#   t=2026-06-23T10:23:45.0+00:00 lvl=eror msg="failed" logger=http
# We require a level (level=/lvl=) AND a msg= so free-text "a=b" lines are not
# claimed. The leading token must not be ``time="`` (that is logrus' format).
# logfmt keys sit at token boundaries; the lookbehind anchor makes findall
# fail in O(1) at every offset inside a long word-run instead of re-consuming
# the rest of the line (O(n²) — a multi-KB junk line cost seconds, a multi-MB
# one minutes). Possessive quantifiers (Python ≥3.11) kill the backtracking
# within a single attempt for the same reason.
_KV_RE = re.compile(r'(?:^|(?<=\s))(\w[\w.\-]*+)=(?:"((?:\\.|[^"\\])*+)"|(\S+))')
_LEVEL_KEYS = ("level", "lvl", "severity")
_TS_KEYS = ("ts", "time", "t", "timestamp")


def _fields(line: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, quoted, bare in _KV_RE.findall(line):
        out[key] = quoted if quoted != "" else bare
    return out


def _looks_like_logfmt(line: str) -> bool:
    if line.startswith('time="'):
        return False
    # The level=/msg= shape check only needs a prefix; scanning a pathological
    # multi-MB line for key=value pairs is wasted work even without backtracking.
    fields = _fields(line[:8192])
    if "msg" not in fields and "message" not in fields:
        return False
    return any(k in fields for k in _LEVEL_KEYS)


class LogfmtParser(LogParser):
    FORMAT_NAME = "logfmt"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        considered = 0
        matched = 0
        for line in sample_lines[:15]:
            if not line.strip():
                continue
            considered += 1
            if _looks_like_logfmt(line):
                matched += 1
        return considered > 0 and matched * 2 >= considered and matched >= 1

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line.strip() or not _looks_like_logfmt(line):
            return None
        fields = _fields(line)
        level = next((fields[k] for k in _LEVEL_KEYS if k in fields), "info")
        ts = None
        for key in _TS_KEYS:
            if key in fields:
                try:
                    ts = dateparser.parse(fields[key])
                except (ValueError, TypeError, OverflowError):
                    ts = None
                if ts is not None:
                    break
        message = fields.get("msg") or fields.get("message") or ""
        for errkey in ("err", "error"):
            if fields.get(errkey):
                message = f"{message} {errkey}={fields[errkey]}".strip()
        extra: dict[str, object] = {"level": level.lower()}
        for key in ("caller", "logger", "component", "source", "job"):
            if key in fields:
                extra[key] = fields[key]
        return ParsedEvent(
            timestamp=ts,
            severity=level_to_severity(level),
            source=str(fields.get("logger") or fields.get("component") or "logfmt"),
            message=message.strip(),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
