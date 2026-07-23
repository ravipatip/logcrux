from __future__ import annotations

import json
import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

_STDERR_KEYWORDS = frozenset(
    ["error", "err ", "fatal", "panic", "exception", "traceback", "critical"]
)
_WARN_KEYWORDS = frozenset(["warn", "warning", "deprecated"])


def _infer_severity(log: str, stream: str) -> Severity:
    low = log.lower()
    if any(kw in low for kw in _STDERR_KEYWORDS):
        return Severity.ERROR
    if stream == "stderr":
        return Severity.WARNING
    if any(kw in low for kw in _WARN_KEYWORDS):
        return Severity.WARNING
    return Severity.INFO


# Structured log levels emitted by many runtimes inside the "log" field
_LEVEL_RE = re.compile(
    r'\b(?:level|lvl|severity)[\s=:"]+(?P<level>error|warn(?:ing)?|info|debug|fatal|critical)',
    re.IGNORECASE,
)


def _level_from_message(log: str) -> Severity | None:
    m = _LEVEL_RE.search(log)
    if not m:
        return None
    lv = m["level"].lower()
    if lv in ("fatal", "critical"):
        return Severity.CRITICAL
    if lv == "error":
        return Severity.ERROR
    if lv in ("warn", "warning"):
        return Severity.WARNING
    if lv == "debug":
        return Severity.DEBUG
    return Severity.INFO


def parse_docker_json_line(
    line: str,
    line_number: int,
    source: str,
) -> ParsedEvent | None:
    if not line or not line.startswith("{"):
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    log: str = obj.get("log", "").rstrip("\n")
    stream: str = obj.get("stream", "")
    time_str: str = obj.get("time", "")
    if not log and not time_str:
        return None
    try:
        ts = dateparser.parse(time_str, fuzzy=True) if time_str else None
    except Exception:
        ts = None
    severity = _level_from_message(log) or _infer_severity(log, stream)
    return ParsedEvent(
        timestamp=ts,
        severity=severity,
        source=source,
        message=log or "(empty)",
        raw=line,
        line_number=line_number,
        extra={"stream": stream},
    )


class DockerParser(LogParser):
    FORMAT_NAME = "docker"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path:
            p = str(path)
            if "/docker/containers/" in p or "/docker/overlay2/" in p:
                return True
        return any(
            line.startswith('{"log":') or line.startswith('{"log" :')
            for line in sample_lines[:5]
        )

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        return parse_docker_json_line(line, line_number, "docker")
