from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# HashiCorp stack (Consul, Vault, Nomad) shares hclog's format: an ISO-8601
# timestamp, a bracketed level, then "component: msg" key=value pairs.
#   2026-06-20T10:23:45.123Z [INFO]  agent: Started Consul agent
#   2026-06-20T10:23:45.123Z [WARN]  raft: heartbeat timeout reached, starting election
#   2026-06-20T10:23:45.123Z [ERROR] core: failed to unseal: error=...
#   2026-06-20T10:23:45.123Z [ERROR] nomad: failed to establish leadership
_PATTERN = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"\s+\[(?P<level>TRACE|DEBUG|INFO|WARN|ERROR)\]\s+"
    r"(?P<component>[\w.\-/]+):\s+"
    r"(?P<message>.*)"
)

# Components that uniquely identify the HashiCorp stack (avoids grabbing other
# "<iso-ts> [LEVEL] word: msg" application logs).
_KNOWN_COMPONENTS = frozenset([
    "agent", "raft", "serf", "consul", "core", "vault", "nomad", "http",
    "rpc", "memberlist", "storage", "secrets", "auth", "client", "server",
    "worker", "leader", "snapshot", "connect", "expiration", "rollback",
    "agent.server", "agent.client", "agent.http", "nomad.client",
])

_LEVEL_MAP: dict[str, Severity] = {
    "TRACE": Severity.DEBUG,
    "DEBUG": Severity.DEBUG,
    "INFO": Severity.INFO,
    "WARN": Severity.WARNING,
    "ERROR": Severity.ERROR,
}


def _component_known(component: str) -> bool:
    head = component.split(".")[0]
    return component in _KNOWN_COMPONENTS or head in _KNOWN_COMPONENTS


class HashiCorpParser(LogParser):
    FORMAT_NAME = "hashicorp"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path:
            name = str(path).lower()
            if any(t in name for t in ("consul", "vault", "nomad")):
                return True
        for line in sample_lines[:10]:
            m = _PATTERN.match(line)
            if m and _component_known(m["component"]):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["ts"])
        except (ValueError, TypeError, OverflowError):
            ts = None
        severity = _LEVEL_MAP.get(m["level"], Severity.INFO)
        message = m["message"].strip()
        # An ERROR-level line frequently carries error=... ; keep severity as-is.
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source=m["component"].split(".")[0],
            message=message,
            raw=line,
            line_number=line_number,
            extra={"component": m["component"], "level": m["level"]},
        )
