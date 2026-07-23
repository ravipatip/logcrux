from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, level_to_severity

# Keycloak (Quarkus distribution) server log. Standard JBoss-logging layout, but
# the category is always a org.keycloak / org.jboss / io.quarkus logger, and the
# auth event lines carry "type=...":
#   2026-06-20 10:15:01,123 INFO  [org.keycloak.services] (build-1) Loaded config
#   2026-06-20 10:15:02,456 WARN  [org.keycloak.events] (executor-thread-1)
#       type=LOGIN_ERROR, realmId=master, userId=null, ipAddress=1.2.3.4,
#       error=invalid_user_credentials, username=admin
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) "
    r"(?P<level>TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s+"
    r"\[(?P<category>[\w.]+)\] "
    r"\((?P<thread>[^)]*)\) (?P<message>.*)$"
)
_EVENT_TYPE_RE = re.compile(r"\btype=(\w+)")
_ERROR_RE = re.compile(r"\berror=(\S+?),?$|\berror=(\S+?),")


class KeycloakParser(LogParser):
    FORMAT_NAME = "keycloak"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for ln in sample_lines[:20]:
            m = _PATTERN.match(ln)
            if m and (
                "keycloak" in m["category"]
                or m["category"].startswith(("org.jboss", "io.quarkus", "org.infinispan"))
            ):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["ts"].replace(",", "."))
        except (ValueError, TypeError, OverflowError):
            ts = None
        message = m["message"].strip()
        severity = level_to_severity(m["level"])
        extra: dict[str, object] = {"level": m["level"].lower(), "category": m["category"]}
        evt = _EVENT_TYPE_RE.search(message)
        if evt:
            event_type = evt.group(1)
            extra["event_type"] = event_type
            # A failed-auth event (LOGIN_ERROR, CODE_TO_TOKEN_ERROR, ...) is a
            # security signal even when logged at WARN/INFO level.
            if event_type.endswith("_ERROR") and severity in (Severity.INFO, Severity.DEBUG):
                severity = Severity.WARNING
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="keycloak",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
