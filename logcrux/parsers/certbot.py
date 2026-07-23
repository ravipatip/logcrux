from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# Certbot / Let's Encrypt ACME client log (/var/log/letsencrypt/letsencrypt.log).
# Python-logging colon style "ts:LEVEL:module:message":
#   2026-06-28 10:15:01,123:DEBUG:certbot._internal.main:certbot version: 2.9.0
#   2026-06-28 10:15:02,456:INFO:certbot._internal.auth_handler:Performing http-01
#   2026-06-28 10:15:03,789:ERROR:certbot._internal.error_handler:Encountered exception
# Distinguished by the certbot/acme module path after the level.
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:,\d+)?):"
    r"(?P<level>DEBUG|INFO|WARNING|WARN|ERROR|CRITICAL):"
    r"(?P<module>[\w._]+):(?P<message>.*)$"
)


def _is_certbot_module(module: str) -> bool:
    return module.startswith(("certbot", "acme"))


class CertbotParser(LogParser):
    FORMAT_NAME = "certbot"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for ln in sample_lines[:20]:
            m = _PATTERN.match(ln)
            if m and _is_certbot_module(m["module"]):
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
        return ParsedEvent(
            timestamp=ts,
            severity=level_to_severity(m["level"]),
            source="certbot",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"level": m["level"].lower(), "module": m["module"]},
        )
