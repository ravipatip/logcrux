from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity


# Terraform machine-readable logs (``terraform ... -json`` / TF_LOG=json) emit
# one JSON object per line keyed with ``@``-prefixed fields:
#   {"@level":"info","@message":"Terraform 1.8.0","@module":"terraform.ui",
#    "@timestamp":"2026-06-23T10:23:45.123456Z"}
#   {"@level":"error","@message":"Error: creating EC2 Instance: ...",
#    "@module":"terraform.ui","@timestamp":"...","diagnostic":{...}}
def _is_terraform(obj: object) -> bool:
    return (
        isinstance(obj, dict)
        and "@level" in obj
        and "@message" in obj
        and "@module" in obj
    )


class TerraformParser(LogParser):
    FORMAT_NAME = "terraform"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for line in sample_lines[:10]:
            stripped = line.strip()
            if not stripped.startswith("{"):
                continue
            try:
                obj = json.loads(stripped)
            except (json.JSONDecodeError, ValueError):
                continue
            if _is_terraform(obj):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        stripped = line.strip()
        if not stripped.startswith("{"):
            return None
        try:
            obj = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            return None
        if not _is_terraform(obj):
            return None
        ts: datetime | None = None
        raw_ts = obj.get("@timestamp")
        if isinstance(raw_ts, str):
            try:
                ts = dateparser.parse(raw_ts)
            except (ValueError, TypeError, OverflowError):
                ts = None
        level = str(obj.get("@level", "info"))
        message = str(obj.get("@message", ""))
        diagnostic = obj.get("diagnostic")
        if isinstance(diagnostic, dict) and diagnostic.get("detail"):
            message = f"{message}: {diagnostic['detail']}"
        return ParsedEvent(
            timestamp=ts,
            severity=level_to_severity(level),
            source=str(obj.get("@module", "terraform")),
            message=message.strip(),
            raw=line,
            line_number=line_number,
            extra={"level": level, "module": obj.get("@module")},
        )
