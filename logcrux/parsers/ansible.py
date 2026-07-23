from __future__ import annotations

import re
from pathlib import Path

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Ansible playbook stdout (default callback). No timestamps unless a profiling
# callback is enabled, so detection keys off the distinctive line shapes:
#   PLAY [webservers] **************************************
#   TASK [Gathering Facts] *********************************
#   ok: [web01]
#   changed: [web02] => {"changed": true}
#   fatal: [web03]: FAILED! => {"msg": "non-zero return code"}
#   unreachable: [web04]: UNREACHABLE! => {"msg": "timed out"}
#   skipping: [web05]
#   PLAY RECAP ********************************************
#   web01 : ok=5  changed=2  unreachable=0  failed=1  skipped=1
_STATUS_RE = re.compile(
    r"^(?P<status>ok|changed|failed|fatal|skipping|skipped|unreachable|included|"
    r"ignoring)::?\s*\[(?P<host>[^\]]+)\](?P<rest>.*)$"
)
_HEADER_RE = re.compile(r"^(?P<kind>PLAY|TASK|PLAY RECAP|RUNNING HANDLER)\b.*$")
_WARNING_RE = re.compile(r"^\[(?:DEPRECATION )?WARNING\]:", re.IGNORECASE)
_RECAP_RE = re.compile(r"^\S+\s*:\s*ok=\d+\s+changed=\d+\s+unreachable=\d+\s+failed=\d+")

_STATUS_SEVERITY = {
    "ok": Severity.INFO,
    "changed": Severity.INFO,
    "included": Severity.INFO,
    "skipping": Severity.DEBUG,
    "skipped": Severity.DEBUG,
    "ignoring": Severity.WARNING,
    "failed": Severity.ERROR,
    "fatal": Severity.ERROR,
    "unreachable": Severity.ERROR,
}


class AnsibleParser(LogParser):
    FORMAT_NAME = "ansible"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        considered = 0
        matched = 0
        for line in sample_lines[:25]:
            if not line.strip():
                continue
            considered += 1
            if (
                _HEADER_RE.match(line)
                or _STATUS_RE.match(line)
                or _RECAP_RE.match(line)
                or _WARNING_RE.match(line)
            ):
                matched += 1
        # Require a real concentration of Ansible-shaped lines so a stray
        # "ok: [x]" in some other log can't claim the file.
        return considered > 0 and matched >= 2 and matched * 2 >= considered

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line.strip():
            return None
        status = _STATUS_RE.match(line)
        if status:
            kind = status["status"]
            severity = _STATUS_SEVERITY.get(kind, Severity.INFO)
            return ParsedEvent(
                timestamp=None,
                severity=severity,
                source="ansible",
                message=line.strip(),
                raw=line,
                line_number=line_number,
                extra={"status": kind, "host": status["host"]},
            )
        if _WARNING_RE.match(line):
            return self._simple(line, line_number, Severity.WARNING)
        if _RECAP_RE.match(line):
            failed = re.search(r"failed=(\d+)", line)
            unreachable = re.search(r"unreachable=(\d+)", line)
            bad = (failed and int(failed.group(1)) > 0) or (
                unreachable and int(unreachable.group(1)) > 0
            )
            return self._simple(
                line, line_number, Severity.ERROR if bad else Severity.INFO
            )
        if _HEADER_RE.match(line):
            return self._simple(line, line_number, Severity.INFO)
        return None

    @staticmethod
    def _simple(line: str, line_number: int, severity: Severity) -> ParsedEvent:
        return ParsedEvent(
            timestamp=None,
            severity=severity,
            source="ansible",
            message=line.strip(),
            raw=line,
            line_number=line_number,
        )
