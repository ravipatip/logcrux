from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# QEMU/KVM emulator stderr (per-VM logs). Lines are prefixed by the emulator
# binary, optionally preceded by an ISO timestamp:
#   2026-06-28T10:15:01.123456Z qemu-system-x86_64: terminating on signal 15
#   qemu-system-x86_64: -drive ...: could not open disk image: No such file
#   qemu-kvm: warning: host doesn't support requested feature
# The "qemu-system-<arch>:" / "qemu-kvm:" binary prefix is the signature.
_PATTERN = re.compile(
    r"^(?:(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z) )?"
    r"(?P<prog>qemu-system-[\w-]+|qemu-kvm|qemu-img): "
    r"(?P<message>.*)$"
)
_ERROR_KW = ("error", "could not", "failed", "cannot", "no such", "unable",
             "terminating", "abort", "fatal")
_WARN_KW = ("warning", "deprecated", "warn", "doesn't support", "ignoring")


class QemuParser(LogParser):
    FORMAT_NAME = "qemu"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return any(_PATTERN.match(ln) for ln in sample_lines[:25])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        ts = None
        if m["ts"]:
            try:
                ts = dateparser.parse(m["ts"])
            except (ValueError, TypeError, OverflowError):
                ts = None
        message = m["message"].strip()
        low = message.lower()
        severity = Severity.INFO
        if low.startswith("warning") or any(k in low for k in _WARN_KW):
            severity = Severity.WARNING
        if any(k in low for k in _ERROR_KW):
            severity = Severity.ERROR
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="qemu",
            message=message,
            raw=line,
            line_number=line_number,
            extra={"program": m["prog"]},
        )
