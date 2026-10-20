from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# SUSE/openSUSE /var/log/zypp/history — pipe-delimited, one record per line, and
# the field layout depends on the action in field 2:
#   2026-07-28 00:15:51|command|root@host|'zypper' '-n' 'install' 'zsh'|
#   2026-07-28 00:15:51|install|libgdbm6|1.24-160000.2.2|aarch64||repo-oss|<sha>|
#   2026-07-28 00:15:52|patch  |openSUSE-Leap-16.0-1283|1|noarch|repo-oss|important
#       |security|not-needed|applied|          (one line; wrapped here to fit)
#   2026-07-28 00:16:03|remove |vim|9.1.1418-16.1|aarch64|root@host|
# zypp pads some action names to 7 chars ("patch  ", "remove "), so the action is
# stripped before dispatch. "#" lines are zypp's own comments/headers.
_ACTION_FIELDS: dict[str, tuple[str, ...]] = {
    "install": ("package", "version", "arch", "requested_by", "repo", "checksum"),
    "remove": ("package", "version", "arch", "requested_by"),
    "patch": (
        "patch", "version", "arch", "repo",
        "patch_severity", "category", "interactive", "status",
    ),
    "command": ("user", "commandline"),
    "radd": ("repo_alias", "repo_url"),
    "rremove": ("repo_alias",),
    "ralias": ("old_alias", "new_alias"),
    "rurl": ("repo_alias", "repo_url"),
    "rname": ("old_name", "new_name"),
    "rpriority": ("repo_alias", "priority"),
}
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")
# Patch severities zypp records; the top two are worth surfacing as warnings
# because they mark a security-relevant update the operator may have skipped.
_HIGH_PATCH_SEVERITIES = frozenset(["important", "critical"])


# zypp annotates the history with "#"-prefixed lines carrying the rpm output of
# the record above ("# warning: ... NOKEY", "# ... cpio.rpm installed ok"). On a
# real SLES 15 SP7 image they were 80% of /var/log/zypp/history (2398/3000) and
# 92% on Leap 16; counted as unparsed they dropped coverage to 602/3000 and the
# file fell to generic. Fold them into their record instead.
_ANNOTATION = re.compile(r"^#")


class ZyppHistoryParser(LogParser):
    FORMAT_NAME = "zypp-history"
    CONTINUATION = _ANNOTATION

    @classmethod
    def _fields(cls, line: str) -> list[str] | None:
        if not line or line.startswith("#"):
            return None
        parts = line.split("|")
        if len(parts) < 3 or not _TS_RE.match(parts[0]):
            return None
        if parts[1].strip() not in _ACTION_FIELDS:
            return None
        return parts

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "zypp" in str(path).lower() and "history" in str(path).lower():
            return True
        matched = sum(1 for ln in sample_lines[:20] if cls._fields(ln))
        nonblank = sum(
            1 for ln in sample_lines[:20] if ln.strip() and not ln.startswith("#")
        )
        return nonblank > 0 and matched * 2 >= nonblank

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        parts = self._fields(line)
        if parts is None:
            return None
        action = parts[1].strip()
        try:
            ts = dateparser.parse(parts[0])
        except (ValueError, TypeError, OverflowError):
            ts = None
        extra: dict[str, object] = {"action": action}
        for name, value in zip(_ACTION_FIELDS[action], parts[2:]):
            if value:
                extra[name] = value
        severity = Severity.INFO
        if action == "patch" and extra.get("patch_severity") in _HIGH_PATCH_SEVERITIES:
            severity = Severity.WARNING
        # The trailing field is always empty (records end in "|"); joining the
        # populated ones keeps the message readable without re-listing the layout.
        detail = " ".join(str(extra[name]) for name in _ACTION_FIELDS[action]
                          if name in extra)
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="zypp",
            message=f"{action}: {detail}".strip(),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
