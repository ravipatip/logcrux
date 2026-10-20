from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# macOS /var/log/install.log — written by Installer.app, softwareupdated and
# friends. Syslog-ish, but the timestamp is ISO date + time with a *short*
# numeric offset ("+10", not "+1000"), which is why the syslog parser (RFC3164
# "Mon DD HH:MM:SS") never matches it and a real install.log fell to generic:
#   2026-07-27 16:16:24+10 host softwareupdated[25464]: Doing periodic action
#   2026-07-27 16:16:25+10 host installd[452]: PackageKit: Extracting file://...
# Multi-line property-list dumps continue on tab-indented lines and are folded
# into the event that opened them (see CONTINUATION).
_PATTERN = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2})"
    r"(?P<offset>[+-]\d{2}(?::?\d{2})?)? "
    r"(?P<host>\S+) (?P<prog>[^\[\s]+|[^\[:]+?(?=\[\d+\]))(?:\[(?P<pid>\d+)\])?: "
    r"(?P<message>.*)$"
)
# The same file also carries plain RFC 3164 lines from boot-time daemons
# ("May 27 12:36:43 host powerd[53]: ..."): 8,900 of 104,729 lines of a real
# install.log, unparsed until this. Parsed here, never used for detection
# (that stays on the ISO shape, so install.log never claims a syslog file).
_RFC3164 = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) (?P<prog>[^\[\s]+|[^\[:]+?(?=\[\d+\]))(?:\[(?P<pid>\d+)\])?: "
    r"(?P<message>.*)$"
)
# What install.log is for: did an install fail. A real 258-day install.log
# (macOS 26, 2026-10-20) held 6,956 keyword "errors" — 3,731 of them
# "Package Authoring: error running installation-check script", 1,092 "Failed
# to get bridge device", OneDrive cleanup, offline catalog scans — and zero
# failed installs; graded as errors they made 67 "error bursts" on a healthy
# Mac, and as warnings still 60. Only installer failure wording is an ERROR;
# other error words are INFO (still searchable, still seen by the specific
# detectors); "skipping"/"retrying" stay warnings.
# The failure wording below is Apple's documented installer phrasing, not yet
# seen in a captured failure (confidence: low) — the downgrade above is the
# measured part.
_INSTALL_FAILED_RE = re.compile(
    r"\b(?:install(?:ation)? failed|failed to install(?! product keys tonight)"
    r"|could not be installed|didFailWithError|PKInstallErrorDomain)\b",
    re.I,
)
# Keyword warnings keep the word-start anchor: "_buildInstallPlanReturningError:"
# and similar Objective-C selectors are routine progress lines.
_WARN_RE = re.compile(
    r"(?<![A-Za-z])(warning|deprecated|retrying|skipping)", re.I
)


class MacOSInstallParser(LogParser):
    FORMAT_NAME = "macos-install"

    # Plist / array dumps that Installer writes across several indented lines.
    CONTINUATION = re.compile(r"^\s+\S")

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and path.name.lower() in ("install.log", "macos-install.log"):
            return True
        matched = sum(1 for ln in sample_lines[:20] if _PATTERN.match(ln))
        nonblank = sum(1 for ln in sample_lines[:20] if ln.strip())
        return nonblank > 0 and matched * 2 >= nonblank

    def _severity(self, message: str) -> Severity:
        if _INSTALL_FAILED_RE.search(message):
            return Severity.ERROR
        if _WARN_RE.search(message):
            return Severity.WARNING
        return Severity.INFO

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if m:
            # "+10" is a valid macOS offset but not ISO-8601; pad it to "+1000"
            # so dateutil keeps the zone instead of discarding the timestamp.
            offset = m["offset"] or ""
            if len(offset) == 3:
                offset += "00"
            stamp = f'{m["date"]} {m["time"]}{offset}'
        else:
            m = _RFC3164.match(line)
            if not m:
                return None
            stamp = f'{m["mon"]} {m["day"]} {datetime.now().year} {m["time"]}'
        try:
            ts = dateparser.parse(stamp)
        except (ValueError, TypeError, OverflowError):
            ts = None
        message = m["message"].strip()
        extra: dict[str, object] = {"program": m["prog"], "host": m["host"]}
        if m["pid"]:
            extra["pid"] = m["pid"]
        return ParsedEvent(
            timestamp=ts,
            severity=self._severity(message),
            source=m["prog"],
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
