from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# wpa_supplicant Wi-Fi client (often via syslog, sometimes bare). Interface +
# CTRL-EVENT / state messages:
#   Jun 28 10:15:01 host wpa_supplicant[1234]: wlan0: SME: Trying to authenticate
#   Jun 28 10:15:02 host wpa_supplicant[1234]: wlan0: CTRL-EVENT-CONNECTED ...
#   wlan0: CTRL-EVENT-DISCONNECTED bssid=aa:bb reason=3
#   wlan0: CTRL-EVENT-SSID-TEMP-DISABLED ssid="x" auth_failures=1
# Detection keys on the wpa-specific "CTRL-EVENT-" / "wlanN:" + association verbs.
_SYSLOG_PREFIX = re.compile(
    r"^\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2} \S+ "
    r"wpa_supplicant(?:\[\d+\])?: (?P<rest>.*)$"
)
_IFACE_RE = re.compile(r"^(?P<iface>[a-z]+\d+|p2p-dev-\w+): (?P<message>.*)$")
_WPA_MARKERS = ("CTRL-EVENT-", "SME:", "Trying to associate", "WPA:",
                "Trying to authenticate", "Associated with", "EAP",
                "key negotiation", "RSN:", "deauthenticat", "pre-shared key")
_CURRENT_YEAR = datetime.now().year

_ERROR_MARKERS = ("DISCONNECTED", "AUTH-REJECT", "CONNECTION-LOST",
                  "TEMP-DISABLED", "handshake failed", "WRONG-KEY",
                  "authentication with", "deauthenticat", "failed")
_WARN_MARKERS = ("SCAN-FAILED", "ASSOC-REJECT", "retr", "timeout",
                 "Failed to initiate", "reason=")


def _payload(line: str) -> str | None:
    m = _SYSLOG_PREFIX.match(line)
    if m:
        return m["rest"]
    if _IFACE_RE.match(line) and any(mk in line for mk in _WPA_MARKERS):
        return line
    return None


class WpaSupplicantParser(LogParser):
    FORMAT_NAME = "wpa_supplicant"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for ln in sample_lines[:20]:
            payload = _payload(ln)
            if payload and any(mk in payload for mk in _WPA_MARKERS):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        payload = _payload(line)
        if payload is None:
            return None
        if not any(mk in payload for mk in _WPA_MARKERS):
            return None
        ts = None
        sm = re.match(
            r"^(\w{3})\s+(\d{1,2}) (\d{2}:\d{2}:\d{2})", line
        )
        if sm:
            try:
                ts = dateparser.parse(
                    f"{sm.group(1)} {sm.group(2)} {_CURRENT_YEAR} {sm.group(3)}"
                )
            except Exception:
                ts = None
        extra: dict[str, object] = {}
        im = _IFACE_RE.match(payload)
        message = payload
        if im:
            extra["interface"] = im["iface"]
            message = im["message"]
        severity = Severity.INFO
        if any(mk in message for mk in _ERROR_MARKERS):
            severity = Severity.ERROR
        elif any(mk in message for mk in _WARN_MARKERS):
            severity = Severity.WARNING
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="wpa_supplicant",
            message=message.strip(),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
