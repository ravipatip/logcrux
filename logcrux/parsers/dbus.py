from __future__ import annotations

from logcrux.parsers.base import SyslogKeywordParser

# D-Bus message-bus daemon syslog output. Tagged "dbus-daemon" (or "dbus"):
#   Jun 28 10:15:01 host dbus-daemon[1234]: [system] Activating service name='org.x'
#   Jun 28 10:15:02 host dbus-daemon[1234]: [system] Successfully activated service 'org.y'
#   Jun 28 10:15:03 host dbus-daemon[1234]: [system] Failed to activate service 'org.x': timed out


class DBusParser(SyslogKeywordParser):
    FORMAT_NAME = "dbus"
    SOURCE = "dbus"
    TAG_PATTERN = r"dbus-daemon|dbus"
    ERROR_KW = ("failed", "error", "cannot", "denied", "timed out", "refused",
                "rejected", "no such")
    WARN_KW = ("dropping", "exceeded", "reached", "retry", "deprecated")
