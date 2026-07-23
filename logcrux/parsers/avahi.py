from __future__ import annotations

from logcrux.parsers.base import SyslogKeywordParser

# Avahi mDNS/DNS-SD daemon syslog output. Tagged "avahi-daemon":
#   Jun 28 10:15:01 host avahi-daemon[1234]: Server startup complete. Host name is host.local
#   Jun 28 10:15:02 host avahi-daemon[1234]: Joining mDNS multicast group on interface eth0.IPv4
#   Jun 28 10:15:03 host avahi-daemon[1234]: Withdrawing address record for 10.0.0.5 on eth0
#   Jun 28 10:15:04 host avahi-daemon[1234]: Failed to create client object: Daemon not running


class AvahiParser(SyslogKeywordParser):
    FORMAT_NAME = "avahi"
    SOURCE = "avahi"
    TAG_PATTERN = r"avahi-daemon|avahi"
    ERROR_KW = ("failed", "error", "cannot", "denied", "refused", "not running",
                "no such", "invalid")
    WARN_KW = ("withdrawing", "registering", "conflict", "retry", "received")
