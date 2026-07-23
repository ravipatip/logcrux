from __future__ import annotations

from logcrux.parsers.base import SyslogKeywordParser

# snapd package-daemon syslog output. Tagged "snapd":
#   Jun 28 10:15:01 host snapd[1234]: storehelpers.go:827: cannot refresh: snap has no updates
#   Jun 28 10:15:02 host snapd[1234]: api.go:1130: Installing snap "hello" revision 42
#   Jun 28 10:15:03 host snapd[1234]: daemon.go:600: error: cannot install "x": network error


class SnapdParser(SyslogKeywordParser):
    FORMAT_NAME = "snapd"
    SOURCE = "snapd"
    TAG_PATTERN = r"snapd"
    ERROR_KW = ("error", "cannot", "failed", "refused", "denied", "no such",
                "unable", "timeout")
    WARN_KW = ("warning", "retry", "retrying", "no updates", "deprecated",
               "held back")
