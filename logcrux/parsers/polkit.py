from __future__ import annotations

from logcrux.parsers.base import SyslogKeywordParser

# polkit (PolicyKit) authorization-manager syslog output. Tagged "polkitd":
#   Jun 28 10:15:01 host polkitd[1234]: Registered Authentication Agent for unix-session
#   Jun 28 10:15:02 host polkitd[1234]: Operator of unix-session granted authorization
#   Jun 28 10:15:03 host polkitd[1234]: Error getting authority: Error initializing


class PolkitParser(SyslogKeywordParser):
    FORMAT_NAME = "polkit"
    SOURCE = "polkit"
    TAG_PATTERN = r"polkitd|polkit"
    ERROR_KW = ("error", "failed", "denied", "not authorized", "cannot",
                "refused", "unable")
    WARN_KW = ("dismissed", "cancelled", "timed out", "revoked")
