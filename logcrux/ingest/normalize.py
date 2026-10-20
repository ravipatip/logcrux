from __future__ import annotations

import re

# Transport decoration that is not part of the log format. Each wrapper is
# stripped only when it frames most of the input, so a format that merely
# contains such text somewhere is never rewritten.
#
#   ANSI SGR/CSI colour codes   RabbitMQ, Spring Boot, any tty-aware app (B2)
#   <PRI> syslog prefix         container stdout relayed by a syslog driver (B1)
#   RFC 3339 nano timestamp     `docker logs --timestamps`, `kubectl logs --timestamps`
#   [pod/<name>/<container>]    `kubectl logs --prefix` (and --all-containers)

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][0-9A-Za-z]|\x1b[=>]")
_PRI = re.compile(r"^<\d{1,3}>")
# docker writes RFC3339 with fixed nanoseconds in UTC ("...:59.191271967Z");
# kubectl the same, trimming trailing zeros on a few lines. The majority test
# uses the 9-digit form: "2026-10-13T03:54:42+00:00 host kernel: ..." is
# `journalctl -o short-iso`, and an app's own "...:59.191Z" is its format.
# Not the CRI log format ("<ts> stdout F <msg>", the kubelet's on-disk files):
# there the timestamp is the format's own and the cri parser needs it.
_DOCKER_TS_STRICT = re.compile(
    r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{9}Z (?!(?:stdout|stderr) [FP] )"
)
_DOCKER_TS = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z ")
_KUBE_PREFIX = re.compile(r"^\[pod/[^\]\s]+\] ")

_SAMPLE = 200
_MAJORITY = 0.8


def _frames(lines: list[str], rx: re.Pattern[str]) -> bool:
    sample = [ln for ln in lines[:_SAMPLE] if ln.strip()]
    return bool(sample) and sum(1 for ln in sample if rx.match(ln)) >= _MAJORITY * len(sample)


def normalize(lines: list[str]) -> tuple[list[str], list[str]]:
    """Strip transport wrappers; return the lines and what was stripped."""
    done: list[str] = []
    if any("\x1b" in ln for ln in lines[:_SAMPLE]) or any("\x1b" in ln for ln in lines[-50:]):
        lines = [_ANSI.sub("", ln) if "\x1b" in ln else ln for ln in lines]
        done.append("ANSI colour codes")
    # Order matters: kubectl puts its prefix before the timestamp.
    for name, test, rx in (("kubectl --prefix column", _KUBE_PREFIX, _KUBE_PREFIX),
                           ("docker/kubectl --timestamps column", _DOCKER_TS_STRICT, _DOCKER_TS),
                           ("syslog <PRI> prefix", _PRI, _PRI)):
        if _frames(lines, test):
            lines = [rx.sub("", ln, count=1) for ln in lines]
            done.append(name)
    return lines, done
