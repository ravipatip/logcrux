from __future__ import annotations

from pathlib import Path

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser
from logcrux.parsers.cri import parse_cri_line
from logcrux.parsers.docker import parse_docker_json_line


class KubernetesParser(LogParser):
    """Parses Kubernetes pod logs stored at /var/log/pods/<ns>_<pod>_<uid>/<container>/*.log.

    Two on-disk shapes exist depending on the container runtime: the CRI format
    (containerd / CRI-O — the default since dockershim was removed in k8s 1.24)
    and the legacy Docker json-file format (older clusters). We try CRI first,
    then fall back to Docker JSON, tagging the source 'kubernetes' either way.
    """

    FORMAT_NAME = "kubernetes"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "/var/log/pods/" in str(path):
            return True
        if path and "k8s" in str(path).lower():
            return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        return parse_cri_line(line, line_number, "kubernetes") or parse_docker_json_line(
            line, line_number, "kubernetes"
        )
