from __future__ import annotations

from collections.abc import Generator, Iterable
from pathlib import Path

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser
from logcrux.parsers.generic import GenericParser


class CompositeParser(LogParser):
    """Several formats interleaved in one stream (B3).

    ``docker logs`` merges a container's stdout and stderr: the official nginx
    image writes access lines to one and error lines to the other, behind an
    entrypoint banner; httpd does the same. No single parser covers such a
    stream, so 0.9 parsed it as generic text and lost the HTTP status of every
    request (a 502 flood read as a "network issue"). Each line goes to the
    first member that parses it; a line none of them parses folds into the
    previous event when that event's parser calls it a continuation, and is
    otherwise kept as a generic event — so nothing is dropped.

    Never auto-detected (not in the registry): ``_parse_with_fallback`` builds
    one only when no single parser covers the file.
    """

    FORMAT_NAME = "composite"
    MIN_COVERAGE = 0.0

    def __init__(self, members: list[LogParser]) -> None:
        self.members = members
        self.generic = GenericParser()
        self.FORMAT_NAME = "+".join(m.FORMAT_NAME for m in members)  # type: ignore[misc]
        self.member_lines: dict[str, int] = {m.FORMAT_NAME: 0 for m in members}
        self.generic_lines = 0

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        for m in self.members:
            try:
                ev = m.parse_line(line, line_number)
            except Exception:
                ev = None
            if ev is not None:
                self.member_lines[m.FORMAT_NAME] += 1
                return ev
        return None

    def parse_stream(self, stream: Iterable[str]) -> Generator[ParsedEvent, None, None]:
        pending: ParsedEvent | None = None
        owner: LogParser | None = None
        for i, line in enumerate(stream, start=1):
            stripped = line.rstrip("\n")
            if not stripped.strip():
                continue
            event, parser = None, None
            for m in self.members:
                try:
                    event = m.parse_line(stripped, i)
                except Exception:
                    event = None
                if event is not None:
                    parser = m
                    self.member_lines[m.FORMAT_NAME] += 1
                    break
            if event is None and pending is not None and owner is not None \
                    and owner.is_continuation(stripped):
                pending.message = f"{pending.message}\n{stripped}"
                self.meta_lines += 1
                continue
            if event is None:
                event, parser = self.generic.parse_line(stripped, i), self.generic
                self.generic_lines += 1
            if pending is not None:
                yield pending
            pending, owner = event, parser
        if pending is not None:
            yield pending

    @property
    def specific_lines(self) -> int:
        return sum(self.member_lines.values())
