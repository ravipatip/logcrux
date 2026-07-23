from __future__ import annotations

import bz2
import gzip
import logging
import sys
import time
from datetime import UTC, timedelta
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from logcrux import __version__
from logcrux.analysis.engine import run_analysis
from logcrux.config import load_config, resolve_config_path
from logcrux.exceptions import ConfigError, PathValidationError
from logcrux.inference.engine import InferenceEngine
from logcrux.models import ParsedEvent, Severity
from logcrux.output.renderer import render_footer, render_json, render_summary
from logcrux.parsers.base import LogParser
from logcrux.parsers.generic import GenericParser
from logcrux.parsers.registry import detect_parser
from logcrux.security import parse_duration, validate_log_path
from logcrux.state.baseline import get_baseline, upsert_baseline
from logcrux.state.db import Database
from logcrux.state.history import insert_run
from logcrux.summarizer.engine import summarize

app = typer.Typer(add_completion=True, help="Fully local AI-powered Linux log analyzer.")
console = Console()
err_console = Console(stderr=True)

logger = logging.getLogger("logcrux")


@app.command()
def analyze(
    path: Annotated[
        Path | None,
        typer.Argument(help="Log file to analyze. Omit to read from stdin."),
    ] = None,
    last: Annotated[
        str | None,
        typer.Option("--last", help="Only last N time units: 30s, 10m, 2h, 1d"),
    ] = None,
    format_override: Annotated[
        str | None,
        typer.Option("--format", help="Override parser auto-detection."),
    ] = None,
    threshold: Annotated[
        float | None,
        typer.Option("--threshold", help="Min inference confidence [0.0-1.0]", min=0.0, max=1.0),
    ] = None,
    no_baseline: Annotated[
        bool,
        typer.Option("--no-baseline", help="Skip baseline comparison."),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit JSON instead of Rich output."),
    ] = False,
    config_path: Annotated[
        Path | None,
        typer.Option("--config", help="YAML config file path."),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Debug output and timing."),
    ] = False,
    version: Annotated[
        bool,
        typer.Option("--version", "-V", help="Show version and exit.", is_eager=True),
    ] = False,
) -> None:
    if version:
        console.print(f"logcrux v{__version__}")
        raise typer.Exit(0)

    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(name)s %(levelname)s %(message)s",
    )

    try:
        cfg = load_config(resolve_config_path(config_path))
    except ConfigError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)
    t0 = time.perf_counter()

    # --- Determine input source ---
    if path is None:
        if sys.stdin.isatty():
            err_console.print(
                "[red]Error:[/red] No file specified and stdin is a tty. "
                "Pass a log file or pipe input."
            )
            raise typer.Exit(1)
        stream_lines = sys.stdin.readlines()
        log_path_str = "<stdin>"
    else:
        try:
            resolved = validate_log_path(str(path), cfg.security)
        except PathValidationError as exc:
            err_console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(2)
        log_path_str = str(resolved)
        stream_lines = _read_lines(resolved)

    # --- Validate --last early (fail fast on bad input) ---
    duration = None
    if last is not None:
        try:
            duration = parse_duration(last)
        except ValueError as exc:
            err_console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(1)

    # --- Parse ---
    sample = [line.rstrip("\n") for line in stream_lines[:20]]
    file_path = path if path else None
    try:
        parser = detect_parser(file_path, sample, format_override=format_override)
    except ValueError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    events, parser = _parse_with_fallback(
        parser, stream_lines, forced=format_override is not None
    )
    if verbose:
        # stderr so it never corrupts --json output on stdout.
        err_console.print(f"[dim]Parser: {parser.FORMAT_NAME}[/dim]")

    # Count blank lines as legitimately skipped, not as data loss. Structural
    # lines the parser consumed (W3C #Fields headers, Oracle timestamp lines)
    # are tracked in parser.meta_lines and aren't data loss either.
    non_blank = sum(1 for line in stream_lines if line.strip())
    skipped = max(0, non_blank - len(events) - parser.meta_lines)

    # --- Apply --last filter on parsed timestamps ---
    if duration is not None:
        events = _filter_last(events, duration)

    # --- Baseline ---
    db_path = Path(cfg.state.db_path).expanduser()
    db: Database | None = None
    baseline = None
    try:
        db = Database(db_path)
        if not no_baseline:
            baseline = get_baseline(db, log_path_str)
    except Exception as exc:
        logger.warning("State DB unavailable: %s", exc)

    # --- Analysis ---
    analysis_result = run_analysis(
        events, parser.FORMAT_NAME, log_path_str,
        baseline=baseline, config=cfg.analysis, skipped_count=skipped,
    )

    # --- Inference ---
    # CLI --threshold overrides config; fall back to config when unset.
    effective_threshold = threshold if threshold is not None else cfg.inference.threshold
    inference_engine = InferenceEngine(enabled=cfg.inference.enabled)
    inference_result = inference_engine.run(analysis_result, threshold=effective_threshold)

    # --- Summarize ---
    elapsed = time.perf_counter() - t0
    summary = summarize(analysis_result, inference_result, elapsed_seconds=elapsed)

    # --- Update state ---
    if db is not None:
        try:
            _update_state(
                db, summary, log_path_str, parser.FORMAT_NAME,
                events, cfg.state.baseline_alpha, skipped,
            )
        except Exception as exc:
            logger.warning("State update failed: %s", exc)

    # --- Output ---
    if json_output:
        render_json(summary, console)
    else:
        # Honour output config: disable ANSI colour and/or hide remediation text.
        if not cfg.output.color:
            console.no_color = True
        render_summary(summary, console, show_remediation=cfg.output.show_remediation)
        render_footer(
            summary.parsed_count,
            len(analysis_result.signals),
            elapsed,
            __version__,
            console,
            skipped_count=skipped,
        )

    _exit_for_level(summary.level)


def _read_lines(resolved: Path) -> list[str]:
    """Read a log file's lines, transparently decompressing gzip or bz2.

    Rotated logs are gzipped (``syslog.1.gz``) or bzip2-compressed
    (``wifi.log.0.bz2`` on macOS). Reading compressed bytes as text produces
    garbage, so we detect the format by magic number and decompress accordingly.
    Decoding errors are replaced rather than raised so a stray non-UTF-8 byte
    never aborts analysis of an otherwise-readable log.
    """
    with open(resolved, "rb") as fb:
        chunk = fb.read(4096)
    if chunk[:2] == b"\x1f\x8b":
        return _read_compressed(gzip.open(resolved, "rt", errors="replace"), resolved)
    if chunk[:3] == b"BZh":
        return _read_compressed(bz2.open(resolved, "rt", errors="replace"), resolved)
    with open(resolved, encoding=_sniff_encoding(chunk), errors="replace") as f:
        return f.readlines()


def _sniff_encoding(chunk: bytes) -> str:
    """Pick a text encoding from the file's first bytes.

    Windows-exported logs are routinely UTF-16; decoding them as UTF-8 with
    errors="replace" yields NUL-riddled garbage that the generic parser happily
    "parses" — a brute-force log then reports CLEAN. Detect the UTF-16 BOM, and
    for BOM-less UTF-16 use the NUL-byte density (text logs never contain NULs,
    but every other byte of UTF-16-encoded ASCII is one). utf-8-sig transparently
    strips a UTF-8 BOM, which otherwise costs the first line its parse.
    """
    if chunk[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return "utf-16"
    if chunk and chunk.count(0) > len(chunk) // 4:
        le = chunk[1::2].count(0)
        be = chunk[0::2].count(0)
        return "utf-16-le" if le >= be else "utf-16-be"
    return "utf-8-sig"


def _read_compressed(stream: object, resolved: Path) -> list[str]:
    """Read lines from a compressed stream, salvaging what a truncated or
    corrupt archive yields before the error.

    Rotated logs get truncated by crashes and partial copies; ``readlines()``
    on such a file raises (EOFError / BadGzipFile) and previously aborted the
    whole run with no message. Analyzing the recoverable prefix — with a loud
    warning — is strictly more useful. A file that yields nothing at all is a
    hard error.
    """
    lines: list[str] = []
    try:
        with stream:  # type: ignore[attr-defined]
            for line in stream:  # type: ignore[attr-defined]
                lines.append(line)
    except (OSError, EOFError) as exc:
        if not lines:
            err_console.print(f"[red]Error:[/red] Cannot decompress {resolved}: {exc}")
            raise typer.Exit(2)
        err_console.print(
            f"[yellow]Warning:[/yellow] {resolved} is truncated or corrupt ({exc}); "
            f"analyzing the {len(lines)} recovered line(s)."
        )
    return lines


def _parse_with_fallback(
    parser: LogParser,
    stream_lines: list[str],
    *,
    forced: bool,
) -> tuple[list[ParsedEvent], LogParser]:
    """Parse with the detected parser, falling back to the generic parser
    when detection latched onto the wrong format and dropped most lines.

    A "just analyze any log" tool must never silently lose the bulk of a file
    to a misdetected service parser (e.g. a stray ``CRON`` line steering a mixed
    ``/var/log/syslog`` to the cron parser). When the detected parser covers
    less than its ``MIN_COVERAGE`` of non-blank lines, we re-parse with the generic
    parser — which never drops a non-blank line — and keep whichever recovered
    more events. ``--format`` overrides this: an explicit choice is honoured.
    """
    events = list(parser.parse_stream(iter(stream_lines)))
    if forced or isinstance(parser, GenericParser):
        return events, parser

    non_blank = sum(1 for line in stream_lines if line.strip())
    effective_min = parser.MIN_COVERAGE
    # Structural lines the parser consumed (headers, directive lines) count
    # toward coverage: a small W3C log where #Fields headers are a large
    # fraction of the file must not be handed to the generic parser, which
    # would lose the status→severity mapping.
    covered = len(events) + parser.meta_lines
    if non_blank == 0 or covered >= non_blank * effective_min:
        return events, parser

    generic = GenericParser()
    generic_events = list(generic.parse_stream(iter(stream_lines)))
    if len(generic_events) > len(events):
        logger.warning(
            "Parser %r covered only %d/%d lines; falling back to generic parser.",
            parser.FORMAT_NAME, len(events), non_blank,
        )
        return generic_events, generic
    return events, parser


def _filter_last(events: list[ParsedEvent], duration: timedelta) -> list[ParsedEvent]:
    """Keep events within `duration` of now.

    Filtering happens on parser-extracted timestamps rather than raw lines, so
    every supported format benefits from the parser's format-specific timestamp
    logic. Naive timestamps (e.g. syslog) are treated as UTC, matching how the
    analysis engine normalizes them. Events without a timestamp are kept, since
    we cannot place them in time and dropping them could discard real signals.
    """
    from datetime import datetime

    cutoff = datetime.now(UTC) - duration
    result = []
    for e in events:
        ts = e.timestamp
        if ts is None:
            result.append(e)
            continue
        ts_utc = ts.astimezone(UTC) if ts.tzinfo is not None else ts.replace(tzinfo=UTC)
        if ts_utc >= cutoff:
            result.append(e)
    return result


def _update_state(
    db: Database,
    summary: object,
    log_path: str,
    parser_format: str,
    events: list[ParsedEvent],
    alpha: float,
    skipped_count: int = 0,
) -> None:
    import numpy as np

    from logcrux.models import IncidentSummary
    assert isinstance(summary, IncidentSummary)
    insert_run(db, summary, parser_format=parser_format, skipped_count=skipped_count)
    # Strip tzinfo so naive and aware timestamps can be compared/sorted together.
    timed = sorted(
        (e for e in events if e.timestamp is not None),
        key=lambda e: e.timestamp.replace(tzinfo=None),  # type: ignore[union-attr]
    )
    if timed:
        ts = [e.timestamp.replace(tzinfo=None) for e in timed]  # type: ignore[union-attr]
        duration_hours = max(
            (ts[-1] - ts[0]).total_seconds() / 3600,
            1 / 3600,
        )
        errors = [e for e in timed if e.severity in (Severity.ERROR, Severity.CRITICAL)]
        window = timedelta(minutes=5)
        # Forward sliding-window event counts via a two-pointer sweep. ``ts`` is
        # sorted, so the right edge only ever advances — O(n) overall. A naive
        # ``sum(... for t in ts[i:])`` is O(n²) and made baseline updates hang on
        # large logs (~26s for 40k events; minutes for 100k).
        n = len(ts)
        window_counts = []
        right = 0
        for i in range(n):
            cutoff = ts[i] + window
            if right < i:
                right = i
            while right < n and ts[right] <= cutoff:
                right += 1
            window_counts.append(right - i)
        p95 = float(np.percentile(window_counts, 95)) if window_counts else 1.0
        upsert_baseline(
            db,
            log_path,
            parser_format,
            avg_events_per_hour=len(timed) / duration_hours,
            avg_errors_per_hour=len(errors) / duration_hours,
            p95_burst_size=p95,
            alpha=alpha,
        )


def _exit_for_level(level: str) -> None:
    codes = {"CLEAN": 0, "INFO": 3, "WARNING": 3, "CRITICAL": 4}
    raise typer.Exit(codes.get(level, 0))


if __name__ == "__main__":  # pragma: no cover — `python -m logcrux.cli`
    app()
