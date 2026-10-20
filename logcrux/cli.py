from __future__ import annotations

import bz2
import gzip
import json
import logging
import re
import sys
import time
from datetime import UTC, timedelta
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from rich.console import Console

from logcrux import __version__
from logcrux.analysis.engine import run_analysis
from logcrux.config import load_config, resolve_config_path
from logcrux.exceptions import ConfigError, PathValidationError
from logcrux.inference.engine import InferenceEngine
from logcrux.ingest.normalize import normalize
from logcrux.models import Coverage, IncidentSummary, ParsedEvent, Severity
from logcrux.output.renderer import (
    render_checked,
    render_footer,
    render_json,
    render_overview,
    render_summary,
)
from logcrux.parsers.base import LogParser
from logcrux.parsers.composite import CompositeParser
from logcrux.parsers.generic import GenericParser
from logcrux.parsers.registry import detect_parser, redetect_candidates
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
    paths: Annotated[
        list[Path] | None,
        typer.Argument(
            help="Log file(s) or directories to analyze. Omit to read from stdin.",
            metavar="[PATH]...",
            # Our own checks (security.validate_log_path) say what to do about
            # an unreadable log; Click's would print "Invalid value for PATH".
            exists=False, readable=False,
        ),
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
        typer.Option("--verbose", "-v", help="Debug output, timing and all evidence."),
    ] = False,
    version: Annotated[
        bool,
        typer.Option("--version", "-V", help="Show version and exit.", is_eager=True),
    ] = False,
    fail_on: Annotated[
        str,
        typer.Option("--fail-on", help="Lowest level that exits non-zero: warning (default), "
                     "critical, or never. For CI gates."),
    ] = "warning",
    doctor: Annotated[
        bool,
        typer.Option("--doctor", help="Check this installation (models, state DB) and exit."),
    ] = False,
) -> None:
    if version:
        console.print(f"logcrux v{__version__}")
        raise typer.Exit(0)
    if doctor:
        raise typer.Exit(_doctor(config_path))
    global _FAIL_ON
    if fail_on not in ("warning", "critical", "never"):
        err_console.print(f"[red]Error:[/red] --fail-on must be warning, critical or never, "
                          f"not {fail_on!r}")
        raise typer.Exit(1)
    _FAIL_ON = fail_on

    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(name)s %(levelname)s %(message)s",
    )

    try:
        cfg = load_config(resolve_config_path(config_path))
    except ConfigError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    # --- Validate --last early (fail fast on bad input) ---
    duration = None
    if last is not None:
        try:
            duration = parse_duration(last)
        except ValueError as exc:
            err_console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(1)

    run = _Run(cfg=cfg, last=last, duration=duration, format_override=format_override,
               threshold=threshold, no_baseline=no_baseline, verbose=verbose)

    # --- Determine input source ---
    if paths and [str(p) for p in paths] == ["-"]:
        paths = None  # `logcrux -`: stdin, by the usual convention
    if not paths:
        if sys.stdin.isatty():
            err_console.print(
                "[red]Error:[/red] No file specified and stdin is a tty. "
                "Pass a log file or pipe input."
            )
            raise typer.Exit(1)
        stdin_text = sys.stdin.buffer.read().decode("utf-8", errors="replace")
        summary = run.analyze(_split_lines(stdin_text.replace("\r\n", "\n")), "<stdin>", None)
        _emit_one(summary, run, json_output)
        _exit_for_level(summary.level)

    files, skipped_notes = _expand_paths(paths, cfg)
    if len(files) == 1 and len(paths) == 1 and not paths[0].is_dir():
        summary = run.analyze(_read_lines(files[0]), str(files[0]), paths[0])
        _emit_one(summary, run, json_output)
        _exit_for_level(summary.level)

    if not files:
        for note in skipped_notes:
            err_console.print(f"[yellow]Skipped:[/yellow] {note}")
        err_console.print("[red]Error:[/red] No readable text log files to analyze.")
        raise typer.Exit(2)

    summaries = []
    for f in files:
        try:
            lines = _read_lines(f)
        except typer.Exit:
            skipped_notes.append(f"{f}: cannot be read as a text log")
            continue
        summaries.append(run.analyze(lines, str(f), f))
    if json_output:
        console.file.write(json.dumps(
            [s.model_dump(mode="json") for s in summaries], default=str, indent=2) + "\n")
    else:
        for s in summaries:
            if s.level != "CLEAN" or verbose:
                console.print(f"\n[bold]{s.log_path}[/bold]", highlight=False, soft_wrap=True)
                _emit_one(s, run, json_output=False)
        render_overview(summaries, console)
        denied = [n for n in skipped_notes if n.startswith("Permission denied: ")]
        for note in skipped_notes:
            if note not in denied:
                err_console.print(f"[dim]Skipped: {note}[/dim]")
        if denied:
            names = ", ".join(Path(n.split(": ", 1)[1]).name for n in denied[:8])
            more = f" and {len(denied) - 8} more" if len(denied) > 8 else ""
            err_console.print(
                f"[yellow]⚠ {len(denied)} file(s) not readable by this user were skipped "
                f"({names}{more}). Run with sudo to include them.[/yellow]")
    worst = max(summaries, key=lambda s: _LEVEL_RANK[s.level]) if summaries else None
    _exit_for_level(worst.level if worst else "CLEAN")


def _doctor(config_path: Path | None) -> int:
    """What a user (or a bug report) needs to know about this install."""
    import platform

    from logcrux.parsers.registry import _PARSERS

    ok = True

    def row(name: str, good: bool, detail: str) -> None:
        nonlocal ok
        ok = ok and good
        mark = "[green]ok[/green]  " if good else "[yellow]warn[/yellow]"
        console.print(f"  {mark} {name:<14} {detail}", highlight=False)

    console.print(f"logcrux v{__version__}")
    row("python", sys.version_info >= (3, 11),
        f"{platform.python_version()} ({sys.executable})")
    row("platform", True, f"{platform.system()} {platform.machine()} {platform.libc_ver()[1]}")
    row("parsers", len(_PARSERS) > 0, f"{len(_PARSERS)} registered")
    try:
        cfg = load_config(resolve_config_path(config_path))
        row("config", True, str(resolve_config_path(config_path) or "defaults"))
    except ConfigError as exc:
        row("config", False, str(exc))
        return 1
    try:
        import onnxruntime  # noqa: F401

        engine = InferenceEngine(enabled=True)
        engine._ensure_loaded()
        row("ai models", True, f"loaded (onnxruntime {onnxruntime.__version__})")
    except ImportError:
        row("ai models", False, "onnxruntime not installed: detection works, incident naming "
            "is less precise. Fix: uv tool install --reinstall --python 3.12 logcrux")
    except Exception as exc:
        row("ai models", False, f"failed to load: {exc}")
    db_path = Path(cfg.state.db_path).expanduser()
    try:
        Database(db_path)
        row("state db", True, f"{db_path} (baselines)")
    except Exception as exc:
        row("state db", False, f"{db_path}: {exc} — baselines disabled, analysis unaffected")
    console.print("All good." if ok else "Usable, with the warnings above.")
    return 0


_LEVEL_RANK = {"CLEAN": 0, "INFO": 1, "WARNING": 2, "CRITICAL": 3}


def _emit_one(summary: IncidentSummary, run: _Run, json_output: bool) -> None:
    if json_output:
        render_json(summary, console)
        return
    # Honour output config: disable ANSI colour and/or hide remediation text.
    if not run.cfg.output.color:
        console.no_color = True
    render_summary(summary, console, show_remediation=run.cfg.output.show_remediation,
                   verbose=run.verbose)
    render_checked(summary, console)
    render_footer(
        summary.parsed_count,
        summary.signal_count,
        summary.elapsed_seconds,
        __version__,
        console,
        skipped_count=summary.skipped_count,
    )


# Files in a directory that are never text logs: login accounting, binary
# journals, archives logcrux cannot open, and editor/OS litter.
_NOT_LOGS = re.compile(
    r"(?:^|/)(?:wtmp|btmp|utmp|lastlog|faillog)(?:\.\d+)?$|\.(?:journal~?|zst|xz|lz4|zip|tar"
    r"|db|sqlite|pid|lock|swp)$|(?:^|/)\.DS_Store$"
    # Documents, data and config that sit next to logs (a directory run once
    # "analysed" a lab's EXPECTATIONS.tsv label file and flagged it). Named
    # explicitly, any of these is still analysed.
    r"|\.(?:md|rst|tsv|csv|ya?ml|toml|ini|conf|cfg|xml|html?|py|sh|js|ts|go|rb|pem|crt|key)$",
    re.I,
)


def _expand_paths(paths: list[Path], cfg: object) -> tuple[list[Path], list[str]]:
    """Resolve files and directories (one level deep) to analyzable files.

    A single path keeps 0.9's behaviour exactly — errors exit 2. With several
    paths or a directory, an unreadable or binary member is reported and
    skipped so one bad file does not hide the others."""
    from logcrux.config import LogcruxConfig
    assert isinstance(cfg, LogcruxConfig)
    single = len(paths) == 1 and not paths[0].is_dir()
    files: list[Path] = []
    notes: list[str] = []
    for p in paths:
        if p.is_dir():
            members = sorted(c for c in p.iterdir() if c.is_file() and not c.name.startswith("."))
            if not members:
                notes.append(f"{p}: directory has no files")
        else:
            members = [p]
        for m in members:
            if p.is_dir() and _NOT_LOGS.search(str(m)):
                notes.append(f"{m}: not a log file")
                continue
            try:
                resolved = validate_log_path(str(m), cfg.security)
            except PathValidationError as exc:
                if single:
                    hint = ""
                    if str(exc).startswith("Permission denied"):
                        hint = (" System logs are usually readable only by root: run it "
                                "with sudo (or see README, Permissions).")
                    err_console.print(f"[red]Error:[/red] {exc}.{hint}")
                    raise typer.Exit(2)
                notes.append(str(exc))
                continue
            if not single and _looks_binary(resolved):
                notes.append(f"{resolved}: binary file, not a text log")
                continue
            # A directory member is shown under the directory the user named,
            # not where a symlink leads (/var/log/README -> /usr/share/doc/...).
            files.append(resolved if single or not p.is_dir() else m.absolute())
    return files, notes


# What journalctl prints instead of the journal for a user without access
# (real Ubuntu/Debian/RHEL/SLES VMs, 2026-10-20). Piped into 0.9 it was a
# confident CLEAN of 4 lines.
_JOURNAL_DENIED = (
    "No journal files were opened due to insufficient permissions",
    "You are currently not seeing messages from other users and the system",
    "No journal files were found",
)


class _Run:
    """One invocation's settings, applied to each input in turn."""

    def __init__(self, *, cfg: object, last: str | None, duration: timedelta | None,
                 format_override: str | None, threshold: float | None,
                 no_baseline: bool, verbose: bool) -> None:
        from logcrux.config import LogcruxConfig
        assert isinstance(cfg, LogcruxConfig)
        self.cfg = cfg
        self.last = last
        self.duration = duration
        self.format_override = format_override
        self.threshold = threshold
        self.no_baseline = no_baseline
        self.verbose = verbose

    def analyze(self, stream_lines: list[str], log_path_str: str,
                file_path: Path | None) -> IncidentSummary:
        cfg = self.cfg
        t0 = time.perf_counter()
        given = stream_lines
        # A log truncated by a crash is often NUL-padded to its block size;
        # NULs are never log content and break every line-shape regex.
        if any("\x00" in line for line in stream_lines[:50]) or (
                stream_lines and "\x00" in stream_lines[-1]):
            stream_lines = [line.replace("\x00", "") for line in stream_lines]

        stream_lines, stripped = normalize(stream_lines)
        if stripped and self.verbose:
            err_console.print(f"[dim]Stripped: {', '.join(stripped)}[/dim]")

        # --- Parse ---
        sample = [line.rstrip("\n") for line in stream_lines[:20]]
        try:
            parser = detect_parser(file_path, sample, format_override=self.format_override)
        except ValueError as exc:
            err_console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(1)

        events, parser = _parse_with_fallback(
            parser, stream_lines, forced=self.format_override is not None
        )
        if self.verbose:
            # stderr so it never corrupts --json output on stdout.
            err_console.print(f"[dim]Parser: {parser.FORMAT_NAME}[/dim]")

        # Count blank lines as legitimately skipped, not as data loss. Structural
        # lines the parser consumed (W3C #Fields headers, Oracle timestamp lines)
        # are tracked in parser.meta_lines and aren't data loss either.
        non_blank = sum(1 for line in stream_lines if line.strip())
        skipped = max(0, non_blank - len(events) - parser.meta_lines)

        notes: list[str] = []
        head = "\n".join(stream_lines[:12])
        # The events now hold everything analysis needs. Release the input
        # lines (the caller's list too: normalising may have made a copy), or
        # a large log is held in memory twice through the whole analysis.
        given.clear()
        stream_lines.clear()
        if any(marker in head for marker in _JOURNAL_DENIED):
            notes.append(
                "This input is journalctl's permission notice, not the system journal: "
                "the user running journalctl may only see their own messages. Re-run "
                "with sudo, or join the systemd-journal (or adm) group and log in again."
            )
        if non_blank == 0:
            notes.append(
                "No log lines were read: the input is empty. If you piped journalctl or "
                "a root-only file, check permissions (e.g. run with sudo, or join the "
                "systemd-journal group)."
            )
        elif isinstance(parser, GenericParser) and self.format_override is None:
            notes.append(
                "No specific log format recognised; analysed as generic text "
                "(timestamps and severity keywords only). Use --format to force one."
            )

        # --- Apply --last filter on parsed timestamps ---
        if self.duration is not None:
            before = len(events)
            events = _filter_last(events, self.duration)
            if before and not events:
                notes.append(
                    f"--last {self.last} kept none of the {before:,} events: the log's "
                    "timestamps are all older than that."
                )

        # --- Baseline ---
        db_path = Path(cfg.state.db_path).expanduser()
        db: Database | None = None
        baseline = None
        try:
            db = Database(db_path)
            if not self.no_baseline:
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
        effective_threshold = (self.threshold if self.threshold is not None
                               else cfg.inference.threshold)
        inference_engine = InferenceEngine(enabled=cfg.inference.enabled)
        inference_result = inference_engine.run(analysis_result, threshold=effective_threshold)

        # --- Summarize ---
        elapsed = time.perf_counter() - t0
        summary = summarize(analysis_result, inference_result, elapsed_seconds=elapsed)
        covered = max(0, non_blank - skipped)
        summary.coverage = Coverage(
            lines=non_blank, parsed=covered, unparsed=skipped,
            ratio=round(covered / non_blank, 4) if non_blank else 0.0,
        )
        summary.warnings = notes
        summary.signal_count = len(analysis_result.signals)

        # --- Update state ---
        if db is not None:
            try:
                _update_state(
                    db, summary, log_path_str, parser.FORMAT_NAME,
                    events, cfg.state.baseline_alpha, skipped,
                )
            except Exception as exc:
                logger.warning("State update failed: %s", exc)
        return summary


def _looks_binary(resolved: Path) -> bool:
    """True for files that are not text logs (wtmp, a .journal, an image).

    UTF-16 is text (see _sniff_encoding); compressed files are read through
    gzip/bz2. Anything else whose first 4 KiB is mostly undecodable bytes or
    control characters is binary — analysing it "succeeds" with a meaningless
    CLEAN, which is worse than refusing.
    """
    with open(resolved, "rb") as fb:
        chunk = fb.read(4096)
    if not chunk or chunk[:2] == b"\x1f\x8b" or chunk[:3] == b"BZh":
        return False
    if _sniff_encoding(chunk) != "utf-8-sig":
        return False
    # NUL padding from a crash is one or two long runs; binary records (wtmp,
    # journal objects) pad every field, so NUL runs are many and short.
    if len(re.findall(rb"\x00+", chunk)) > 8:
        return True
    text = chunk.replace(b"\x00", b"").decode("utf-8", errors="replace")
    if not text:
        return True
    bad = sum(1 for c in text if c == "\ufffd" or (ord(c) < 32 and c not in "\t\n\r\x1b\x0c"))
    return bad > 0.3 * len(text)


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
    if _looks_binary(resolved):
        hint = ""
        if resolved.name.endswith((".journal", ".journal~")):
            hint = f" For a systemd journal file use: journalctl --file {resolved} | logcrux"
        elif re.search(r"(?:^|/)[bw]tmp(?:\.\d+)?$", str(resolved)):
            hint = " For login records use: last -f " + str(resolved) + " | logcrux"
        err_console.print(f"[red]Error:[/red] {resolved} is a binary file, not a text log.{hint}")
        raise typer.Exit(2)
    if chunk[:2] == b"\x1f\x8b":
        return _read_compressed(gzip.open(resolved, "rt", errors="replace"), resolved)
    if chunk[:3] == b"BZh":
        return _read_compressed(bz2.open(resolved, "rt", errors="replace"), resolved)
    with open(resolved, encoding=_sniff_encoding(chunk), errors="replace") as f:
        return [ln[:-1] if ln.endswith("\n") else ln for ln in f]


def _split_lines(text: str) -> list[str]:
    """Lines without their newline. Parsers strip it anyway, and a line kept
    with it made every event's ``raw`` a second copy of the line (rstrip
    copies): about a sixth of peak memory on a large log. Only "\n" splits —
    str.splitlines() would also split on form feeds and U+2028 and shift
    every later line number."""
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


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
        # UTF-16 ASCII puts its NULs on one parity only. A log NUL-padded by a
        # crash (zeros on both parities) is UTF-8 with junk, not UTF-16 —
        # decoding it as UTF-16 turned a real brute-force log CLEAN.
        half = len(chunk) // 2
        if max(le, be) > 0.4 * half and min(le, be) < 0.1 * half:
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
                lines.append(line[:-1] if line.endswith("\n") else line)
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
    if forced:
        return events, parser
    non_blank = sum(1 for line in stream_lines if line.strip())
    if isinstance(parser, GenericParser):
        # The head looked like nothing in particular (an entrypoint banner,
        # a stack trace) — the body may still be a known format, or several.
        mixed = _composite(stream_lines, non_blank, None, 0)
        return mixed if mixed is not None else (events, parser)

    effective_min = parser.MIN_COVERAGE
    # Structural lines the parser consumed (headers, directive lines) count
    # toward coverage: a small W3C log where #Fields headers are a large
    # fraction of the file must not be handed to the generic parser, which
    # would lose the status→severity mapping.
    covered = len(events) + parser.meta_lines - parser.fallback_lines
    if non_blank == 0 or covered >= non_blank * _MIXED_TRIGGER:
        return events, parser
    if covered >= non_blank * effective_min:
        # Good enough for this parser, but a tenth or more of the file is
        # something else — on `docker logs` of httpd, every access line.
        mixed = _composite(stream_lines, non_blank, parser, covered)
        if mixed is None:
            # No better mix: keep the parser and the lines it cannot read as
            # generic events, instead of dropping them. httpd's own
            # "consider raising the MaxRequestWorkers setting" error sat in
            # the 27% an access parser skipped (lab/apps8) and was never seen.
            mixed = _composite(stream_lines, non_blank, parser, covered, keep_rest=True)
        return mixed if mixed is not None else (events, parser)

    # Low coverage usually means detection latched onto an atypical head (B4):
    # a boot journal opens with hundreds of ``kernel:`` lines, so ``kernel``
    # wins the 20-line sample and then covers half the file. Before giving up to
    # generic — which keeps every line but loses all structure — re-detect on
    # windows across the whole file and keep the candidate with the best
    # measured coverage, if it clears its own MIN_COVERAGE (B5).
    best: tuple[list[ParsedEvent], LogParser] | None = None
    floor = covered / non_blank
    best_key: tuple[int, float] = (0, floor)
    best_cov = floor
    for cls, windows in redetect_candidates(stream_lines, type(parser)):
        cand = cls()
        cand_events = list(cand.parse_stream(iter(stream_lines)))
        cov = (len(cand_events) + cand.meta_lines - cand.fallback_lines) / non_blank
        # Breadth first (how much of the file looks like this format), then
        # coverage — see redetect_candidates.
        if cov >= cand.MIN_COVERAGE and cov > floor and (windows, cov) > best_key:
            best, best_key, best_cov = (cand_events, cand), (windows, cov), cov
    if best is not None:
        logger.info(
            "Parser %r covered only %d/%d lines; re-detected as %r (%.0f%% coverage).",
            parser.FORMAT_NAME, covered, non_blank, best[1].FORMAT_NAME, 100 * best_cov,
        )
        if best_cov < _MIXED_TRIGGER:
            # The re-detected parser still leaves lines out: mix in what else
            # claims them, or at least keep them as generic events.
            best_covered = round(best_cov * non_blank)
            mixed = _composite(stream_lines, non_blank, best[1], best_covered) or \
                _composite(stream_lines, non_blank, best[1], best_covered, keep_rest=True)
            if mixed is not None:
                return mixed
        return best

    # The alternative now is generic for every line, so the detected parser
    # keeping the lines it does parse (the rest generic) is strictly better —
    # postgres behind its image's initdb banner, for one.
    mixed = _composite(stream_lines, non_blank, parser, covered, fallback=True)
    if mixed is not None:
        return mixed

    generic = GenericParser()
    generic_events = list(generic.parse_stream(iter(stream_lines)))
    if len(generic_events) > len(events):
        logger.info(
            "Parser %r covered only %d/%d lines; falling back to generic parser.",
            parser.FORMAT_NAME, len(events), non_blank,
        )
        return generic_events, generic
    return events, parser


# A parser covering less than this share of a file gets a chance to share it.
_MIXED_TRIGGER = 0.9
# A composite must parse at least this much of the file with real parsers,
# and beat the single parser by this margin, or it is not worth the switch.
_MIXED_MIN = 0.4
_MIXED_GAIN = 0.1
# Instead of generic for everything, a parser keeps its lines if it parses this.
_MIXED_FALLBACK_MIN = 0.2
_GENERIC_SHAPED = frozenset({"gostdlib", "pylogging", "logfmt", "pip"})
# Coverage of each candidate is measured on at most this many lines.
_MIXED_SAMPLE = 20000


def _composite(
    stream_lines: list[str], non_blank: int, first: LogParser | None, covered: int,
    *, fallback: bool = False, keep_rest: bool = False,
) -> tuple[list[ParsedEvent], LogParser] | None:
    """Parse a stream that interleaves formats with the parsers that claim
    regions of it (B3) — see CompositeParser. Returns None when no
    combination parses enough more of the file than ``first`` alone."""
    if non_blank == 0:
        return None
    if keep_rest and first is not None:
        comp = CompositeParser([type(first)()])
        events = list(comp.parse_stream(iter(stream_lines)))
        names = [first.FORMAT_NAME]
        if comp.generic_lines >= _MIXED_GAIN * non_blank:
            names.append("generic")
        comp.FORMAT_NAME = "+".join(names)  # type: ignore[misc]
        return events, comp
    exclude = type(first) if first is not None else GenericParser
    claimed = redetect_candidates(stream_lines, exclude)
    if not claimed and first is None:
        return None
    sample = stream_lines
    if len(stream_lines) > _MIXED_SAMPLE:
        step = len(stream_lines) // _MIXED_SAMPLE + 1
        sample = stream_lines[::step]
    sample_nb = sum(1 for line in sample if line.strip()) or 1

    def share(cls: type[LogParser]) -> float:
        probe = cls()
        n = sum(1 for i, line in enumerate(sample, 1)
                if line.strip() and _safe_parse(probe, line.rstrip("\n"), i))
        return n / sample_nb

    ranked: list[tuple[float, type[LogParser]]] = []
    if first is not None:
        ranked.append((covered / non_blank, type(first)))
    for cls, _windows in claimed:
        cov = share(cls)
        # A member that "parses" nearly every line of a mixed stream accepts
        # what is not its format (pip takes any line); it would also have won
        # the single-parser re-detect already.
        if 0.02 <= cov < 0.98:
            ranked.append((cov, cls))
    # Parsers of a generic line shape go last, so the format's own parser
    # claims its lines first (Go's "2006/01/02 15:04:05 msg" is also nginx's
    # error-log timestamp).
    # On a tie, the detected parser's family wins: httpd's access lines are
    # the combined format nginx-access also reads.
    family = first.FORMAT_NAME.split("-", 1)[0] if first is not None else ""
    ranked.sort(key=lambda t: (t[1].FORMAT_NAME in _GENERIC_SHAPED, -round(t[0], 3),
                               not (family and t[1].FORMAT_NAME.startswith(family))))
    members = [cls() for _cov, cls in ranked[:3]]
    if not members:
        return None
    comp = CompositeParser(members)
    events = list(comp.parse_stream(iter(stream_lines)))
    specific = comp.specific_lines + comp.meta_lines
    # Name only the members that ended up owning lines.
    names = [m.FORMAT_NAME for m in members if comp.member_lines[m.FORMAT_NAME]]
    if comp.generic_lines >= _MIXED_GAIN * non_blank:
        names.append("generic")
    comp.FORMAT_NAME = "+".join(names) or "generic"  # type: ignore[misc]
    if fallback:
        if specific < _MIXED_FALLBACK_MIN * non_blank:
            return None
    elif specific < _MIXED_MIN * non_blank or specific < covered + _MIXED_GAIN * non_blank:
        return None
    if not fallback and len(members) == 1 and first is not None \
            and type(members[0]) is type(first):
        return None
    logger.info("Mixed stream: %s parse %d/%d lines; the rest kept as generic.",
                comp.FORMAT_NAME, specific, non_blank)
    return events, comp


def _safe_parse(parser: LogParser, line: str, n: int) -> bool:
    try:
        return parser.parse_line(line, n) is not None
    except Exception:
        return False


def _filter_last(events: list[ParsedEvent], duration: timedelta) -> list[ParsedEvent]:
    """Keep events within `duration` of now.

    Filtering happens on parser-extracted timestamps rather than raw lines, so
    every supported format benefits from the parser's format-specific timestamp
    logic. Naive timestamps (e.g. syslog) are read as host-local time, which is
    how they were written. Events without a timestamp are kept, since
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
        # A timestamp without an offset (RFC 3164 syslog, most app logs) was
        # written in the host's local time; astimezone() reads a naive value
        # as local. Treating it as UTC skewed --last by the UTC offset: in
        # Sydney `--last 1h` kept 3 h of a local-time log, west of UTC it kept
        # nothing.
        ts_utc = ts.astimezone(UTC)
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


_FAIL_ON = "warning"


def _exit_for_level(level: str) -> NoReturn:
    codes = {"CLEAN": 0, "INFO": 3, "WARNING": 3, "CRITICAL": 4}
    code = codes.get(level, 0)
    if _FAIL_ON == "never" or (_FAIL_ON == "critical" and code != 4):
        code = 0
    raise typer.Exit(code)


if __name__ == "__main__":  # pragma: no cover — `python -m logcrux.cli`
    app()
