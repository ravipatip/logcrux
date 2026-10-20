from __future__ import annotations

import json

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from logcrux.models import EvidenceLine, Finding, IncidentSummary

_LEVEL_COLORS = {
    "CRITICAL": "bold red",
    "WARNING": "bold yellow",
    "INFO": "bold blue",
    "CLEAN": "bold green",
}


# How much proof the terminal view shows. JSON always carries all of it.
_TEXT_FINDINGS_WITH_EVIDENCE = 3
_TEXT_EVIDENCE_LINES = 2


def _fmt_span(f: Finding) -> str:
    if f.first_seen is None or f.last_seen is None:
        return ""
    a, b = f.first_seen, f.last_seen
    if (b - a).total_seconds() < 1:
        return f"at {a:%Y-%m-%d %H:%M:%S}"
    end = f"{b:%H:%M:%S}" if a.date() == b.date() else f"{b:%Y-%m-%d %H:%M:%S}"
    return f"{a:%Y-%m-%d %H:%M:%S} → {end} ({_fmt_duration((b - a).total_seconds())})"


def _fmt_duration(seconds: float) -> str:
    s = int(round(seconds))
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m{s % 60:02d}s"
    if s < 86400:
        return f"{s // 3600}h{(s % 3600) // 60:02d}m"
    return f"{s // 86400}d{(s % 86400) // 3600:02d}h"


def _subject_lines(f: Finding) -> list[str]:
    """``source: 203.0.113.9 ×140, 198.51.100.7 ×4 · user: root ×40`` — and
    recurring message templates one per line, since each is a sentence."""
    groups: dict[str, list[str]] = {}
    templates: list[str] = []
    for sub in f.subjects:
        if sub.label == "message" and sub.count == 1:
            continue  # a one-off message is already shown as an evidence line
        if sub.label == "message":
            templates.append(f"×{sub.count:<5} {sub.value}")
        else:
            groups.setdefault(sub.label, []).append(f"{sub.value} ×{sub.count}")
    out = []
    if groups:
        out.append(" · ".join(f"{label}: {', '.join(vals)}" for label, vals in groups.items()))
    out += templates
    return out


def render_summary(
    summary: IncidentSummary, console: Console, show_remediation: bool = True,
    verbose: bool = False,
) -> None:
    color = _LEVEL_COLORS.get(summary.level, "white")
    header = Text()
    header.append(f"  {summary.level}  ", style=f"reverse {color}")
    header.append(f"  {summary.title}")

    body = Text()
    for i, finding in enumerate(summary.findings):
        if i:
            body.append("\n")
        body.append(f"● {finding.headline}", style="bold")
        if finding.detail:
            body.append(f"  ({finding.detail})")
        span = _fmt_span(finding)
        if span:
            body.append(f"\n    {span}", style="dim")
        if not verbose and i >= _TEXT_FINDINGS_WITH_EVIDENCE:
            continue
        for line in _subject_lines(finding):
            body.append(f"\n    {line if verbose else _clip(line, max(40, console.width - 10))}",
                        style="cyan")
        shown = finding.evidence if verbose else finding.evidence[:_TEXT_EVIDENCE_LINES]
        for ev in shown:
            prefix = f"line {ev.line}: "
            body.append(f"\n    {prefix}", style="dim")
            text = ev.text if verbose else _short(ev)
            body.append(text if verbose else
                        _clip(text, max(30, console.width - len(prefix) - 9)))

    if summary.confidence > 0 and summary.level != "CLEAN":
        body.append(f"\n\nConfidence: {summary.confidence:.0%}", style="dim")

    if summary.remediation and show_remediation:
        body.append("\n\nRemediation: ", style="bold")
        body.append(summary.remediation)

    if not body.plain:
        body.append(_clean_detail(summary))
        if summary.last_error is not None:
            le = summary.last_error
            body.append(f"\nLast line logged is an error (line {le.line}): ", style="yellow")
            body.append(_clip(_short(le), max(30, console.width - 44)))
    console.print(Panel(body, title=header, border_style=color.replace("bold ", ""),
                        padding=(0, 1)))
    for w in summary.warnings:
        console.print(f"[yellow]⚠ {w}[/yellow]")


def _short(ev: EvidenceLine) -> str:
    """The evidence line without its timestamp/hostname prefix, which on a
    journal line eats the whole terminal width before the message starts."""
    if not ev.message:
        return ev.text
    src = ev.source if ev.source and ev.source not in ("generic", "unknown") else ""
    if src and not ev.message.startswith(src):
        return f"{src}: {ev.message}"
    return ev.message


def _clip(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 1] + "…"


def _clean_detail(summary: IncidentSummary) -> str:
    """A clean verdict must say what was checked, or it reads as "didn't work"."""
    errors = summary.severity_counts.get("error", 0) + summary.severity_counts.get("critical", 0)
    warnings = summary.severity_counts.get("warning", 0)
    if summary.parsed_count == 0:
        return "Nothing to analyze: no log lines were read."
    if errors or warnings:
        return (f"{errors:,} error and {warnings:,} warning line(s) seen; none formed an "
                "incident (no burst, crash, OOM, auth attack, disk, storage, policy or job "
                "failure).")
    return "No error or warning lines; no crash, OOM, auth, disk or job failure found."


def render_checked(summary: IncidentSummary, console: Console) -> None:
    """One line saying what logcrux looked at: format, coverage, time span."""
    n = summary.parsed_count
    parts = [f"{n:,} event{'s' if n != 1 else ''} as [bold]{summary.parser_format}[/bold]"]
    cov = summary.coverage
    if cov is not None and cov.lines:
        note = f"{cov.ratio:.0%} of {cov.lines:,} lines parsed"
        parts.append(f"[yellow]{note}[/yellow]" if cov.ratio < 0.9 else note)
    tr = summary.time_range
    if tr is not None:
        same_day = tr.start.date() == tr.end.date()
        end = f"{tr.end:%H:%M:%S}" if same_day else f"{tr.end:%Y-%m-%d %H:%M:%S}"
        parts.append(f"{tr.start:%Y-%m-%d %H:%M:%S} → {end} ({_fmt_duration(tr.duration_seconds)})")
    else:
        parts.append("no timestamps")
    sc = summary.severity_counts
    errors = sc.get("error", 0) + sc.get("critical", 0)
    parts.append(f"{errors:,} error · {sc.get('warning', 0):,} warning")
    console.print("Checked " + "  │  ".join(parts), style="dim", highlight=False)


def render_json(summary: IncidentSummary, console: Console) -> None:
    data = summary.model_dump(mode="json")
    console.file.write(json.dumps(data, default=str, indent=2) + "\n")


def render_footer(
    parsed_count: int,
    incident_count: int,
    elapsed: float,
    version: str,
    console: Console,
    skipped_count: int = 0,
) -> None:
    skipped_note = ""
    if skipped_count > 0:
        # Make dropped lines visible — a trustable tool never hides data loss.
        skipped_note = f"  │  [yellow]{skipped_count:,} line(s) unparsed[/yellow]"
    console.print(
        f"Analyzed [bold]{parsed_count:,}[/bold] events in [bold]{elapsed:.1f}s[/bold]"
        f"  │  [bold]{incident_count}[/bold] incident(s)"
        f"{skipped_note}"
        f"  │  logcrux v{version}",
        style="dim",
    )


def render_overview(summaries: list[IncidentSummary], console: Console) -> None:
    """One row per file when several were analysed, worst first."""
    import os

    from rich.table import Table

    rank = {"CRITICAL": 0, "WARNING": 1, "INFO": 2, "CLEAN": 3}
    paths = [s.log_path for s in summaries]
    base = os.path.commonpath([os.path.dirname(p) for p in paths]) if paths else ""
    counts = {lvl: sum(1 for s in summaries if s.level == lvl) for lvl in rank}
    tally = ", ".join(f"{n} {lvl.lower()}" for lvl, n in counts.items() if n)
    table = Table(title=f"{len(summaries)} file(s) in {base or '.'}: {tally}",
                  title_justify="left", show_edge=False, pad_edge=False)
    table.add_column("level")
    width = max((len(os.path.relpath(p, base) if base else p) for p in paths), default=10)
    table.add_column("file", no_wrap=True, min_width=min(width, 44), overflow="ellipsis")
    table.add_column("format")
    table.add_column("events", justify="right")
    table.add_column("finding", overflow="fold")
    for s in sorted(summaries, key=lambda s: (rank.get(s.level, 9), s.log_path)):
        color = _LEVEL_COLORS.get(s.level, "white")
        finding = s.title if s.level != "CLEAN" else ""
        if s.findings and s.findings[0].subjects and s.level != "CLEAN":
            sub = s.findings[0].subjects[0]
            if sub.label != "message":
                finding += f" — {sub.label} {sub.value}"
        name = os.path.relpath(s.log_path, base) if base else s.log_path
        table.add_row(f"[{color}]{s.level}[/{color}]", name, s.parser_format,
                      f"{s.parsed_count:,}", finding)
    console.print(table)
