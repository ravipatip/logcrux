from __future__ import annotations

import json

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from logcrux.models import IncidentSummary

_LEVEL_COLORS = {
    "CRITICAL": "bold red",
    "WARNING": "bold yellow",
    "INFO": "bold blue",
    "CLEAN": "bold green",
}


def render_summary(
    summary: IncidentSummary, console: Console, show_remediation: bool = True
) -> None:
    color = _LEVEL_COLORS.get(summary.level, "white")
    header = Text()
    header.append(f"  {summary.level}  ", style=f"reverse {color}")
    header.append(f"  {summary.title}")

    body_lines: list[str] = []
    for finding in summary.findings:
        bullet = f"  ● {finding.headline}"
        if finding.detail:
            bullet += f"  ({finding.detail})"
        body_lines.append(bullet)

    if summary.confidence > 0:
        body_lines.append(f"  Confidence: {summary.confidence:.0%}")

    if summary.remediation and show_remediation:
        body_lines.append("")
        body_lines.append(f"  Remediation: {summary.remediation}")

    body = "\n".join(body_lines)
    console.print(Panel(body, title=header, border_style=color.replace("bold ", "")))


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
