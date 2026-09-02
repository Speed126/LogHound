from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from loghound.analyzer import analyze, find_first_critical
from loghound.models import AnalysisResult, LogEvent, Severity
from loghound.parser import DEFAULT_AFTER_CONTEXT, DEFAULT_BEFORE_CONTEXT, parse_file
from loghound.report import (
    default_report_path,
    event_title,
    format_context,
    group_title,
    write_markdown_report,
)

app = typer.Typer(
    help="Analyze noisy application logs without losing your mind.",
    no_args_is_help=True,
)
console = Console()


class FailureSeverity(StrEnum):
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


def _load_analysis(
    path: Path,
    before: int = DEFAULT_BEFORE_CONTEXT,
    after: int = DEFAULT_AFTER_CONTEXT,
) -> AnalysisResult:
    if not path.exists():
        console.print(f"[red]Error:[/red] {path} does not exist.")
        raise typer.Exit(code=2)
    if not path.is_file():
        console.print(f"[red]Error:[/red] {path} is not a file.")
        raise typer.Exit(code=2)

    try:
        events, lines_scanned = parse_file(path, before=before, after=after)
    except PermissionError as exc:
        console.print(f"[red]Could not read {path}.[/red]")
        console.print(str(exc))
        raise typer.Exit(code=2) from exc
    except OSError as exc:
        console.print(f"[red]Could not read {path}.[/red]")
        console.print(str(exc))
        raise typer.Exit(code=2) from exc

    return analyze(events, filename=path.name, lines_scanned=lines_scanned)


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(exists=False, readable=False)],
    before: Annotated[
        int,
        typer.Option(
            "--before",
            min=0,
            help="Number of context lines to show before each detected failure.",
        ),
    ] = DEFAULT_BEFORE_CONTEXT,
    after: Annotated[
        int,
        typer.Option(
            "--after",
            min=0,
            help="Number of context lines to show after each detected failure.",
        ),
    ] = DEFAULT_AFTER_CONTEXT,
    limit: Annotated[
        int,
        typer.Option("--limit", min=1, help="Maximum number of detected failures to display."),
    ] = 20,
    severity: Annotated[
        FailureSeverity | None,
        typer.Option(
            "--severity",
            "-s",
            case_sensitive=False,
            help="Only display events with this failure severity.",
        ),
    ] = None,
) -> None:
    """Scan a log and show detailed failure context."""
    result = _load_analysis(path, before=before, after=after)
    selected_severity = _to_severity(severity)
    events = _filter_events(result.events, selected_severity)
    display_result = (
        analyze(events, filename=result.filename, lines_scanned=result.lines_scanned)
        if selected_severity is not None
        else result
    )

    console.print("[bold]LogHound[/bold]")
    console.print()
    _print_overview(display_result)
    console.print()

    if not display_result.events:
        if selected_severity is not None and result.events:
            console.print(f"No failures matched severity {selected_severity.value}.")
        else:
            console.print(_no_failures_message(result))
        return

    _print_group_table(display_result)
    console.print()
    console.rule("Detected failures", style="grey50")
    for event in events[:limit]:
        _print_event(event)

    remaining = len(events) - limit
    if remaining > 0:
        console.print(
            f"{remaining:,} more failure(s) hidden by --limit {limit}.",
            style="dim",
            highlight=False,
        )


@app.command()
def summary(path: Annotated[Path, typer.Argument(exists=False, readable=False)]) -> None:
    """Show a compact triage summary for a log."""
    result = _load_analysis(path)

    console.print("[bold]LogHound Summary[/bold]")
    console.print()
    console.print(result.filename)
    console.print()
    console.print(f"{result.lines_scanned:,} lines scanned")
    console.print(f"{len(result.events):,} errors found")
    console.print(f"{len(result.groups):,} unique signatures")
    console.print()

    if not result.events:
        console.print(_no_failures_message(result))
        return

    _print_group_table(result)
    first_critical = find_first_critical(result.events)
    console.print()
    if first_critical:
        console.print("[bold]First critical failure:[/bold]")
        line = Text(f"Line {first_critical.line_number} - ")
        line.append(event_title(first_critical))
        console.print(line)
    elif result.events:
        console.print("No critical failures detected.")
    else:
        console.print("No failures detected.")


@app.command()
def report(
    path: Annotated[Path, typer.Argument(exists=False, readable=False)],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Markdown report path."),
    ] = None,
) -> None:
    """Generate a Markdown report for a log."""
    result = _load_analysis(path)
    report_path = output or default_report_path(path)

    try:
        write_markdown_report(result, report_path)
    except OSError as exc:
        console.print(f"[red]Could not write {report_path}.[/red]")
        console.print(str(exc))
        raise typer.Exit(code=2) from exc

    console.print(f"Wrote report to {report_path}")


def _to_severity(severity: FailureSeverity | None) -> Severity | None:
    if severity is None:
        return None
    return Severity(severity.value)


def _filter_events(events: list[LogEvent], severity: Severity | None) -> list[LogEvent]:
    if severity is None:
        return events
    return [event for event in events if event.severity is severity]


def _print_overview(result: AnalysisResult) -> None:
    console.print(f"File: {result.filename}")
    console.print(f"Lines scanned: {result.lines_scanned:,}")
    console.print(f"Errors detected: {len(result.events):,}")
    console.print(f"Unique signatures: {len(result.groups):,}")


def _no_failures_message(result: AnalysisResult) -> str:
    if result.lines_scanned == 0:
        return "Nothing to report."
    return "Suspiciously healthy."


def _print_group_table(result: AnalysisResult) -> None:
    console.print("[bold]Most frequent[/bold]")
    if not result.groups:
        console.print("No failures detected.")
        return

    table = Table(box=box.SIMPLE, show_edge=False)
    table.add_column("Occurrences", justify="right")
    table.add_column("Failure")

    for group in result.groups:
        table.add_row(f"{group.count:,}", Text(group_title(group)))

    console.print(table)


def _print_event(event: LogEvent) -> None:
    console.print()

    severity_style = "bold bright_red" if event.severity is Severity.CRITICAL else "bold red"
    header = Text()
    header.append(event.severity.value, style=severity_style)
    header.append(" Line ", style="bold")
    header.append(str(event.line_number), style="bold cyan")
    console.print(header)

    console.print(Text(event_title(event)))
    console.print()
    console.print("[bold]Context[/bold]")
    for line in format_context(event):
        console.print(Text(line))
