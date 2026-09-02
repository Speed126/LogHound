import re
from pathlib import Path

from loghound.analyzer import find_first_critical
from loghound.fingerprint import find_traceback_exception
from loghound.models import AnalysisResult, LogEvent, SignatureGroup

_TIMESTAMP_PREFIX_RE = re.compile(
    r"^\s*\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}"
    r"(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+"
)
_SEVERITY_PREFIX_RE = re.compile(
    r"^\s*(?:\[[A-Z]+\]\s*)?(?:ERROR|ERR|FATAL|CRITICAL)\s*[:|-]?\s*",
    re.IGNORECASE,
)


def default_report_path(log_path: str | Path) -> Path:
    """Return the default Markdown report path for a log file."""
    path = Path(log_path)
    return path.with_name(f"{path.stem}-loghound-report.md")


def event_title(event: LogEvent) -> str:
    """Return a compact human-readable title for an event."""
    if event.message.lstrip().lower().startswith("traceback"):
        exception_line = find_traceback_exception(event.after_context)
        if exception_line:
            return exception_line

    title = _TIMESTAMP_PREFIX_RE.sub("", event.message.strip())
    title = _SEVERITY_PREFIX_RE.sub("", title).strip()
    return title or event.fingerprint or "Other"


def group_title(group: SignatureGroup) -> str:
    """Return a compact title for a signature group."""
    return event_title(group.first_occurrence)


def format_context(event: LogEvent) -> list[str]:
    """Format an event and its context with source line numbers."""
    lines: list[str] = []
    start_line = event.line_number - len(event.before_context)

    for offset, line in enumerate(event.before_context):
        lines.append(f"  {start_line + offset} {line}")

    lines.append(f"> {event.line_number} {event.message}")

    for offset, line in enumerate(event.after_context, start=1):
        lines.append(f"  {event.line_number + offset} {line}")

    return lines


def generate_markdown_report(result: AnalysisResult) -> str:
    """Generate a readable Markdown report from an analysis result."""
    lines = [
        "# LogHound Analysis",
        "",
        "## Overview",
        "",
        f"File: `{_escape_inline_code(result.filename or 'unknown')}`",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Lines scanned | {result.lines_scanned:,} |",
        f"| Errors | {len(result.events):,} |",
        f"| Unique signatures | {len(result.groups):,} |",
        "",
        "## Most Frequent Failures",
        "",
    ]

    if result.groups:
        for group in result.groups:
            title = _escape_heading(group_title(group))
            lines.extend(
                [
                    f"### {title}",
                    "",
                    f"Occurrences: {group.count:,}",
                    "",
                    f"First occurrence: Line {group.first_occurrence.line_number}",
                    "",
                    f"Severity: {group.first_occurrence.severity.value}",
                    "",
                    "Context:",
                    "",
                    "```text",
                    *format_context(group.first_occurrence),
                    "```",
                    "",
                ]
            )
    else:
        lines.extend(["No failures detected.", ""])

    first_critical = find_first_critical(result.events)
    lines.extend(["## First Critical Failure", ""])
    if first_critical:
        lines.extend(
            [
                f"Line {first_critical.line_number}: {_escape_text(event_title(first_critical))}",
                "",
                "```text",
                *format_context(first_critical),
                "```",
                "",
            ]
        )
    else:
        lines.extend(["No critical failures detected.", ""])

    return "\n".join(lines).rstrip() + "\n"


def write_markdown_report(result: AnalysisResult, output_path: str | Path) -> Path:
    """Write a Markdown report and return the path used."""
    path = Path(output_path)
    path.write_text(generate_markdown_report(result), encoding="utf-8")
    return path


def _escape_inline_code(text: str) -> str:
    return text.replace("`", "\\`")


def _escape_heading(text: str) -> str:
    return _escape_text(text).replace("#", "\\#").strip() or "Other"


def _escape_text(text: str) -> str:
    return text.replace("|", "\\|")
