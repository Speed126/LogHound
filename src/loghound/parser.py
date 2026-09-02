import re
from collections.abc import Iterable
from pathlib import Path

from loghound.models import LogEvent, Severity

DEFAULT_BEFORE_CONTEXT = 3
DEFAULT_AFTER_CONTEXT = 5

_FAILURE_MARKER_RE = re.compile(
    r"\b(?:error|err|fatal|critical|traceback|appcrash|panic)\b"
    r"|\b\w*exception\b"
    r"|segmentation fault"
    r"|access violation",
    re.IGNORECASE,
)
_CRITICAL_RE = re.compile(
    r"\b(?:fatal|critical|appcrash|panic)\b"
    r"|segmentation fault"
    r"|access violation"
    r"|unhandled exception",
    re.IGNORECASE,
)
_ERROR_RE = re.compile(
    r"\b(?:error|err|traceback)\b|\b\w*exception\b",
    re.IGNORECASE,
)
_WARNING_RE = re.compile(r"\b(?:warning|warn)\b", re.IGNORECASE)
_INFO_RE = re.compile(r"\binfo\b", re.IGNORECASE)


def detect_event(line: str) -> bool:
    """Return True when a line contains a recognizable failure marker."""
    return bool(_FAILURE_MARKER_RE.search(line))


def detect_severity(line: str) -> Severity:
    """Infer severity from the strongest marker present in a single log line."""
    if _CRITICAL_RE.search(line):
        return Severity.CRITICAL
    if _ERROR_RE.search(line):
        return Severity.ERROR
    if _WARNING_RE.search(line):
        return Severity.WARNING
    if _INFO_RE.search(line):
        return Severity.INFO
    return Severity.ERROR if detect_event(line) else Severity.INFO


def extract_context(
    lines: list[str],
    index: int,
    before: int = DEFAULT_BEFORE_CONTEXT,
    after: int = DEFAULT_AFTER_CONTEXT,
) -> tuple[list[str], list[str]]:
    """Extract bounded context around a zero-based line index."""
    if before < 0 or after < 0:
        raise ValueError("Context sizes must be non-negative.")

    before_start = max(0, index - before)
    after_end = min(len(lines), index + after + 1)
    return lines[before_start:index], lines[index + 1 : after_end]


def parse_lines(
    lines: Iterable[str],
    before: int = DEFAULT_BEFORE_CONTEXT,
    after: int = DEFAULT_AFTER_CONTEXT,
) -> list[LogEvent]:
    """Parse already-loaded log lines into failure events."""
    normalized_lines = [line.rstrip("\r\n") for line in lines]
    events: list[LogEvent] = []

    for index, line in enumerate(normalized_lines):
        if not detect_event(line):
            continue

        before_context, after_context = extract_context(
            normalized_lines,
            index,
            before=before,
            after=after,
        )
        events.append(
            LogEvent(
                line_number=index + 1,
                severity=detect_severity(line),
                message=line,
                before_context=before_context,
                after_context=after_context,
            )
        )

    return events


def parse_file(
    path: str | Path,
    before: int = DEFAULT_BEFORE_CONTEXT,
    after: int = DEFAULT_AFTER_CONTEXT,
) -> tuple[list[LogEvent], int]:
    """Read a text log file and return detected events plus total lines scanned."""
    log_path = Path(path)
    content = log_path.read_text(encoding="utf-8", errors="replace")
    lines = content.splitlines()
    return parse_lines(lines, before=before, after=after), len(lines)
