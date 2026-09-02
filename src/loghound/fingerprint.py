import re

from loghound.models import LogEvent

_TIMESTAMP_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}"
    r"(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
)
_DATE_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_ADDRESS_RE = re.compile(r"\b0x[0-9a-fA-F]{4,}\b")
_WINDOWS_PATH_RE = re.compile(r"(?<!\w)(?:[A-Za-z]:\\|\\\\)[^\s:]+")
_UNIX_PATH_RE = re.compile(r"(?<!\w)/(?:[A-Za-z0-9._-]+/)+[A-Za-z0-9._-]+")
_LABELED_NUMBER_RE = re.compile(
    r"\b("
    r"pid|tid|process(?:\s+id)?|thread(?:\s+id)?|"
    r"request(?:\s+id)?|req(?:uest)?|user(?:\s+id)?|session(?:\s+id)?|"
    r"line|column|col|row"
    r")\s*[:=#-]?\s*\d+\b",
    re.IGNORECASE,
)
_DURATION_RE = re.compile(
    r"\b\d+(?:\.\d+)?\s*(?:ms|milliseconds?|s|sec(?:onds?)?)\b",
    re.IGNORECASE,
)
_NUMBER_WITH_SIZE_UNIT_RE = re.compile(
    r"\b\d+(?:\.\d+)?\s*(?=(?:bytes?|kb|mb|gb)\b)",
    re.IGNORECASE,
)
_PYTHON_EXCEPTION_LINE_RE = re.compile(
    r"^\s*(?:"
    r"[A-Za-z_][\w.]*(?:Error|Exception)|"
    r"KeyboardInterrupt|SystemExit|GeneratorExit|StopIteration|StopAsyncIteration"
    r")\b(?::.*)?$"
)
_WHITESPACE_RE = re.compile(r"\s+")


def _replace_labeled_number(match: re.Match[str]) -> str:
    return f"{match.group(1)} <NUMBER>"


def fingerprint_message(message: str) -> str:
    """Normalize volatile values while preserving useful failure identity."""
    normalized = message.strip()
    normalized = _TIMESTAMP_RE.sub("<TIMESTAMP>", normalized)
    normalized = _DATE_RE.sub("<TIMESTAMP>", normalized)
    normalized = _UUID_RE.sub("<UUID>", normalized)
    normalized = _ADDRESS_RE.sub("<ADDRESS>", normalized)
    normalized = _WINDOWS_PATH_RE.sub("<PATH>", normalized)
    normalized = _UNIX_PATH_RE.sub("<PATH>", normalized)
    normalized = _LABELED_NUMBER_RE.sub(_replace_labeled_number, normalized)
    normalized = _DURATION_RE.sub("<DURATION>", normalized)
    normalized = _NUMBER_WITH_SIZE_UNIT_RE.sub("<NUMBER>", normalized)
    normalized = _WHITESPACE_RE.sub(" ", normalized)
    return normalized.lower().strip()


def find_traceback_exception(context_lines: list[str]) -> str | None:
    """Return the terminal Python exception line from traceback context when present."""
    for line in reversed(context_lines):
        stripped = line.strip()
        if stripped and _PYTHON_EXCEPTION_LINE_RE.match(stripped):
            return stripped
    return None


def fingerprint_event(event: LogEvent) -> str:
    """Build the normalized signature for one parsed event."""
    message = event.message
    if message.lstrip().lower().startswith("traceback"):
        exception_line = find_traceback_exception(event.after_context)
        if exception_line:
            message = f"{message} {exception_line}"

    return fingerprint_message(message)


def assign_fingerprints(events: list[LogEvent]) -> list[LogEvent]:
    """Attach fingerprints to events in-place and return the same list."""
    for event in events:
        event.fingerprint = fingerprint_event(event)
    return events
