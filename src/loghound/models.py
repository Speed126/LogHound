from dataclasses import dataclass
from enum import StrEnum


class Severity(StrEnum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@dataclass(slots=True)
class LogEvent:
    line_number: int
    severity: Severity
    message: str
    before_context: list[str]
    after_context: list[str]
    fingerprint: str | None = None


@dataclass(slots=True)
class SignatureGroup:
    fingerprint: str
    count: int
    first_occurrence: LogEvent
    occurrences: list[LogEvent]


@dataclass(slots=True)
class AnalysisResult:
    filename: str
    lines_scanned: int
    events: list[LogEvent]
    groups: list[SignatureGroup]
