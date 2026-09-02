from collections import defaultdict
from pathlib import Path

from loghound.fingerprint import fingerprint_event
from loghound.models import AnalysisResult, LogEvent, Severity, SignatureGroup


def group_by_fingerprint(events: list[LogEvent]) -> list[SignatureGroup]:
    """Group events by normalized fingerprint."""
    grouped: dict[str, list[LogEvent]] = defaultdict(list)

    for event in events:
        if event.fingerprint is None:
            event.fingerprint = fingerprint_event(event)
        grouped[event.fingerprint].append(event)

    groups = [
        SignatureGroup(
            fingerprint=fingerprint,
            count=len(occurrences),
            first_occurrence=occurrences[0],
            occurrences=occurrences,
        )
        for fingerprint, occurrences in grouped.items()
    ]
    return rank_groups(groups)


def rank_groups(groups: list[SignatureGroup]) -> list[SignatureGroup]:
    """Rank groups by frequency, then by first occurrence."""
    return sorted(
        groups,
        key=lambda group: (-group.count, group.first_occurrence.line_number, group.fingerprint),
    )


def find_first_critical(events: list[LogEvent]) -> LogEvent | None:
    """Return the earliest critical event, if one exists."""
    critical_events = (event for event in events if event.severity is Severity.CRITICAL)
    return min(critical_events, key=lambda event: event.line_number, default=None)


def analyze(
    events: list[LogEvent],
    filename: str | Path = "",
    lines_scanned: int = 0,
) -> AnalysisResult:
    """Analyze parsed events into counts, groups, and rankings."""
    return AnalysisResult(
        filename=Path(filename).name if filename else "",
        lines_scanned=lines_scanned,
        events=events,
        groups=group_by_fingerprint(events),
    )
