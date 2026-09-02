from pathlib import Path

from loghound.analyzer import analyze, find_first_critical, group_by_fingerprint, rank_groups
from loghound.models import LogEvent, Severity, SignatureGroup
from loghound.parser import parse_file

FIXTURES = Path(__file__).parent / "fixtures"


def make_event(
    line_number: int,
    message: str,
    severity: Severity = Severity.ERROR,
    after_context: list[str] | None = None,
) -> LogEvent:
    return LogEvent(
        line_number=line_number,
        severity=severity,
        message=message,
        before_context=[],
        after_context=after_context or [],
    )


def test_group_by_fingerprint_groups_duplicate_failures() -> None:
    events = [
        make_event(3, "2026-09-01 12:05:03 ERROR request 9921 timed out after 5003ms"),
        make_event(5, "2026-09-01 12:05:05 ERROR request 9922 timed out after 5011ms"),
        make_event(7, "CRITICAL database unavailable", Severity.CRITICAL),
    ]

    groups = group_by_fingerprint(events)

    assert len(groups) == 2
    assert groups[0].count == 2
    assert groups[0].first_occurrence.line_number == 3
    assert groups[0].occurrences == events[:2]
    assert all(event.fingerprint for event in events)


def test_rank_groups_sorts_by_count_then_first_occurrence() -> None:
    early_single = SignatureGroup(
        fingerprint="early",
        count=1,
        first_occurrence=make_event(1, "ERROR early"),
        occurrences=[],
    )
    later_pair = SignatureGroup(
        fingerprint="later-pair",
        count=2,
        first_occurrence=make_event(10, "ERROR later"),
        occurrences=[],
    )
    early_pair = SignatureGroup(
        fingerprint="early-pair",
        count=2,
        first_occurrence=make_event(3, "ERROR early pair"),
        occurrences=[],
    )

    assert rank_groups([early_single, later_pair, early_pair]) == [
        early_pair,
        later_pair,
        early_single,
    ]


def test_find_first_critical_returns_earliest_critical_event() -> None:
    first_error = make_event(1, "ERROR retry failed")
    first_critical = make_event(3, "FATAL storage corruption", Severity.CRITICAL)
    later_critical = make_event(8, "CRITICAL shutdown", Severity.CRITICAL)

    assert find_first_critical([first_error, first_critical, later_critical]) is first_critical


def test_find_first_critical_returns_earliest_critical_event_from_shuffled_input() -> None:
    later_critical = make_event(20, "CRITICAL later", Severity.CRITICAL)
    earlier_critical = make_event(3, "CRITICAL earlier", Severity.CRITICAL)

    assert find_first_critical([later_critical, earlier_critical]) is earlier_critical


def test_find_first_critical_returns_none_when_absent() -> None:
    assert find_first_critical([make_event(1, "ERROR retry failed")]) is None


def test_analyze_returns_result_with_counts_and_ranked_groups() -> None:
    events, lines_scanned = parse_file(FIXTURES / "noisy-server.log")

    result = analyze(events, filename="noisy-server.log", lines_scanned=lines_scanned)

    assert result.filename == "noisy-server.log"
    assert result.lines_scanned == 9
    assert len(result.events) == 5
    assert len(result.groups) == 4
    assert result.groups[0].count == 2


def test_analyzer_keeps_distinct_traceback_exception_groups() -> None:
    events, lines_scanned = parse_file(FIXTURES / "two-tracebacks.log")

    result = analyze(events, filename="two-tracebacks.log", lines_scanned=lines_scanned)

    assert len(result.events) == 2
    assert len(result.groups) == 2
    assert result.groups[0].fingerprint != result.groups[1].fingerprint
