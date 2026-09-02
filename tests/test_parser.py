from pathlib import Path

import pytest

from loghound.models import Severity
from loghound.parser import detect_event, detect_severity, extract_context, parse_file, parse_lines

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_file_detects_simple_error_with_context() -> None:
    events, lines_scanned = parse_file(FIXTURES / "simple.log")

    assert lines_scanned == 6
    assert len(events) == 1
    event = events[0]
    assert event.line_number == 4
    assert event.severity is Severity.ERROR
    assert event.message == "ERROR Unable to load account"
    assert event.before_context == [
        "Application starting",
        "Database connected",
        "Processing request",
    ]
    assert event.after_context == ["Request failed", "Application continuing"]


def test_parse_file_returns_no_events_for_clean_log() -> None:
    events, lines_scanned = parse_file(FIXTURES / "clean.log")

    assert lines_scanned == 4
    assert events == []


def test_parse_file_handles_empty_file(tmp_path: Path) -> None:
    empty = tmp_path / "empty.log"
    empty.write_text("", encoding="utf-8")

    events, lines_scanned = parse_file(empty)

    assert lines_scanned == 0
    assert events == []


def test_parse_file_tolerates_invalid_utf8_bytes(tmp_path: Path) -> None:
    log_path = tmp_path / "binary-ish.log"
    log_path.write_bytes(b"ready\nERROR failed near \xff\xfe\n")

    events, lines_scanned = parse_file(log_path)

    assert lines_scanned == 2
    assert len(events) == 1
    assert "ERROR failed near" in events[0].message


def test_traceback_header_is_primary_event() -> None:
    events, lines_scanned = parse_file(FIXTURES / "traceback.log")

    assert lines_scanned == 5
    assert len(events) == 1
    assert events[0].line_number == 2
    assert events[0].severity is Severity.ERROR
    assert events[0].message == "Traceback (most recent call last):"


def test_windows_crash_markers_are_detected() -> None:
    events, _ = parse_file(FIXTURES / "windows-crash.log")

    assert [event.line_number for event in events] == [2, 3, 4]
    assert [event.severity for event in events] == [
        Severity.ERROR,
        Severity.CRITICAL,
        Severity.CRITICAL,
    ]


@pytest.mark.parametrize(
    "line",
    [
        "FATAL SaveManager.Load() failed",
        "critical storage corruption detected",
        "Segmentation fault (core dumped)",
        "Access violation at 0x00007FFD21AA119F",
        "APPCRASH module renderer.exe",
        "Unhandled exception in worker",
        "panic: send on closed channel",
    ],
)
def test_critical_failure_markers(line: str) -> None:
    assert detect_event(line)
    assert detect_severity(line) is Severity.CRITICAL


@pytest.mark.parametrize(
    "line",
    [
        "ERROR unable to load profile",
        "ERR failed to bind port",
        "NullReferenceException while saving",
        "Traceback (most recent call last):",
    ],
)
def test_error_failure_markers(line: str) -> None:
    assert detect_event(line)
    assert detect_severity(line) is Severity.ERROR


def test_multiple_error_words_on_one_line_create_one_event() -> None:
    events = parse_lines(["ERROR fatal exception while saving"])

    assert len(events) == 1
    assert events[0].severity is Severity.CRITICAL


def test_extract_context_clamps_at_file_edges() -> None:
    lines = ["ERROR boot failed", "Attempting recovery", "Recovered"]

    before_context, after_context = extract_context(lines, 0, before=3, after=5)

    assert before_context == []
    assert after_context == ["Attempting recovery", "Recovered"]


def test_parse_lines_respects_custom_context_sizes() -> None:
    events = parse_lines(
        ["one", "two", "ERROR failure", "four", "five", "six"],
        before=1,
        after=2,
    )

    assert events[0].before_context == ["two"]
    assert events[0].after_context == ["four", "five"]


def test_negative_context_size_is_rejected() -> None:
    with pytest.raises(ValueError):
        extract_context(["ERROR failed"], 0, before=-1)


def test_large_line_does_not_crash_parser() -> None:
    events = parse_lines(["ERROR " + ("x" * 100_000)])

    assert len(events) == 1
    assert events[0].line_number == 1


def test_non_failure_text_is_not_an_event() -> None:
    assert not detect_event("Application started successfully")
    assert detect_severity("INFO Application started successfully") is Severity.INFO
    assert detect_severity("WARNING retrying request") is Severity.WARNING


def test_exception_like_normal_words_are_not_failures() -> None:
    assert not detect_event("Operation completed exceptionally fast")
    assert not detect_event("This produced exceptional performance")
