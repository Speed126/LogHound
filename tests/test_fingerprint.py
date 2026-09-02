from pathlib import Path

from loghound.fingerprint import assign_fingerprints, fingerprint_event, fingerprint_message
from loghound.models import LogEvent, Severity
from loghound.parser import parse_file

FIXTURES = Path(__file__).parent / "fixtures"


def test_dynamic_request_ids_and_latency_values_share_signature() -> None:
    first = fingerprint_message("2026-09-01 12:05:01 ERROR request 9921 timed out after 5003ms")
    second = fingerprint_message("2026-09-01 12:05:05 ERROR request 9922 timed out after 5011ms")

    assert first == second
    assert "<duration>" in first


def test_duration_units_normalize_regardless_of_size_or_spacing() -> None:
    fingerprints = {
        fingerprint_message("ERROR timeout after 12ms"),
        fingerprint_message("ERROR timeout after 999ms"),
        fingerprint_message("ERROR timeout after 5003 ms"),
        fingerprint_message("ERROR timeout after 5.2s"),
    }

    assert fingerprints == {"error timeout after <duration>"}


def test_memory_addresses_are_normalized() -> None:
    first = fingerprint_message("Access violation at 0x00007FFD21AA119F")
    second = fingerprint_message("Access violation at 0x00007FFD39118834")

    assert first == second
    assert first == "access violation at <address>"


def test_uuids_are_normalized() -> None:
    first = fingerprint_message("ERROR failed account 90488152-89cb-43fa-882b-c01ba167de44")
    second = fingerprint_message("ERROR failed account 2a7875b5-0e83-4b6b-a8b7-29fa2e749067")

    assert first == second
    assert "<uuid>" in first


def test_timestamps_are_normalized() -> None:
    first = fingerprint_message("2026-08-31 14:53:12 ERROR database unavailable")
    second = fingerprint_message("2026-09-01T09:10:11 ERROR database unavailable")

    assert first == second
    assert first == "<timestamp> error database unavailable"


def test_pid_and_thread_ids_are_normalized() -> None:
    first = fingerprint_message("PID 18472 Thread ID 99 ERROR worker crashed")
    second = fingerprint_message("PID 18473 Thread ID 100 ERROR worker crashed")

    assert first == second
    assert "pid <number>" in first
    assert "thread id <number>" in first


def test_paths_are_normalized() -> None:
    first = fingerprint_message(r"ERROR opening C:\Users\alice\App\crash-1234.log")
    second = fingerprint_message(r"ERROR opening C:\Users\bob\App\crash-5678.log")

    assert first == second
    assert first == "error opening <path>"


def test_http_status_codes_are_preserved() -> None:
    not_found = fingerprint_message("ERROR HTTP 404 from /api/accounts/42")
    server_error = fingerprint_message("ERROR HTTP 500 from /api/accounts/42")

    assert not_found != server_error
    assert "http 404" in not_found
    assert "http 500" in server_error


def test_unlabeled_error_codes_are_preserved() -> None:
    first = fingerprint_message("ERROR code 1001 authentication failed")
    second = fingerprint_message("ERROR code 1002 authentication failed")

    assert first != second
    assert "1001" in first
    assert "1002" in second


def test_different_exception_types_stay_distinct() -> None:
    null_reference = fingerprint_message("NullReferenceException at line 5001")
    index_error = fingerprint_message("IndexOutOfRangeException at line 5001")

    assert null_reference != index_error


def test_whitespace_and_case_are_normalized() -> None:
    first = fingerprint_message("ERROR   Connection   Timeout")
    second = fingerprint_message("error connection timeout")

    assert first == second


def test_assign_fingerprints_mutates_events_in_place() -> None:
    event = LogEvent(
        line_number=1,
        severity=Severity.ERROR,
        message="ERROR request 9921 timed out after 5003ms",
        before_context=[],
        after_context=[],
    )

    result = assign_fingerprints([event])

    assert result == [event]
    assert event.fingerprint == "error request <number> timed out after <duration>"


def test_traceback_fingerprints_include_terminal_exception_identity() -> None:
    events, _ = parse_file(FIXTURES / "two-tracebacks.log")

    assert len(events) == 2
    assert fingerprint_event(events[0]) == (
        "traceback (most recent call last): valueerror: invalid account"
    )
    assert fingerprint_event(events[1]) == (
        "traceback (most recent call last): filenotfounderror: config.json"
    )
    assert fingerprint_event(events[0]) != fingerprint_event(events[1])
