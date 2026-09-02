from pathlib import Path

from typer.testing import CliRunner

from loghound.cli import app

FIXTURES = Path(__file__).parent / "fixtures"


def test_help_shows_registered_commands() -> None:
    result = CliRunner().invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Analyze noisy application logs without losing your mind." in result.output
    assert "scan" in result.output
    assert "summary" in result.output
    assert "report" in result.output


def test_summary_command_outputs_counts_and_first_critical() -> None:
    result = CliRunner().invoke(app, ["summary", str(FIXTURES / "noisy-server.log")])

    assert result.exit_code == 0
    assert "LogHound Summary" in result.output
    assert "noisy-server.log" in result.output
    assert "9 lines scanned" in result.output
    assert "5 errors found" in result.output
    assert "4 unique signatures" in result.output
    assert "request 9921 timed out after 5003ms" in result.output
    assert "Line 7 - database unavailable" in result.output


def test_summary_command_handles_empty_log(tmp_path: Path) -> None:
    log_path = tmp_path / "empty.log"
    log_path.write_text("", encoding="utf-8")

    result = CliRunner().invoke(app, ["summary", str(log_path)])

    assert result.exit_code == 0
    assert "0 lines scanned" in result.output
    assert "0 errors found" in result.output
    assert "Nothing to report." in result.output
    assert "Traceback" not in result.output


def test_summary_command_handles_clean_log() -> None:
    result = CliRunner().invoke(app, ["summary", str(FIXTURES / "clean.log")])

    assert result.exit_code == 0
    assert "4 lines scanned" in result.output
    assert "0 errors found" in result.output
    assert "Suspiciously healthy." in result.output
    assert "Most frequent" not in result.output


def test_scan_command_outputs_limited_context() -> None:
    result = CliRunner().invoke(
        app,
        [
            "scan",
            str(FIXTURES / "noisy-server.log"),
            "--limit",
            "1",
            "--before",
            "1",
            "--after",
            "1",
        ],
    )

    assert result.exit_code == 0
    assert "LogHound" in result.output
    assert "Errors detected: 5" in result.output
    assert "ERROR Line 3" in result.output
    assert "> 3 2026-09-01 12:05:03 ERROR request 9921 timed out after 5003ms" in result.output
    assert "4 more failure(s) hidden by --limit 1." in result.output


def test_scan_command_can_filter_by_critical_severity() -> None:
    result = CliRunner().invoke(
        app,
        ["scan", str(FIXTURES / "noisy-server.log"), "--severity", "critical"],
    )

    assert result.exit_code == 0
    assert "Errors detected: 1" in result.output
    assert "Unique signatures: 1" in result.output
    assert "request 9921 timed out after 5003ms" not in result.output
    assert "CRITICAL Line 7" in result.output
    assert "ERROR Line 3" not in result.output


def test_scan_command_reports_when_severity_filter_has_no_matches() -> None:
    result = CliRunner().invoke(
        app,
        ["scan", str(FIXTURES / "simple.log"), "--severity", "critical"],
    )

    assert result.exit_code == 0
    assert "Errors detected: 0" in result.output
    assert "No failures matched severity CRITICAL." in result.output


def test_scan_command_rejects_non_failure_severity() -> None:
    result = CliRunner().invoke(
        app,
        ["scan", str(FIXTURES / "simple.log"), "--severity", "warning"],
    )

    assert result.exit_code == 2
    assert "warning" in result.output


def test_scan_command_handles_clean_log() -> None:
    result = CliRunner().invoke(app, ["scan", str(FIXTURES / "clean.log")])

    assert result.exit_code == 0
    assert "Lines scanned: 4" in result.output
    assert "Errors detected: 0" in result.output
    assert "Suspiciously healthy." in result.output
    assert "Most frequent" not in result.output


def test_scan_renders_log_markup_as_literal_text(tmp_path: Path) -> None:
    log_path = tmp_path / "markup.log"
    log_path.write_text("starting\nERROR [bold]database[/bold] exploded\n", encoding="utf-8")

    result = CliRunner().invoke(app, ["scan", str(log_path)])

    assert result.exit_code == 0
    assert "[bold]database[/bold] exploded" in result.output


def test_report_command_writes_markdown_file(tmp_path: Path) -> None:
    output_path = tmp_path / "report.md"

    result = CliRunner().invoke(
        app,
        ["report", str(FIXTURES / "simple.log"), "--output", str(output_path)],
    )

    assert result.exit_code == 0
    assert "Wrote report to" in result.output
    assert output_path.exists()
    assert "| Errors | 1 |" in output_path.read_text(encoding="utf-8")


def test_report_command_uses_default_output_path(tmp_path: Path) -> None:
    log_path = tmp_path / "server.log"
    log_path.write_text("ERROR database exploded\n", encoding="utf-8")
    expected_report = tmp_path / "server-loghound-report.md"

    result = CliRunner().invoke(app, ["report", str(log_path)])

    assert result.exit_code == 0
    assert "Wrote report to" in result.output
    assert "server-loghound-report.md" in result.output
    assert expected_report.exists()
    assert "| Errors | 1 |" in expected_report.read_text(encoding="utf-8")


def test_missing_file_exits_cleanly_without_traceback() -> None:
    result = CliRunner().invoke(app, ["summary", "missing.log"])

    assert result.exit_code == 2
    assert "does not exist" in result.output
    assert "Traceback" not in result.output


def test_unreadable_file_exits_cleanly_without_traceback(tmp_path: Path, monkeypatch) -> None:
    log_path = tmp_path / "unreadable.log"
    log_path.write_text("ERROR hidden\n", encoding="utf-8")

    def raise_permission_error(*args, **kwargs):
        raise PermissionError("Permission denied")

    monkeypatch.setattr("loghound.cli.parse_file", raise_permission_error)

    result = CliRunner().invoke(app, ["summary", str(log_path)])

    assert result.exit_code == 2
    assert "Could not read" in result.output
    assert "unreadable.log." in result.output
    assert "Permission denied" in result.output
    assert "Traceback" not in result.output


def test_report_write_error_exits_cleanly_without_traceback(tmp_path: Path, monkeypatch) -> None:
    output_path = tmp_path / "report.md"

    def raise_write_error(*args, **kwargs):
        raise OSError("Disk full")

    monkeypatch.setattr("loghound.cli.write_markdown_report", raise_write_error)

    result = CliRunner().invoke(
        app,
        ["report", str(FIXTURES / "simple.log"), "--output", str(output_path)],
    )

    assert result.exit_code == 2
    assert "Could not write" in result.output
    assert "report.md." in result.output
    assert "Disk full" in result.output
    assert "Traceback" not in result.output
