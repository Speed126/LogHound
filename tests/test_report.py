from pathlib import Path

from loghound.analyzer import analyze
from loghound.parser import parse_file
from loghound.report import default_report_path, generate_markdown_report, write_markdown_report

FIXTURES = Path(__file__).parent / "fixtures"


def analyze_fixture(name: str):
    events, lines_scanned = parse_file(FIXTURES / name)
    return analyze(events, filename=name, lines_scanned=lines_scanned)


def test_default_report_path_uses_log_stem() -> None:
    assert default_report_path("server.log") == Path("server-loghound-report.md")
    assert default_report_path(Path("logs/server.txt")) == Path("logs/server-loghound-report.md")


def test_generate_markdown_report_contains_summary_groups_and_context() -> None:
    result = analyze_fixture("noisy-server.log")

    markdown = generate_markdown_report(result)

    assert "# LogHound Analysis" in markdown
    assert "## Overview" in markdown
    assert "| Lines scanned | 9 |" in markdown
    assert "| Errors | 5 |" in markdown
    assert "| Unique signatures | 4 |" in markdown
    assert "## Most Frequent Failures" in markdown
    assert "Occurrences: 2" in markdown
    assert "> 3 2026-09-01 12:05:03 ERROR request 9921 timed out after 5003ms" in markdown
    assert "## First Critical Failure" in markdown
    assert "Line 7: database unavailable" in markdown
    assert "None" not in markdown
    assert "NaN" not in markdown


def test_generate_markdown_report_handles_clean_logs() -> None:
    result = analyze_fixture("clean.log")

    markdown = generate_markdown_report(result)

    assert "| Lines scanned | 4 |" in markdown
    assert "| Errors | 0 |" in markdown
    assert "| Unique signatures | 0 |" in markdown
    assert "No failures detected." in markdown
    assert "No critical failures detected." in markdown
    assert "None" not in markdown


def test_markdown_report_uses_traceback_exception_titles() -> None:
    result = analyze_fixture("two-tracebacks.log")

    markdown = generate_markdown_report(result)

    assert "### ValueError: invalid account" in markdown
    assert "### FileNotFoundError: config.json" in markdown


def test_write_markdown_report_creates_file(tmp_path: Path) -> None:
    result = analyze_fixture("simple.log")
    output_path = tmp_path / "simple-report.md"

    written_path = write_markdown_report(result, output_path)

    assert written_path == output_path
    assert output_path.read_text(encoding="utf-8").startswith("# LogHound Analysis")
