"""CLI tests for analyze, tree, story and inspect: every exit code in §10.5.

Subprocess runs cover each command and exit code end to end; in-process runs inject
failures (interrupts, write errors, internal errors) and freeze the clock.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from helpers.reports import FIXTURES, validator
from lineage_ir import cli, outputs
from lineage_ir.render.terminal import PARTIAL_LINE

PHISH = FIXTURES / "phish_chain.jsonl"
BENIGN = FIXTURES / "benign_host.jsonl"
MISSING = FIXTURES / "missing_telemetry.jsonl"
UTF16 = FIXTURES / "broken" / "utf16.json"
POWERSHELL_GUID = "8f3c2a71-5e4b-4d9a-a1c3-0000000000e1"


def run(*args: str | Path) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ, NO_COLOR="1", COLUMNS="120", PYTHONIOENCODING="utf-8")
    return subprocess.run(
        [sys.executable, "-m", "lineage_ir", *map(str, args)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        timeout=120,
        check=False,
    )


def invoke(*args: str | Path) -> object:
    return CliRunner().invoke(cli.app, [str(a) for a in args], env={"COLUMNS": "120"})


# Subprocess: every command, every exit code.


@pytest.mark.parametrize(
    ("args", "code"),
    [
        (("analyze", BENIGN), 0),
        (("analyze", PHISH), 1),
        (("analyze", MISSING), 4),
        (("analyze", UTF16), 3),
        (("analyze", PHISH, "--rules", "NOPE-999"), 2),
        (("tree", PHISH, "--hot-only"), 1),
        (("tree", MISSING), 4),
        (("tree", BENIGN, "--max-depth", "4"), 0),
        (("story", PHISH, "--storyline", "2"), 1),
        (("story", PHISH, "--storyline", "3"), 2),
        (("story", UTF16), 3),
        (("inspect", PHISH, POWERSHELL_GUID), 0),
        (("inspect", PHISH, "image:nothing.exe"), 2),
        (("inspect", UTF16, "pid:1"), 3),
    ],
    ids=lambda v: (
        " ".join(str(Path(a).name) if isinstance(a, Path) else a for a in v)
        if isinstance(v, tuple)
        else str(v)
    ),
)
def test_exit_codes(args: tuple[str | Path, ...], code: int) -> None:
    proc = run(*args)
    assert proc.returncode == code, proc.stderr
    if code in (2, 3):
        assert proc.stdout == "" and "error" in proc.stderr


def test_incomplete_runs_say_so() -> None:
    for command in ("analyze", "tree", "story"):
        proc = run(command, MISSING)
        assert proc.returncode == 4
        assert PARTIAL_LINE in proc.stdout.replace("\n", " ").replace("  ", " ") or (
            "Coverage is partial" in proc.stdout and "NOT a clean result" in proc.stdout
        )


@pytest.mark.parametrize("command", ["analyze", "tree", "story"])
def test_format_json_prints_only_the_report(command: str) -> None:
    proc = run(command, PHISH, "--format", "json")
    assert proc.returncode == 1
    document = json.loads(proc.stdout)
    assert validator("report-1.0.json").is_valid(document)
    assert proc.stderr == ""


def test_inspect_json() -> None:
    proc = run("inspect", PHISH, "{" + POWERSHELL_GUID.upper() + "}", "--format", "json")
    assert proc.returncode == 0
    document = json.loads(proc.stdout)
    assert document["node"]["guid"] == POWERSHELL_GUID
    assert validator("report-1.0.json", "inspectDocument").is_valid(document)


def test_fatal_errors_print_nothing_on_stdout_in_json_mode() -> None:
    for args in (
        ("analyze", PHISH, "--format", "json", "--since", "2026-10-12T10:00:00"),
        ("analyze", UTF16, "--format", "json"),
        ("inspect", BENIGN, "image:notepad.exe", "--format", "json"),
    ):
        proc = run(*args)
        assert proc.returncode in (2, 3)
        assert proc.stdout == ""


def test_reports_and_artifacts_are_written(tmp_path: Path) -> None:
    report, iocs = tmp_path / "report.json", tmp_path / "iocs.jsonl"
    proc = run("analyze", PHISH, "--report", report, "--artifacts", iocs)
    assert proc.returncode == 1
    assert validator("report-1.0.json").is_valid(json.loads(report.read_text("utf-8")))
    lines = [json.loads(x) for x in iocs.read_text("utf-8").splitlines()]
    assert all(validator("artifacts-1.0.json").is_valid(line) for line in lines)
    assert "report.json" in proc.stdout and "iocs.jsonl" in proc.stdout


def test_partial_coverage_still_writes_outputs(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    proc = run("analyze", MISSING, "--report", report)
    assert proc.returncode == 4
    assert json.loads(report.read_text("utf-8"))["status"] == "incomplete"


# In-process: usage errors (exit 2).


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (["--since", "2026-10-12T10:00:00"], "explicit offset"),
        (["--window", "5m"], "--window can only be used with --around"),
        (["--around", "2026-10-12T10:00:00Z", "--since", "2026-10-12T09:00:00Z"], "--around"),
        (["--since", "2026-10-12T11:00:00Z", "--until", "2026-10-12T10:00:00Z"], "before"),
        (["--rules", "CMD,NOPE"], "unknown rule"),
        (["--focus", "pid:99999"], "process not found"),
        (["--focus", "not-a-guid"], "not a GUID"),
        (["--min-severity", "urgent"], "invalid option"),
        (["--gap", "10x"], "not a duration"),
        (["--max-steps", "5"], "--max-steps"),
        (["--html", "out.html"], "--html: not available in this build"),
    ],
)
def test_usage_errors(extra: list[str], message: str) -> None:
    result = invoke("analyze", PHISH, *extra)
    assert result.exit_code == 2  # type: ignore[attr-defined]
    assert message in result.output  # type: ignore[attr-defined]


def test_directory_input_and_oversize_file(tmp_path: Path) -> None:
    assert invoke("analyze", tmp_path).exit_code == 2  # type: ignore[attr-defined]
    big = tmp_path / "big.jsonl"
    big.write_bytes(PHISH.read_bytes() * 100)
    result = invoke("tree", big, "--max-file-size", "1")
    assert result.exit_code == 2  # type: ignore[attr-defined]


def test_ambiguous_target_lists_candidates() -> None:
    # The same GUID on two hosts: inspect needs exactly one node, so it lists both.
    guid = "6c1e0a2b-7d3f-4e5a-9b8c-0000000000e1"
    result = invoke("inspect", FIXTURES / "multi_host.jsonl", guid)
    assert result.exit_code == 2  # type: ignore[attr-defined]
    output = result.output  # type: ignore[attr-defined]
    assert "matches 2 processes; pick one by GUID" in output
    assert "ws-14.corp.example" in output and "ws-15.corp.example" in output
    narrowed = invoke(
        "inspect", FIXTURES / "multi_host.jsonl", guid, "--host", "ws-15.corp.example"
    )
    assert narrowed.exit_code == 0  # type: ignore[attr-defined]


def test_image_target_over_the_cap() -> None:
    result = invoke("inspect", BENIGN, "image:notepad.exe")
    assert result.exit_code == 2  # type: ignore[attr-defined]
    assert "matches 23 processes (at most 20)" in result.output  # type: ignore[attr-defined]


def test_unsafe_output_paths_end_the_run_before_analysis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def never(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("analysis ran")

    monkeypatch.setattr(cli, "run_analysis", never)
    existing = tmp_path / "taken.json"
    existing.write_text("{}", encoding="utf-8")
    for args in (
        ["--report", str(PHISH)],
        ["--report", str(existing)],
        ["--report", str(existing), "--force"],
        ["--artifacts", str(tmp_path / "missing" / "a.jsonl")],
        ["--csv", str(PHISH)],
        ["--csv", str(existing), "--force"],
        ["--csv", str(tmp_path / "t.csv"), "--report", str(tmp_path / "t.csv")],
    ):
        result = invoke("analyze", PHISH, *args)
        assert result.exit_code == 2, args  # type: ignore[attr-defined]
    assert existing.read_text(encoding="utf-8") == "{}"


def test_force_replaces_an_earlier_report(tmp_path: Path) -> None:
    report = tmp_path / "r.json"
    assert invoke("analyze", PHISH, "--report", report).exit_code == 1  # type: ignore[attr-defined]
    first = report.read_bytes()
    assert invoke("analyze", PHISH, "--report", report).exit_code == 2  # type: ignore[attr-defined]
    result = invoke("analyze", PHISH, "--report", report, "--force")
    assert result.exit_code == 1  # type: ignore[attr-defined]
    assert report.read_bytes() != first  # a new run ID and times


# In-process: interrupts, write failures and internal errors.


def test_interrupt_exits_130_and_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def interrupt(*_args: object, **_kwargs: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "run_analysis", interrupt)
    report = tmp_path / "r.json"
    result = CliRunner().invoke(cli.app, ["analyze", str(PHISH), "--report", str(report)])
    assert result.exit_code == 130
    assert result.stdout == ""
    assert list(tmp_path.iterdir()) == []


def test_write_failure_is_a_fatal_exit_4(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(outputs.os, "replace", fail)
    report = tmp_path / "r.json"
    result = CliRunner().invoke(
        cli.app, ["analyze", str(PHISH), "--report", str(report), "--format", "json"]
    )
    assert result.exit_code == 4
    assert result.stdout == ""
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("command", ["analyze", "tree", "story"])
def test_internal_error_exits_4_without_details(
    command: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("secret-record-content")

    monkeypatch.setattr(cli, "run_analysis", boom)
    result = CliRunner().invoke(cli.app, [command, str(PHISH)])
    assert result.exit_code == 4
    assert "secret-record-content" not in result.output
    assert "internal error" in result.output


def test_display_filters_never_change_the_exit_code() -> None:
    for extra in (
        ["--since", "2026-10-12T12:00:00Z"],
        ["--focus", "image:notepad.exe"],
        ["--around", "2026-10-12T09:00:00Z", "--window", "1m"],
        ["--hot-only"],
    ):
        assert invoke("analyze", PHISH, *extra).exit_code == 1  # type: ignore[attr-defined]
    for extra in (["--until", "2026-10-12T09:00:00Z"], ["--hot-only"]):
        assert invoke("tree", MISSING, *extra).exit_code == 4  # type: ignore[attr-defined]
    until = invoke("story", MISSING, "--until", "2026-10-12T09:00:00Z")
    assert until.exit_code == 4  # type: ignore[attr-defined]


def test_narrow_terminal_gets_a_compact_header() -> None:
    result = CliRunner().invoke(cli.app, ["analyze", str(PHISH)], env={"COLUMNS": "70"})
    first = result.output.splitlines()[0]
    assert first.startswith(" LINEAGE ") and "analyze ·" in first and "input" in first


def test_redirected_output_survives_a_legacy_code_page(tmp_path: Path) -> None:
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONIOENCODING", "PYTHONUTF8")}
    env.update(NO_COLOR="1", COLUMNS="120", PYTHONIOENCODING="cp1252")
    proc = subprocess.run(
        [sys.executable, "-m", "lineage_ir", "story", str(PHISH)],
        capture_output=True,
        env=env,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 1, proc.stderr
    assert "→".encode() in proc.stdout


def test_csv_timeline_is_written_with_the_other_outputs(tmp_path: Path) -> None:
    from helpers.reports import frozen_analysis
    from lineage_ir.render.csv_timeline import csv_bytes

    csv_path, report = tmp_path / "timeline.csv", tmp_path / "report.json"
    result = CliRunner().invoke(
        cli.app,
        [
            "analyze",
            str(PHISH),
            "--csv",
            str(csv_path),
            "--report",
            str(report),
            "--artifacts",
            str(tmp_path / "iocs.jsonl"),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 1
    assert json.loads(result.stdout)["envelope"]["tool"] == "Lineage"
    assert csv_path.read_bytes() == csv_bytes(frozen_analysis(PHISH))
    assert report.exists() and (tmp_path / "iocs.jsonl").exists()
    again = CliRunner().invoke(cli.app, ["analyze", str(PHISH), "--csv", str(csv_path), "--force"])
    assert again.exit_code == 1
    assert "csv" in again.output and "timeline.csv" in again.output


def test_csv_for_an_incomplete_run_is_still_written(tmp_path: Path) -> None:
    csv_path = tmp_path / "t.csv"
    proc = run("analyze", MISSING, "--csv", csv_path)
    assert proc.returncode == 4
    assert csv_path.read_bytes().startswith(bytes([0xEF, 0xBB, 0xBF]))
