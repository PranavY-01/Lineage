"""Subprocess tests for the overview, --version and `validate` exit codes (§10.5, §11)."""

import json
import os
import subprocess
import sys
from pathlib import Path

from lineage_ir import __version__
from lineage_ir.config import DEFAULT_MAX_RECORDS, MAX_RECORDS_RANGE
from lineage_ir.ingest.reader import IngestOptions

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


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


def test_overview_without_arguments() -> None:
    proc = run()
    assert proc.returncode == 0
    for command in ("validate", "analyze", "tree", "story", "inspect", "rules"):
        assert command in proc.stdout
    assert __version__ in proc.stdout


def test_version_flags() -> None:
    for flag in ("--version", "-V"):
        proc = run(flag)
        assert proc.returncode == 0
        assert proc.stdout == f"lineage {__version__}\n"


def test_validate_valid_input_exits_0() -> None:
    proc = run("validate", FIXTURES / "shapes" / "shape_b.jsonl")
    assert proc.returncode == 0, proc.stderr
    assert "VALID" in proc.stdout
    assert "ws-14.corp.example" in proc.stdout


def test_validate_invalid_records_exit_4() -> None:
    proc = run("validate", FIXTURES / "broken" / "invalid_mix.jsonl")
    assert proc.returncode == 4
    assert "invalid_mix.jsonl:1 bad_json" in proc.stdout
    assert "invalid_mix.jsonl:9 implausible_timestamp" in proc.stdout


def test_validate_max_errors_limits_listing() -> None:
    proc = run("validate", FIXTURES / "broken" / "invalid_mix.jsonl", "--max-errors", "2")
    assert proc.returncode == 4
    assert "invalid_mix.jsonl:2 bad_json" in proc.stdout
    assert "invalid_mix.jsonl:3" not in proc.stdout
    assert "7 more" in proc.stdout


def test_validate_no_sysmon_exit_4(tmp_path: Path) -> None:
    path = tmp_path / "security.jsonl"
    path.write_text(
        json.dumps({"EventID": 4624, "Channel": "Security", "Hostname": "h"}) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    proc = run("validate", path)
    assert proc.returncode == 4
    assert "no_events" in proc.stdout


def test_validate_utf16_exit_3() -> None:
    proc = run("validate", FIXTURES / "broken" / "utf16.json")
    assert proc.returncode == 3
    assert proc.stdout == ""
    assert "Out-File -Encoding utf8" in proc.stderr


def test_validate_not_json_exit_3(tmp_path: Path) -> None:
    path = tmp_path / "notes.txt"
    path.write_text("hello\n", encoding="utf-8", newline="\n")
    proc = run("validate", path, "--format", "json")
    assert proc.returncode == 3
    assert proc.stdout == ""


def test_validate_directory_exit_2(tmp_path: Path) -> None:
    proc = run("validate", tmp_path, "--format", "json")
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "directory" in proc.stderr


def test_validate_missing_file_exit_2(tmp_path: Path) -> None:
    proc = run("validate", tmp_path / "missing.jsonl")
    assert proc.returncode == 2


def test_validate_bad_option_exit_2() -> None:
    proc = run("validate", FIXTURES / "duplicates.jsonl", "--max-records", "0")
    assert proc.returncode == 2
    proc = run("validate", FIXTURES / "duplicates.jsonl", "--format", "xml")
    assert proc.returncode == 2


def test_validate_too_large_exit_2(tmp_path: Path) -> None:
    path = tmp_path / "big.jsonl"
    path.write_bytes(b"\n" * (1024 * 1024 + 1))
    proc = run("validate", path, "--max-file-size", "1")
    assert proc.returncode == 2


def test_validate_json_prints_only_json() -> None:
    proc = run("validate", FIXTURES / "duplicates.jsonl", "--format", "json")
    assert proc.returncode == 0, proc.stderr
    document = json.loads(proc.stdout)
    assert list(document)[:2] == ["envelope", "kind"]
    assert document["kind"] == "validate"
    assert document["envelope"]["schema"] == "7d7b-report"
    assert document["envelope"]["tool"] == "Lineage"
    assert document["envelope"]["tool_version"] == __version__
    assert document["counters"]["duplicates_dropped"] == 2
    assert document["counters"]["duplicate_conflicts"] == 1
    assert document["reasons"] == ["duplicate_conflicts"]
    assert document["status"] == "valid"
    assert proc.stdout.isascii()


def test_validate_json_uses_lf_line_endings() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "lineage_ir", "validate", str(FIXTURES / "duplicates.jsonl")]
        + ["--format", "json"],
        capture_output=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0
    assert proc.stdout.endswith(b"}\n")
    assert b"\r" not in proc.stdout


def test_validate_record_cap_exit_4() -> None:
    proc = run("validate", FIXTURES / "duplicates.jsonl", "--max-records", "2", "--format", "json")
    assert proc.returncode == 4
    assert json.loads(proc.stdout)["record_cap_reached"] is True


def test_validate_record_cap_message_names_cap_and_flag() -> None:
    proc = run("validate", FIXTURES / "duplicates.jsonl", "--max-records", "2")
    assert proc.returncode == 4
    text = " ".join(proc.stdout.split())
    assert "Record cap of 2 reached" in text
    assert "Raise the cap with --max-records." in text


def test_default_record_cap() -> None:
    assert DEFAULT_MAX_RECORDS == 2_000_000
    assert MAX_RECORDS_RANGE == (1, 50_000_000)
    assert IngestOptions().max_records == DEFAULT_MAX_RECORDS
