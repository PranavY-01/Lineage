"""In-process CLI tests that need a frozen clock, a fixed run ID or injected failures."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from lineage_ir import cli
from lineage_ir.ingest.timeparse import to_us

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
RUN_ID = "00000000-0000-4000-8000-000000000001"
FROZEN_US = to_us(datetime(2026, 10, 14, 17, 46, 40, tzinfo=UTC))


@pytest.fixture
def frozen(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "clock", lambda: FROZEN_US)
    monkeypatch.setattr(cli, "run_id_factory", lambda: RUN_ID)


def test_validate_json_is_deterministic(frozen: None) -> None:
    runner = CliRunner()
    args = ["validate", str(FIXTURES / "shapes" / "shape_c.jsonl"), "--format", "json"]
    first = runner.invoke(cli.app, args)
    second = runner.invoke(cli.app, args)
    assert first.exit_code == 0
    assert first.stdout == second.stdout
    envelope = json.loads(first.stdout)["envelope"]
    assert envelope["run_id"] == RUN_ID
    assert envelope["started_at"] == envelope["completed_at"] == "2026-10-14T17:46:40Z"


def test_unexpected_error_exits_4_without_details(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("secret-record-content")

    monkeypatch.setattr(cli, "run_validate", boom)
    result = CliRunner().invoke(cli.app, ["validate", str(FIXTURES / "duplicates.jsonl")])
    assert result.exit_code == 4
    assert "secret-record-content" not in result.output
    assert "internal error" in result.output


def test_interrupt_exits_130(monkeypatch: pytest.MonkeyPatch) -> None:
    def interrupt(*_args: object, **_kwargs: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "run_validate", interrupt)
    result = CliRunner().invoke(cli.app, ["validate", str(FIXTURES / "duplicates.jsonl")])
    assert result.exit_code == 130
    assert result.stdout == ""


def test_hostile_values_in_text_view_are_escaped(tmp_path: Path) -> None:
    record = {
        "EventID": 1,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Hostname": "ws-14\x1b[31m[bold]x[/bold]",
        "UtcTime": "2026-10-12 10:41:58.123",
        "Evil\x1b]0;title\x07Key": "v",
    }
    path = tmp_path / "hostile.jsonl"
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    result = CliRunner().invoke(cli.app, ["validate", str(path), "--no-color"])
    assert result.exit_code == 0
    assert "\x1b" not in result.output
    assert "\\x1b[31m[bold]x[/bold]" in result.output
