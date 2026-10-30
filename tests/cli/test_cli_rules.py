"""`lineage rules` (§11.2): 24 entries sorted by ID, text and JSON with the series envelope."""

import json
import os
import subprocess
import sys
from datetime import UTC, datetime

import pytest
from typer.testing import CliRunner

from lineage_ir import cli
from lineage_ir.ingest.timeparse import to_us

RUN_ID = "00000000-0000-4000-8000-000000000002"
FROZEN_US = to_us(datetime(2026, 10, 30, 9, 0, 0, tzinfo=UTC))
EXPECTED_IDS = sorted(
    [
        *(f"LIN-00{n}" for n in (1, 2, 3)),
        *(f"CMD-00{n}" for n in range(1, 8)),
        "LOC-001",
        "LOC-002",
        *(f"PER-00{n}" for n in range(1, 5)),
        "CRD-001",
        "CRD-002",
        "INJ-001",
        "NET-001",
        *(f"GR-00{n}" for n in range(1, 5)),
    ]
)


def run(*args: str) -> subprocess.CompletedProcess[bytes]:
    env = dict(os.environ, NO_COLOR="1", COLUMNS="200", PYTHONIOENCODING="utf-8")
    return subprocess.run(
        [sys.executable, "-m", "lineage_ir", *args],
        capture_output=True,
        env=env,
        timeout=120,
        check=False,
    )


def test_rules_json_lists_24_entries_sorted_by_id() -> None:
    proc = run("rules", "--format", "json")
    assert proc.returncode == 0
    assert proc.stdout.endswith(b"}\n") and b"\r" not in proc.stdout
    document = json.loads(proc.stdout)
    assert document["kind"] == "rules"
    assert document["envelope"]["schema"] == "7d7b-report"
    assert document["envelope"]["tool"] == "Lineage"
    rules = document["rules"]
    assert [r["id"] for r in rules] == EXPECTED_IDS
    assert list(rules[0]) == ["id", "kind", "title", "severity", "event_ids", "attack", "tactics"]
    by_id = {r["id"]: r for r in rules}
    assert by_id["GR-003"] == {
        "id": "GR-003",
        "kind": "graph",
        "title": "Dropped file later executed",
        "severity": "medium",
        "event_ids": [1, 11],
        "attack": ["T1105"],
        "tactics": ["command-and-control"],  # ATT&CK v20 (amendment 23)
    }
    assert by_id["PER-003"]["kind"] == "event"
    assert by_id["PER-003"]["event_ids"] == [1, 13]
    assert by_id["LOC-001"]["attack"] == []
    assert sum(r["kind"] == "graph" for r in rules) == 4


def test_rules_text_table() -> None:
    proc = run("rules")
    assert proc.returncode == 0
    text = proc.stdout.decode("utf-8")
    for rule_id in EXPECTED_IDS:
        assert rule_id in text
    assert text.index("CMD-001") < text.index("GR-001") < text.index("PER-004")
    assert "T1003.001" in text and "credential-access" in text


@pytest.fixture
def frozen(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "clock", lambda: FROZEN_US)
    monkeypatch.setattr(cli, "run_id_factory", lambda: RUN_ID)


def test_rules_json_is_deterministic(frozen: None) -> None:
    runner = CliRunner()
    first = runner.invoke(cli.app, ["rules", "--format", "json"])
    second = runner.invoke(cli.app, ["rules", "--format", "json"])
    assert first.exit_code == 0
    assert first.stdout == second.stdout
    envelope = json.loads(first.stdout)["envelope"]
    assert envelope["run_id"] == RUN_ID
    assert envelope["started_at"] == "2026-10-30T09:00:00Z"
