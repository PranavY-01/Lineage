"""Determinism, golden outputs, evidence integrity and "no clean on partial" (§14.3)."""

import json
import random
from pathlib import Path
from typing import Any

import pytest

from helpers.golden import CSV_GOLDEN, GOLDEN, TEXT_GOLDEN, golden_path, render
from helpers.reports import FIXTURES, frozen_analysis, report_text
from lineage_ir.engine import run_analysis
from lineage_ir.render import artifacts

DETERMINISM_FIXTURES = ["phish_chain", "hostile_strings", "masquerade", "missing_telemetry"]
BOM = bytes([0xEF, 0xBB, 0xBF])
PROVENANCE = {"source", "evidence", "index", "write_index", "record_id", "create_record"}


@pytest.mark.parametrize("name", DETERMINISM_FIXTURES)
def test_two_runs_are_byte_identical(name: str) -> None:
    path = FIXTURES / f"{name}.jsonl"
    first, second = frozen_analysis(path), frozen_analysis(path)
    assert report_text(first) == report_text(second)
    assert artifacts.artifacts_text(first) == artifacts.artifacts_text(second)


def test_only_run_id_and_times_differ_between_live_runs() -> None:
    path = FIXTURES / "phish_chain.jsonl"
    first = json.loads(report_text(run_analysis([path])))
    second = json.loads(report_text(run_analysis([path])))
    for document in (first, second):
        for key in ("run_id", "started_at", "completed_at"):
            document["envelope"].pop(key)
    assert first == second


def _comparable(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _comparable(v) for k, v in value.items() if k not in PROVENANCE}
    if isinstance(value, list):
        return [_comparable(v) for v in value]
    return value


def test_shuffled_input_gives_the_same_report(tmp_path: Path) -> None:
    source = FIXTURES / "phish_chain.jsonl"
    lines = source.read_text(encoding="utf-8").splitlines()
    baseline = json.loads(report_text(frozen_analysis(source)))
    baseline.pop("input")
    # Records out of file order depend on file order by definition (§10.1).
    baseline["coverage"]["timeline"].pop("out_of_order")
    for seed in range(5):
        shuffled = lines[:]
        random.Random(seed).shuffle(shuffled)
        path = tmp_path / f"{seed}" / source.name
        path.parent.mkdir()
        path.write_text("\n".join(shuffled) + "\n", encoding="utf-8", newline="\n")
        document = json.loads(report_text(frozen_analysis(path)))
        document.pop("input")
        document["coverage"]["timeline"].pop("out_of_order")
        assert _comparable(document) == _comparable(baseline)


@pytest.mark.parametrize("name", sorted(GOLDEN))
def test_golden_output(name: str) -> None:
    expected = golden_path(name).read_bytes()
    assert render(name) == expected, (
        f"{name} changed; if intended, run scripts/update_golden.py and note it in CHANGELOG.md"
    )


def test_golden_files_do_not_hardcode_the_version() -> None:
    from lineage_ir import __version__

    for name in TEXT_GOLDEN:
        text = golden_path(name).read_text(encoding="utf-8")
        assert __version__ not in text and "<version>" in text
    assert __version__.encode() not in golden_path(CSV_GOLDEN).read_bytes()


def test_committed_golden_csv_keeps_its_bom_and_crlf() -> None:
    # .gitattributes marks *.csv as -text so a checkout never rewrites CRLF as LF.
    data = golden_path(CSV_GOLDEN).read_bytes()
    assert data.startswith(BOM + b'"storyline","step","time_utc"')
    crlf = bytes([13, 10])
    assert data.count(crlf) >= 2 and data.endswith(crlf)
    assert bytes([10]) not in data.replace(crlf, b"")


def _records(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


@pytest.mark.parametrize("name", ["phish_chain", "hostile_strings", "masquerade", "ghosts"])
def test_every_evidence_reference_resolves(name: str) -> None:
    path = FIXTURES / f"{name}.jsonl"
    records = _records(path)
    result = frozen_analysis(path)
    refs = [e for f in result.findings for e in f.evidence]
    refs += [s.source for story in result.storylines for s in story.steps]
    assert refs
    for ref in refs:
        assert ref.file == path.name
        assert ref.file_sha256 == result.inputs[0].sha256
        record = records[ref.index]
        assert record.get("RecordNumber") == ref.record_id


@pytest.mark.parametrize("path", sorted(FIXTURES.glob("*.jsonl")), ids=lambda p: p.name)
def test_no_fixture_with_a_coverage_reason_exits_0(path: Path) -> None:
    result = run_analysis([path])
    if result.coverage.reasons:
        assert result.exit_code == 4 and result.status == "incomplete"
    assert (result.exit_code == 0) == (result.status == "no_findings")
