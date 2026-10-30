"""P4 gate: storylines for phish_chain.jsonl match the hand-derived oracle (the hero dataset
check is PENDING P0 data)."""

import json
from pathlib import Path

import pytest

from lineage_ir.engine import AnalysisResult, run_analysis
from lineage_ir.ingest.timeparse import format_rfc3339

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
ORACLE = json.loads((FIXTURES / "expected" / "phish_chain.storylines.json").read_text("utf-8"))


@pytest.fixture(scope="module")
def result() -> AnalysisResult:
    return run_analysis([FIXTURES / ORACLE["fixture"]])


def test_status_and_exit_code(result: AnalysisResult) -> None:
    assert result.status == ORACLE["status"]
    assert result.exit_code == ORACLE["exit_code"]
    assert result.coverage.complete


def test_findings(result: AnalysisResult) -> None:
    assert sorted((f.rule_id, f.guid) for f in result.findings) == sorted(
        tuple(item) for item in ORACLE["findings"]
    )


def test_storylines_match_the_oracle(result: AnalysisResult) -> None:
    graph = result.graphs[ORACLE["host"]]
    assert len(result.storylines) == len(ORACLE["storylines"])
    for expected, actual in zip(ORACLE["storylines"], result.storylines, strict=True):
        assert actual.storyline_id == expected["storyline_id"]
        assert actual.host == ORACLE["host"]
        assert actual.root_guid == expected["root_guid"]
        assert actual.root_image_name == expected["root_image_name"]
        assert actual.anchor_image_name == expected["anchor_image_name"]
        assert list(actual.flagged) == expected["flagged"]
        assert list(actual.path_nodes) == expected["path_nodes"]
        assert list(actual.descendant_nodes) == expected["descendant_nodes"]
        assert list(actual.nodes) == expected["nodes"]
        assert [graph.nodes[g].image_name for g in actual.nodes] == expected["node_images"]
        assert len(actual.finding_ids) == expected["finding_count"]
        assert actual.max_severity == expected["max_severity"]
        assert list(actual.tactics) == expected["tactics"]
        assert list(actual.users) == expected["users"]
        assert format_rfc3339(actual.start_us) == expected["start"]
        assert format_rfc3339(actual.end_us) == expected["end"]
