"""Every bundled rule against its positive and near-miss negative fixture (§14.1, §15.2 P3)."""

from pathlib import Path

import pytest

from helpers.detection import detect_file
from lineage_ir.detect.loader import load_rules
from lineage_ir.ingest.windows.json_reader import read_jsonl

RULES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "rules"
RULE_IDS = [r.id for r in load_rules()]


def test_every_rule_has_both_fixtures() -> None:
    names = sorted(p.name for p in RULES_DIR.glob("*.jsonl"))
    assert names == sorted(f"{i}_{kind}.jsonl" for i in RULE_IDS for kind in ("pos", "neg"))


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_positive_fixture_hits_on_every_record(rule_id: str) -> None:
    path = RULES_DIR / f"{rule_id}_pos.jsonl"
    run = detect_file(path)
    records = {(path.name, item.index) for item in read_jsonl(path)}
    evidence = {(e.file, e.index) for f in run.by_rule(rule_id) for e in f.evidence}
    assert evidence == records
    assert all(f.count == len(f.evidence) for f in run.by_rule(rule_id))


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_negative_fixture_never_hits(rule_id: str) -> None:
    run = detect_file(RULES_DIR / f"{rule_id}_neg.jsonl")
    assert run.ingest.counters.invalid == 0
    assert run.by_rule(rule_id) == []


def test_cmd007_clears_the_security_log() -> None:
    path = RULES_DIR / "CMD-007_pos.jsonl"
    run = detect_file(path)
    commands = {f.details.get("command_line") for f in run.by_rule("CMD-007")}
    assert "wevtutil cl security" in commands


def test_file_stream_to_startup_never_feeds_per004_or_gr004() -> None:
    run = detect_file(RULES_DIR / "PER-004_neg.jsonl")
    streaming = {
        n.guid
        for g in run.graphs.values()
        for n in g.nodes.values()
        if n.is_ghost and any(a.kind == "file_stream" for a in n.activity)
    }
    assert streaming
    assert run.by_rule("PER-004") == []
    # The event 11 actor in the same fixture is a ghost too, so GR-004 does fire there.
    assert {f.guid for f in run.by_rule("GR-004")}.isdisjoint(streaming)
