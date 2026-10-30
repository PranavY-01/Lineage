"""How persistence and drop links appear in views and the report (§9.8 "Display")."""

import io
from pathlib import Path

import pytest
from rich.console import Console

from helpers.chain import EXPLORER, Chain, guid
from helpers.reports import FIXTURES, frozen_analysis, report, validator
from lineage_ir.analyze.anchors import load_anchors
from lineage_ir.engine import AnalysisResult
from lineage_ir.render import terminal

PUBLIC = "C:\\Users\\Public\\"
RUN_KEY = "HKU\\S-1-5-21-1-2-3-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\"
APP = "C:\\Program Files\\App\\app.exe"


def _text(render: object) -> str:
    console = Console(
        record=True, width=200, file=io.StringIO(), color_system=None, legacy_windows=False
    )
    render(console)  # type: ignore[operator]
    return console.export_text()


def _view(**options: object) -> terminal.View:
    return terminal.View(is_anchor=load_anchors(), **options)  # type: ignore[arg-type]


@pytest.fixture(scope="module")
def phish() -> AnalysisResult:
    return frozen_analysis(FIXTURES / "phish_chain.jsonl")


@pytest.fixture
def unlinked(tmp_path: Path) -> AnalysisResult:
    chain = Chain().create(1, EXPLORER)
    chain.create(2, PUBLIC + "tool.exe", 1, 1, parent_image=EXPLORER)
    for n, (name, value) in enumerate((("A", APP), ("B", PUBLIC + "never.exe"))):
        chain.event(
            13,
            2,
            5 + n,
            Image=PUBLIC + "tool.exe",
            EventType="SetValue",
            TargetObject=RUN_KEY + name,
            Details=value,
        )
    chain.create(3, APP, 1, 100, parent_image=EXPLORER)
    return frozen_analysis(chain.write(tmp_path / "in.jsonl"))


def _line_after(text: str, anchor: str) -> str:
    lines = text.splitlines()
    at = next(i for i, line in enumerate(lines) if anchor in line)
    return lines[at + 1]


def test_story_shows_links_under_the_setting_steps(phish: AnalysisResult) -> None:
    text = _text(lambda c: terminal.render_story(c, phish, _view(storyline=1)))
    persistence = _line_after(text, "Registry Run key set:")
    assert "↪ fires later as S2 (exact match: c:\\users\\public\\upd.exe)" in persistence
    dropped = _line_after(text, "powershell.exe wrote C:\\Users\\Public\\upd.exe")
    assert "↪ dropped file runs later as S2 (exact match: c:\\users\\public\\upd.exe)" in dropped


def test_trees_mark_the_later_process(phish: AnalysisResult) -> None:
    for render in (terminal.render_analyze, terminal.render_tree):
        text = _text(lambda c, r=render: r(c, phish, _view()))
        upd = next(line for line in text.splitlines() if "! upd.exe" in line)
        assert "↩ persistence of S1" in upd and "↩ dropped by S1" in upd


def test_unlinked_targets_in_the_story_scope(unlinked: AnalysisResult) -> None:
    text = _text(lambda c: terminal.render_story(c, unlinked, _view(storyline=1)))
    ran = next(line for line in text.splitlines() if "app.exe" in line and "ran as" in line)
    assert guid(3) in ran and "2026-10-12T10:01:40Z" in ran and "in no storyline" in ran
    never = next(line for line in text.splitlines() if "never.exe" in line and "Not" not in line)
    assert "not seen running" in never


def test_report_carries_links_and_unlinked_targets(
    phish: AnalysisResult, unlinked: AnalysisResult
) -> None:
    s1 = report(phish)["storylines"][0]
    assert {(link["kind"], link["to_storyline"]) for link in s1["links"]} == {
        ("persistence", "S2"),
        ("dropped_executed", "S2"),
    }
    assert s1["links"][0]["evidence"][0].keys() == {"file", "index", "record_id"}
    notes = report(unlinked)["storylines"][0]["scope"]["unlinked_targets"]
    assert notes[0] == {
        "reason": "target_not_in_storyline",
        "rule_id": "PER-001",
        "path": APP.lower(),
        "match": "exact",
        "guid": guid(3),
        "start": "2026-10-12T10:01:40Z",
        "source": {"file": "in.jsonl", "index": 2, "record_id": 3},
    }
    assert notes[1]["reason"] == "not_seen_running"
    assert notes[1]["guid"] is None and notes[1]["start"] is None
    for result in (phish, unlinked):
        assert list(validator("report-1.0.json").iter_errors(report(result))) == []
