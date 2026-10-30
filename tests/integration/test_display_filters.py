"""Display filters (§9.7): the time window and focus choose what is shown, nothing else."""

from pathlib import Path

import pytest

from lineage_ir.analyze.filters import (
    make_params,
    visible_findings,
    visible_steps,
    visible_storylines,
)
from lineage_ir.analyze.focus import focus_set, resolve_focus
from lineage_ir.engine import AnalysisResult, run_analysis

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture(scope="module")
def phish() -> AnalysisResult:
    return run_analysis([FIXTURES / "phish_chain.jsonl"])


def _ids(stories: tuple[object, ...]) -> list[str]:
    return [s.storyline_id for s in stories]  # type: ignore[attr-defined]


def test_no_filter_shows_everything(phish: AnalysisResult) -> None:
    params = make_params()
    assert _ids(visible_storylines(phish.storylines, params)) == ["S1", "S2"]
    assert visible_findings(phish.findings, params) == phish.findings


def test_time_window_hides_storylines_findings_and_steps(phish: AnalysisResult) -> None:
    late = make_params(since="2026-10-12T10:03:00Z")
    assert _ids(visible_storylines(phish.storylines, late)) == ["S2"]
    assert {f.rule_id for f in visible_findings(phish.findings, late)} == {
        "GR-002",
        "GR-003",
        "LOC-001",
    }
    s2 = phish.storylines[1]
    assert [s.n for s in visible_steps(s2, late)] == [2, 3, 4, 5]
    early = make_params(until="2026-10-12T10:01:30Z")
    assert _ids(visible_storylines(phish.storylines, early)) == ["S1"]
    around = make_params(around="2026-10-12T11:00:40Z", window="1m")
    assert _ids(visible_storylines(phish.storylines, around)) == ["S2"]
    assert [s.n for s in visible_steps(s2, around)] == [2, 3, 4, 5]


def test_focus_limits_storylines_and_findings(phish: AnalysisResult) -> None:
    params = make_params(focus="image:upd.exe")
    focus = focus_set(phish.graphs, resolve_focus(phish.graphs, "image:upd.exe"))
    assert _ids(visible_storylines(phish.storylines, params, focus)) == ["S2"]
    assert {f.rule_id for f in visible_findings(phish.findings, params, focus)} == {
        "GR-002",
        "GR-003",
        "LOC-001",
    }
    word = focus_set(phish.graphs, resolve_focus(phish.graphs, "image:winword.exe"))
    assert _ids(visible_storylines(phish.storylines, params, word)) == ["S1"]
