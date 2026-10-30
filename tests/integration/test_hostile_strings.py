"""Hostile strings are inert in every output (§12.1, §13.1, P5 gate)."""

import io
from collections.abc import Callable
from typing import Any

import pytest
from rich.console import Console

from helpers.reports import FIXTURES, artifact_lines, frozen_analysis, report, report_text
from lineage_ir.analyze.anchors import load_anchors
from lineage_ir.engine import AnalysisResult
from lineage_ir.render import terminal

HOST = "ws-14.corp.example"


@pytest.fixture(scope="module")
def hostile() -> AnalysisResult:
    return frozen_analysis(FIXTURES / "hostile_strings.jsonl")


def _console() -> Console:
    # A colour terminal, so markup that leaked through would turn into real styles and links.
    return Console(
        record=True,
        width=120,
        force_terminal=True,
        color_system="truecolor",
        emoji=False,
        highlight=False,
        file=io.StringIO(),
        legacy_windows=False,
    )


def _view() -> terminal.View:
    return terminal.View(is_anchor=load_anchors())


def _guid(result: AnalysisResult, image_name_prefix: str) -> str:
    nodes = result.graphs[HOST].nodes
    return next(g for g, n in nodes.items() if (n.image_name or "").startswith(image_name_prefix))


VIEWS: dict[str, Callable[[Console, AnalysisResult], None]] = {
    "analyze": lambda c, r: terminal.render_analyze(c, r, _view()),
    "tree": lambda c, r: terminal.render_tree(c, r, _view()),
    "story": lambda c, r: terminal.render_story(c, r, _view()),
    "inspect-cmd": lambda c, r: terminal.render_inspect(c, r, HOST, _guid(r, "cmd"), _view()),
    "inspect-dropper": lambda c, r: terminal.render_inspect(
        c, r, HOST, _guid(r, "invoice"), _view()
    ),
    "inspect-powershell": lambda c, r: terminal.render_inspect(
        c, r, HOST, _guid(r, "powershell"), _view()
    ),
}


@pytest.mark.parametrize("name", VIEWS)
def test_terminal_views_are_inert(name: str, hostile: AnalysisResult) -> None:
    console = _console()
    VIEWS[name](console, hostile)
    segments = list(console._record_buffer)
    text = "".join(s.text for s in segments)
    assert "\x1b" not in text, "a control sequence from the evidence reached the terminal"
    assert "\x00" not in text and "‮" not in text
    assert " " not in text and " " not in text, "a line separator reached the terminal"
    assert "http://" not in text and "https://" not in text
    assert not any(s.style is not None and s.style.link for s in segments), "evidence became a link"
    assert "\U0001f480" not in text, "an emoji code in the evidence was rendered"


def test_markup_is_shown_literally(hostile: AnalysisResult) -> None:
    console = _console()
    terminal.render_inspect(console, hostile, HOST, _guid(hostile, "cmd"), _view())
    text = console.export_text()
    assert "[bold red]FAKE[/bold red]" in text
    assert "\\x1b[31mRED\\x1b[0m" in text
    assert "=cmd|' /C calc'!A0" in text
    assert "x\\u{2028}y\\u{2029}z" in text
    assert "hxxp[://]203[.]0[.]113[.]5" in text


def test_tree_shows_escaped_dns_and_registry(hostile: AnalysisResult) -> None:
    console = _console()
    terminal.render_analyze(console, hostile, _view())
    text = console.export_text()
    assert "</script><script>alert(1)</script>x\\u{2028}y\\u{2029}z[.]example" in text
    assert "invoice\\u{202e}gpj.exe" in text
    assert "hxxp[://]evil[.]example/payload" in text


def test_json_report_keeps_raw_values_ascii_escaped(hostile: AnalysisResult) -> None:
    text = report_text(hostile)
    assert text.isascii()
    assert "\x1b" not in text and " " not in text and "<script>" in text
    flat = " ".join(_strings(report(hostile)))
    assert "\x1b[31mRED" in flat and "‮" in flat and "http://evil.example/payload" in flat


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return []


def test_artifacts_keep_raw_values(hostile: AnalysisResult) -> None:
    values = " ".join(line.get("value", "") for line in artifact_lines(hostile))
    assert "http://evil.example/payload" in values and "\x1b]8;;" in values
