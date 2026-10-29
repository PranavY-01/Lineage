import pytest
from rich.console import Console

from lineage_ir.render.safe import clean, safe, truncate


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("a\x1b[31mred", "a\\x1b[31mred"),
        ("line\nbreak\ttab", "line\\x0abreak\\x09tab"),
        ("nul\x00", "nul\\x00"),
        ("del\x7f", "del\\x7f"),
        ("c1\x85", "c1\\x85"),
        ("bidi\u202eexe.txt", "bidi\\u{202e}exe.txt"),
        ("iso\u2066x\u2069", "iso\\u{2066}x\\u{2069}"),
        ("plain C:\\Windows", "plain C:\\Windows"),
    ],
)
def test_clean(raw: str, expected: str) -> None:
    assert clean(raw) == expected


def test_truncate() -> None:
    assert truncate("abcdef", 4) == "abc…"
    assert truncate("abc", 4) == "abc"
    assert truncate("abcdef", None) == "abcdef"


@pytest.mark.parametrize(
    "hostile",
    [
        "[bold red]fake[/]",
        "[link=http://203.0.113.5]click[/link]",
        "C:\\Temp\\",
        "x\x1b]8;;http://198.51.100.1\x1b\\y",
        ":skull: emoji",
    ],
)
def test_safe_output_is_inert_in_rich(hostile: str) -> None:
    console = Console(record=True, width=200, emoji=False, highlight=False, color_system=None)
    console.print(f"[green]{safe(hostile)}[/]")
    text = console.export_text()
    assert "\x1b" not in text
    assert clean(hostile) in text


def test_safe_none() -> None:
    assert safe(None) == ""
