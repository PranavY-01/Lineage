import pytest
from rich.console import Console

from lineage_ir.render.safe import clean, defang, defang_host, safe, truncate


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
        ("line\u2028sep\u2029para", "line\\u{2028}sep\\u{2029}para"),
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
    assert defang(clean(hostile)) in text


def test_safe_none() -> None:
    assert safe(None) == ""


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("http://203.0.113.50/a", "hxxp[://]203[.]0[.]113[.]50/a"),
        ("HTTPS://Update-CDN.example:8443/x?y=1", "HXXPS[://]Update-CDN[.]example:8443/x?y=1"),
        ("get('http://a.example/p.ps1')", "get('hxxp[://]a[.]example/p.ps1')"),
        ("ftp://files.example/x", "ftp[://]files[.]example/x"),
        ("no url C:\\Users\\Public\\a.dll", "no url C:\\Users\\Public\\a.dll"),
        (
            "two http://a.example and http://b.example",
            "two hxxp[://]a[.]example and hxxp[://]b[.]example",
        ),
    ],
)
def test_defang(raw: str, expected: str) -> None:
    assert defang(raw) == expected


def test_defang_host() -> None:
    assert defang_host("update-cdn.example") == "update-cdn[.]example"


def test_safe_defangs_before_truncating() -> None:
    assert safe("http://a.example/xyz", 12) == "hxxp[://]a[…"
    assert "http" not in safe("x http://203.0.113.5/a")


def test_defang_stays_linear_on_long_input() -> None:
    text = "a" * 1_000_000 + "://" + "b." * 500_000
    assert defang(text).endswith("b[.]")
