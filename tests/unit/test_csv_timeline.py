"""CSV storyline timeline (§12.6, stretch S3)."""

import csv
import io
import json
import random
from pathlib import Path

import pytest
from lineage_ir.render.csv_timeline import csv_bytes, neutralize

from helpers.chain import EXPLORER, Chain
from helpers.reports import FIXTURES, frozen_analysis
from lineage_ir.config import CSV_COLUMNS
from lineage_ir.engine import AnalysisResult
from lineage_ir.ingest.timeparse import format_rfc3339

BOM = bytes([0xEF, 0xBB, 0xBF])
CRLF = bytes([13, 10])
PUBLIC = "C:\\Users\\Public\\"
IDEOGRAPHIC_SPACE = chr(0x3000)
FULLWIDTH = {"=": chr(0xFF1D), "+": chr(0xFF0B), "-": chr(0xFF0D), "@": chr(0xFF20)}
REPLACEMENT = chr(0xFFFD)
HEADER = (
    "storyline,step,time_utc,tactic,technique,severity,host,process_guid,image_name,action,"
    "text,record_id,file"
)


def _rows(data: bytes) -> list[list[str]]:
    assert data.startswith(BOM)
    text = data[len(BOM) :].decode("utf-8")
    return list(csv.reader(io.StringIO(text, newline="")))


@pytest.fixture(scope="module")
def phish() -> AnalysisResult:
    return frozen_analysis(FIXTURES / "phish_chain.jsonl")


# Formula injection (§12.6).


@pytest.mark.parametrize(
    "cell",
    [
        "=cmd|' /C calc'!A0",
        "+1",
        "-2+3",
        "@SUM(A1)",
        "\tx",
        "\rx",
        "  =x",
        " \t=x",
        "\n=x",
        IDEOGRAPHIC_SPACE + "=x",
        *FULLWIDTH.values(),
        IDEOGRAPHIC_SPACE + FULLWIDTH["="] + "x",
        "   \t",
    ],
)
def test_formula_cells_are_prefixed(cell: str) -> None:
    assert neutralize(cell) == "'" + cell


@pytest.mark.parametrize(
    "cell",
    ["", "   ", "cmd=1", "a+b", "x@y", "C:\\a-b\\=c.exe", "'=already", "123", "S1"],
)
def test_other_cells_are_unchanged(cell: str) -> None:
    assert neutralize(cell) == cell


# File format.


def test_bom_header_crlf_and_quoting(phish: AnalysisResult) -> None:
    data = csv_bytes(phish)
    assert data.startswith(BOM + b'"storyline","step","time_utc","tactic"')
    header_line = data[len(BOM) : data.index(CRLF)].decode()
    assert header_line == ",".join(f'"{c}"' for c in CSV_COLUMNS)
    assert ",".join(CSV_COLUMNS) == HEADER
    lines = data[len(BOM) :].split(CRLF)
    assert lines[-1] == b""  # every line, the last one too, ends in CRLF
    for line in lines[:-1]:
        assert line.startswith(b'"') and line.endswith(b'"')
        assert bytes([10]) not in line


def test_one_row_per_step_in_rank_and_step_order(phish: AnalysisResult) -> None:
    header, *rows = _rows(csv_bytes(phish))
    assert tuple(header) == CSV_COLUMNS
    expected = [(s.storyline_id, str(step.n)) for s in phish.storylines for step in s.steps]
    assert [(r[0], r[1]) for r in rows] == expected
    first = phish.storylines[0].steps[0]
    row = dict(zip(CSV_COLUMNS, rows[0], strict=True))
    assert row["time_utc"] == format_rfc3339(first.ts_us)
    assert row["tactic"] == "" and row["severity"] == "" and row["technique"] == ""
    assert row["host"] == "ws-14.corp.example"
    assert row["process_guid"] == first.guid and row["image_name"] == "outlook.exe"
    assert row["action"] == "process_create"
    assert row["record_id"] == str(first.source.record_id)
    assert row["file"] == "phish_chain.jsonl"
    flagged = next(r for r in rows if r[5] == "high")
    assert flagged[3] == "execution" and flagged[4] == "T1204.002"


def test_values_stay_raw(phish: AnalysisResult) -> None:
    text = csv_bytes(phish).decode("utf-8")
    assert "http://203.0.113.10/a.ps1" in text  # not defanged (§12: machine output)
    assert "hxxp" not in text


def _chain_with(command: str, tmp_path: Path) -> AnalysisResult:
    chain = Chain().create(1, EXPLORER)
    chain.create(2, PUBLIC + "tool.exe", 1, 1, command, EXPLORER)
    return frozen_analysis(chain.write(tmp_path / "in.jsonl"))


def test_quotes_and_newlines_inside_cells(tmp_path: Path) -> None:
    result = _chain_with('tool.exe "quoted" arg\nsecond line\r\nthird', tmp_path)
    data = csv_bytes(result)
    assert b'""quoted""' in data
    _, *rows = _rows(data)
    text = next(r[10] for r in rows if "quoted" in r[10])
    assert '"quoted" arg\nsecond line\r\nthird' in text


def test_lone_surrogates_become_replacement_characters(tmp_path: Path) -> None:
    lone = chr(0xD800)
    result = _chain_with(f"tool.exe {lone}x", tmp_path)
    assert any(lone in s.text for s in result.storylines[0].steps)
    _, *rows = _rows(csv_bytes(result))
    assert any(f"{REPLACEMENT}x" in r[10] for r in rows)


def test_display_filters_never_trim_the_csv(phish: AnalysisResult) -> None:
    path = FIXTURES / "phish_chain.jsonl"
    filtered = frozen_analysis(path, since="2026-10-12T10:59:00Z", focus="image:upd.exe")
    assert csv_bytes(filtered) == csv_bytes(phish)


def test_no_storylines_gives_the_header_only() -> None:
    data = csv_bytes(frozen_analysis(FIXTURES / "benign_host.jsonl"))
    assert data == BOM + ",".join(f'"{c}"' for c in CSV_COLUMNS).encode() + CRLF


def test_hostile_cells_are_neutralized_end_to_end() -> None:
    _, *rows = _rows(csv_bytes(frozen_analysis(FIXTURES / "hostile_strings.jsonl")))
    triggers = set("=+-@\t\r") | set(FULLWIDTH.values())
    prefixed = 0
    for row in rows:
        for cell in row:
            stripped = cell.lstrip(" " + IDEOGRAPHIC_SPACE + "\n")
            if cell.startswith("'"):
                prefixed += 1
                continue
            assert stripped[:1] not in triggers, cell
    assert prefixed >= 4
    names = {row[8] for row in rows}
    assert "'=sum(1+1).exe" in names
    assert "'@cmd.exe" in names
    assert "'" + FULLWIDTH["="] + "calc.exe" in names
    assert "' -x.exe" in names


def test_two_runs_and_shuffled_input_give_the_same_bytes(tmp_path: Path) -> None:
    source = FIXTURES / "phish_chain.jsonl"
    baseline = csv_bytes(frozen_analysis(source))
    assert csv_bytes(frozen_analysis(source)) == baseline
    lines = source.read_text(encoding="utf-8").splitlines()
    for seed in range(5):
        shuffled = lines[:]
        random.Random(seed).shuffle(shuffled)
        path = tmp_path / str(seed) / source.name
        path.parent.mkdir()
        path.write_text("\n".join(shuffled) + "\n", encoding="utf-8", newline="\n")
        assert csv_bytes(frozen_analysis(path)) == baseline


def test_fixture_json_has_no_raw_separators() -> None:
    # The hostile fixture keeps every non-ASCII character escaped (json.dumps default).
    for line in (FIXTURES / "hostile_strings.jsonl").read_text(encoding="utf-8").splitlines():
        assert line.isascii()
        json.loads(line)
