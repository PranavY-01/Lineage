"""Golden outputs for phish_chain.jsonl (§14.3 item 4).

Both the test and ``scripts/update_golden.py`` build the outputs here with a frozen clock and
run ID, and compare bytes. Text views and the report go through the real CLI; the version
string is replaced by ``<version>`` so no golden file hardcodes it (amendment 17). The CSV
timeline is built by its renderer and kept byte for byte, BOM and CRLF included
(``*.csv -text`` in .gitattributes).
"""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from helpers.reports import FIXTURES, FROZEN_US, RUN_ID, frozen_analysis
from lineage_ir import __version__, cli
from lineage_ir.render import csv_timeline

GOLDEN_DIR = FIXTURES / "expected"
SOURCE = FIXTURES / "phish_chain.jsonl"
VERSION_MARK = "<version>"
ENV = {"COLUMNS": "120", "NO_COLOR": "1", "TERM": "dumb"}

# Golden file name → CLI arguments after the input path (text outputs).
TEXT_GOLDEN = {
    "phish_chain.report.json": ["analyze", "--format", "json"],
    "phish_chain.story.txt": ["story", "--no-color"],
}
CSV_GOLDEN = "phish_chain.timeline.csv"
GOLDEN = [*TEXT_GOLDEN, CSV_GOLDEN]


def normalize(text: str) -> str:
    return text.replace("\r\n", "\n").replace(__version__, VERSION_MARK)


def render(name: str) -> bytes:
    """The current output for one golden file, as the bytes the file must hold."""
    if name == CSV_GOLDEN:
        return csv_timeline.csv_bytes(frozen_analysis(SOURCE))
    command, *options = TEXT_GOLDEN[name]
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(cli, "clock", lambda: FROZEN_US)
        patch.setattr(cli, "run_id_factory", lambda: RUN_ID)
        result = CliRunner().invoke(cli.app, [command, str(SOURCE), *options], env=ENV)
    if result.exit_code not in (0, 1, 4):
        raise RuntimeError(f"{name}: lineage {command} exited {result.exit_code}")
    return normalize(result.stdout).encode("utf-8")


def golden_path(name: str) -> Path:
    return GOLDEN_DIR / name
