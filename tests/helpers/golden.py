"""Golden outputs for phish_chain.jsonl (§14.3 item 4).

Both the test and ``scripts/update_golden.py`` build the outputs here, through the real CLI
with a frozen clock and run ID. The version string is replaced by ``<version>`` so no golden
file hardcodes it (amendment 17).
"""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from helpers.reports import FIXTURES, FROZEN_US, RUN_ID
from lineage_ir import __version__, cli

GOLDEN_DIR = FIXTURES / "expected"
SOURCE = FIXTURES / "phish_chain.jsonl"
VERSION_MARK = "<version>"
ENV = {"COLUMNS": "120", "NO_COLOR": "1", "TERM": "dumb"}

# Golden file name → CLI arguments after the input path.
GOLDEN = {
    "phish_chain.report.json": ["analyze", "--format", "json"],
    "phish_chain.story.txt": ["story", "--no-color"],
}


def normalize(text: str) -> str:
    return text.replace("\r\n", "\n").replace(__version__, VERSION_MARK)


def render(name: str) -> str:
    """The current output for one golden file, normalized."""
    command, *options = GOLDEN[name]
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(cli, "clock", lambda: FROZEN_US)
        patch.setattr(cli, "run_id_factory", lambda: RUN_ID)
        result = CliRunner().invoke(cli.app, [command, str(SOURCE), *options], env=ENV)
    if result.exit_code not in (0, 1, 4):
        raise RuntimeError(f"{name}: lineage {command} exited {result.exit_code}")
    return normalize(result.stdout)


def golden_path(name: str) -> Path:
    return GOLDEN_DIR / name
