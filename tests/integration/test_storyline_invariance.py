"""Shuffle invariance for findings, storylines and coverage (§14.3 item 1)."""

import random
from pathlib import Path
from typing import Any

import pytest

from lineage_ir.engine import AnalysisResult, run_analysis

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
PROVENANCE = {"source", "evidence", "create_record", "index", "write_index", "file_sha256"}


def _comparable(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _comparable(v) for k, v in value.items() if k not in PROVENANCE}
    if isinstance(value, list | tuple):
        return [_comparable(v) for v in value]
    return value


def _outcome(result: AnalysisResult) -> Any:
    return _comparable(
        {
            "findings": [f.model_dump() for f in result.findings],
            "storylines": [s.model_dump() for s in result.storylines],
            "coverage": result.coverage.model_dump(exclude={"timeline": {"out_of_order"}}),
            "status": (result.result, result.status, result.exit_code),
        }
    )


@pytest.mark.parametrize("name", ["phish_chain", "masquerade", "benign_host"])
def test_shuffled_inputs_give_the_same_analysis(tmp_path: Path, name: str) -> None:
    source = FIXTURES / f"{name}.jsonl"
    lines = source.read_text(encoding="utf-8").splitlines()
    baseline = _outcome(run_analysis([source]))
    for seed in range(20):
        shuffled = lines[:]
        random.Random(seed).shuffle(shuffled)
        directory = tmp_path / str(seed)
        directory.mkdir()
        path = directory / source.name
        path.write_text("\n".join(shuffled) + "\n", encoding="utf-8", newline="\n")
        assert _outcome(run_analysis([path])) == baseline
