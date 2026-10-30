"""Artifacts JSONL for Lucent (§12.4)."""

from collections import Counter
from pathlib import Path

import pytest

from helpers.chain import EXPLORER, Chain
from helpers.reports import FIXTURES, RUN_ID, artifact_lines, frozen_analysis, validator
from lineage_ir.engine import AnalysisResult
from lineage_ir.render import artifacts


@pytest.fixture(scope="module")
def phish() -> AnalysisResult:
    return frozen_analysis(FIXTURES / "phish_chain.jsonl")


def test_header_line(phish: AnalysisResult) -> None:
    header = artifact_lines(phish)[0]
    assert header == {
        "schema": "lineage-artifacts",
        "schema_version": "1.0",
        "tool_version": header["tool_version"],
        "run_id": RUN_ID,
        "source_sha256": [phish.inputs[0].sha256],
    }


def test_kinds_and_raw_values(phish: AnalysisResult) -> None:
    lines = artifact_lines(phish)[1:]
    values = {(line["storyline"], line["kind"], line["value"]) for line in lines}
    assert ("S1", "destination", "203.0.113.10:80") in values
    assert ("S1", "destination_hostname", "dl.example") in values
    assert ("S1", "dns_query", "dl.example") in values
    assert ("S1", "file", "C:\\Users\\Public\\upd.exe") in values
    decoded = [v for s, k, v in values if k == "decoded_command"]
    # Raw, not defanged: Lucent needs the original URL.
    assert all("http://203.0.113.10/a.ps1" in v for v in decoded) and decoded
    registry = [v for s, k, v in values if k == "registry_value"]
    assert registry and registry[0].endswith("\\Run\\Updater=C:\\Users\\Public\\upd.exe")
    assert any(k == "image_hash" for _, k, _ in values)
    assert {line["storyline"] for line in lines} == {"S1", "S2"}


def test_record_ids_point_at_the_source_events(phish: AnalysisResult) -> None:
    lines = artifact_lines(phish)[1:]
    network = next(line for line in lines if line["kind"] == "destination")
    assert network["record_id"] == 5008
    command = next(line for line in lines if line["kind"] == "command_line")
    assert command["record_id"] == 5003


def test_only_storyline_nodes_contribute(phish: AnalysisResult) -> None:
    guids = {line["process_guid"] for line in artifact_lines(phish)[1:]}
    members = {g for s in phish.storylines for g in s.nodes}
    assert guids <= members
    graph = phish.graphs["ws-14.corp.example"]
    notepad = [g for g, n in graph.nodes.items() if n.image_name == "notepad.exe"]
    assert notepad and not guids & set(notepad)


def test_identical_lines_are_written_once(tmp_path: Path) -> None:
    chain = Chain().create(1, EXPLORER)
    chain.create(2, "C:\\Users\\Public\\tool.exe", 1, 1)
    for n in range(3):
        chain.connect(2, 2 + n, "203.0.113.9", Image="C:\\Users\\Public\\tool.exe")
    result = frozen_analysis(chain.write(tmp_path / "in.jsonl"))
    counts = Counter((line["kind"], line["value"]) for line in artifact_lines(result)[1:])
    assert counts[("destination", "203.0.113.9:443")] == 1


def test_ipv6_destinations_are_bracketed(tmp_path: Path) -> None:
    chain = Chain().create(1, EXPLORER)
    chain.create(2, "C:\\Users\\Public\\tool.exe", 1, 1)
    chain.connect(2, 2, "2001:db8::5", Image="C:\\Users\\Public\\tool.exe")
    result = frozen_analysis(chain.write(tmp_path / "in.jsonl"))
    values = {line["value"] for line in artifact_lines(result)[1:]}
    assert "[2001:db8::5]:443" in values


@pytest.mark.parametrize("name", ["phish_chain", "hostile_strings", "masquerade", "benign_host"])
def test_lines_validate_and_are_lf_ascii(name: str) -> None:
    result = frozen_analysis(FIXTURES / f"{name}.jsonl")
    text = artifacts.artifacts_text(result)
    assert text.isascii() and "\r" not in text and text.endswith("\n")
    check = validator("artifacts-1.0.json")
    header = validator("artifacts-1.0.json", "header")
    item = validator("artifacts-1.0.json", "artifact")
    lines = artifact_lines(result)
    assert header.is_valid(lines[0])
    for line in lines:
        assert check.is_valid(line)
    for line in lines[1:]:
        assert item.is_valid(line)


def test_hostile_values_stay_raw_inside_valid_json() -> None:
    result = frozen_analysis(FIXTURES / "hostile_strings.jsonl")
    values = [line["value"] for line in artifact_lines(result)[1:]]
    assert any("</script><script>" in v for v in values)
    assert any("\x1b[31m" in v for v in values)
    assert any(v.startswith("cmd.exe /c =cmd|") for v in values)
