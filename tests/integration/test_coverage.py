"""Coverage (§10): every reason code, informational signals, rule evaluability, status table."""

import json
from pathlib import Path
from typing import Any

import pytest

from helpers.chain import Chain
from lineage_ir.analyze.filters import make_params
from lineage_ir.engine import AnalysisResult, run_analysis

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
BENIGN = FIXTURES / "benign_host.jsonl"


def rows_of(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text("utf-8").splitlines() if line.strip()]


def write(tmp_path: Path, rows: list[Any], name: str = "in.jsonl") -> Path:
    path = tmp_path / name
    text = "".join((r if isinstance(r, str) else json.dumps(r)) + "\n" for r in rows)
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


def benign_plus(tmp_path: Path, chain: Chain) -> AnalysisResult:
    return run_analysis([write(tmp_path, rows_of(BENIGN) + chain.rows)])


def test_benign_host_is_complete_and_clean() -> None:
    result = run_analysis([BENIGN])
    assert result.coverage.complete and result.coverage.reasons == ()
    assert result.findings == () and result.storylines == ()
    assert (result.result, result.status, result.exit_code) == ("no_findings", "no_findings", 0)
    assert result.coverage.event_ids_missing == ()
    assert len(result.coverage.rules) == 24
    assert {c.state for c in result.coverage.rules.values()} == {"evaluable"}


def test_missing_telemetry_reasons() -> None:
    result = run_analysis([FIXTURES / "missing_telemetry.jsonl"])
    coverage = result.coverage
    assert coverage.reasons == (
        "not_evaluable:CRD-001",
        "not_evaluable:GR-003",
        "not_evaluable:INJ-001",
        "not_evaluable:PER-001",
        "not_evaluable:PER-004",
        "partially_evaluable:PER-003",
    )
    assert coverage.rules["PER-003"].state == "partially_evaluable"
    assert coverage.rules["PER-003"].missing_event_ids == (13,)
    assert coverage.rules["GR-003"].missing_event_ids == (11,)
    assert coverage.rules["CRD-001"].missing_event_ids == (10,)
    assert coverage.rules["LIN-001"].state == "evaluable"
    assert coverage.rules["LIN-001"].events_examined == 5
    assert coverage.event_ids_missing == (5, 7, 8, 10, 11, 12, 13, 22, 23)
    assert (result.status, result.exit_code) == ("incomplete", 4)


@pytest.mark.parametrize(
    ("source", "options", "reason"),
    [
        ("empty", {}, "no_events"),
        ("broken/invalid_mix.jsonl", {}, "invalid_records"),
        ("duplicates.jsonl", {}, "duplicate_conflicts"),
        ("cycle.jsonl", {}, "cycles_broken"),
        ("benign_host.jsonl", {"max_records": 10}, "record_cap_reached"),
        ("missing_telemetry.jsonl", {}, "not_evaluable:CRD-001"),
        ("missing_telemetry.jsonl", {}, "partially_evaluable:PER-003"),
    ],
)
def test_each_reason_code_from_its_fixture(
    tmp_path: Path, source: str, options: dict[str, Any], reason: str
) -> None:
    path = write(tmp_path, []) if source == "empty" else FIXTURES / source
    result = run_analysis([path], make_params(**options))
    assert reason in result.coverage.reasons
    assert not result.coverage.complete
    assert result.exit_code == 4


def test_creation_conflicts_feed_duplicate_conflicts(tmp_path: Path) -> None:
    chain = Chain().create(1, "C:\\Tools\\a.exe", None, 0, command="a.exe one")
    chain.create(1, "C:\\Tools\\a.exe", None, 1, command="a.exe two")
    result = benign_plus(tmp_path, chain)
    assert result.coverage.counters.duplicate_conflicts == 1
    assert result.coverage.reasons == ("duplicate_conflicts",)


def test_informational_signals_never_create_reasons(tmp_path: Path) -> None:
    chain = Chain()
    # Ghost with network activity (also a GR-004 info finding) and an unattached event.
    chain.connect(90, 10, "198.51.100.77", Image="C:\\Tools\\beacon.exe")
    chain.event(
        3, None, 11, ProcessGuid="-", Image="C:\\Tools\\x.exe", DestinationIp="198.51.100.78"
    )
    # A ghost parent known only by a bare anchor name (anchor_unverified).
    chain.create(91, "C:\\Tools\\child.exe", 92, 12, parent_image="explorer.exe")
    # Another host, and a telemetry gap of two hours at the end.
    chain.create(93, "C:\\Tools\\other.exe", None, 13, host="ws-15.corp.example")
    chain.create(94, "C:\\Tools\\late.exe", None, 3 * 3600)
    rows = rows_of(BENIGN) + chain.rows
    rows[5], rows[6] = rows[6], rows[5]  # out of order
    rows.append({"EventID": 4624, "Channel": "Security", "Hostname": "ws-14.corp.example"})
    result = run_analysis([write(tmp_path, rows)])
    coverage = result.coverage
    assert coverage.reasons == () and coverage.complete
    counters = coverage.counters
    assert counters.ghosts.get("activity_reference", 0) >= 1
    assert counters.unattached_events == 1
    assert counters.anchor_unverified == 1
    assert counters.irrelevant == 1
    assert coverage.timeline.out_of_order >= 1
    assert len(coverage.hosts) == 2
    assert any(g.seconds >= 3600 for g in coverage.timeline.gaps)
    assert (result.status, result.exit_code) == ("findings_detected", 1)


def test_telemetry_gaps_count_image_loads(tmp_path: Path) -> None:
    chain = Chain().create(1, "C:\\Tools\\a.exe", None, 0)
    chain.event(7, 1, 3600, Image="C:\\Tools\\a.exe", ImageLoaded="C:\\Windows\\System32\\x.dll")
    chain.create(2, "C:\\Tools\\b.exe", None, 7200)
    path = write(tmp_path, chain.rows)
    gaps = run_analysis([path]).coverage.timeline.gaps
    assert [(g.host, g.seconds) for g in gaps] == [
        ("ws-14.corp.example", 3600),
        ("ws-14.corp.example", 3600),
    ]
    assert gaps[0].to_us == gaps[1].from_us
    assert run_analysis([path], make_params(telemetry_gap="2h")).coverage.timeline.gaps == ()


def test_event_7_is_listed_missing_but_never_a_reason(tmp_path: Path) -> None:
    rows = [r for r in rows_of(BENIGN) if r["EventID"] != 7]
    result = run_analysis([write(tmp_path, rows)])
    assert result.coverage.event_ids_missing == (7,)
    assert result.coverage.reasons == () and result.exit_code == 0


def test_disabled_rules_are_not_listed_and_create_no_reasons() -> None:
    result = run_analysis(
        [FIXTURES / "missing_telemetry.jsonl"], make_params(rules="LIN,CMD,NET-001")
    )
    assert sorted(result.coverage.rules) == sorted(
        ["LIN-001", "LIN-002", "LIN-003", *(f"CMD-00{n}" for n in range(1, 8)), "NET-001"]
    )
    assert result.coverage.reasons == ()
    assert (result.status, result.exit_code) == ("no_findings", 0)


def test_min_severity_drops_findings_before_storylines() -> None:
    phish = FIXTURES / "phish_chain.jsonl"
    full = run_analysis([phish])
    high = run_analysis([phish], make_params(min_severity="high"))
    assert {f.severity for f in high.findings} == {"high"}
    assert len(high.storylines) == 1 and len(full.storylines) == 2
    assert high.coverage.rules["LOC-001"].findings == 0
    assert full.coverage.rules["LOC-001"].findings == 1


@pytest.mark.parametrize(
    ("extra", "source", "expected"),
    [
        (False, "benign_host.jsonl", ("no_findings", "no_findings", 0)),
        (True, "benign_host.jsonl", ("findings_detected", "findings_detected", 1)),
        (False, "missing_telemetry.jsonl", ("no_findings", "incomplete", 4)),
        (True, "missing_telemetry.jsonl", ("findings_detected", "incomplete", 4)),
    ],
)
def test_status_table(tmp_path: Path, extra: bool, source: str, expected: tuple[Any, ...]) -> None:
    rows = rows_of(FIXTURES / source)
    if extra:
        rows += Chain().create(70, "C:\\Users\\Public\\dropper.exe", None, 5).rows
    result = run_analysis([write(tmp_path, rows)])
    assert (result.result, result.status, result.exit_code) == expected


def test_unattached_findings_counter(tmp_path: Path) -> None:
    chain = Chain()
    chain.connect(0, 5, "203.0.113.9", ProcessGuid="-")
    rows = rows_of(BENIGN) + [{**chain.rows[0], "ProcessGuid": "-"}]
    result = run_analysis([write(tmp_path, rows)])
    assert result.coverage.counters.unattached_findings == 1
    (story,) = result.storylines
    assert story.root_guid == "host:ws-14.corp.example"


def _signature(result: AnalysisResult) -> tuple[Any, ...]:
    return (
        result.result,
        result.status,
        result.exit_code,
        result.findings,
        result.storylines,
        result.coverage,
    )


@pytest.mark.parametrize(
    "options",
    [
        {"since": "2026-10-12T10:02:00Z"},
        {"until": "2026-10-12T10:01:00Z"},
        {"around": "2026-10-12T11:00:00Z", "window": "5m"},
        {"focus": "image:upd.exe"},
        {"focus": "{" + "8f3c2a71-5e4b-4d9a-a1c3-0000000000c1" + "}"},
    ],
)
def test_display_filters_never_change_the_outcome(options: dict[str, str]) -> None:
    phish = FIXTURES / "phish_chain.jsonl"
    assert _signature(run_analysis([phish], make_params(**options))) == _signature(
        run_analysis([phish])
    )
