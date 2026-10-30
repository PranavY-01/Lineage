"""AnalysisParams validation (§9.7, §11.1, §11.3) and rule selection (--rules)."""

from pathlib import Path

import pytest

from lineage_ir.analyze.filters import make_params, parse_duration, select_rules
from lineage_ir.detect.graph_rules import GRAPH_RULES
from lineage_ir.detect.loader import load_rules
from lineage_ir.errors import UsageError
from lineage_ir.ingest.timeparse import parse_iso

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_defaults() -> None:
    params = make_params()
    assert params.hosts == ()
    assert params.rules is None
    assert params.min_severity == "info"
    assert params.gap_seconds == 600
    assert params.telemetry_gap_seconds == 1800
    assert params.max_steps == 60
    assert params.window_us == (None, None)
    assert params.max_records == 2_000_000


@pytest.mark.parametrize(
    ("text", "seconds"), [("30s", 30), ("15m", 900), ("2h", 7200), ("1d", 86400), ("90M", 5400)]
)
def test_durations(text: str, seconds: int) -> None:
    assert parse_duration(text) == seconds


@pytest.mark.parametrize("text", ["15", "m", "1.5h", "-5m", "5 m", "5w", "", "0x10m"])
def test_bad_durations(text: str) -> None:
    with pytest.raises(UsageError, match="duration"):
        parse_duration(text)


@pytest.mark.parametrize(
    ("option", "low_ok", "too_low", "high_ok", "too_high"),
    [
        ("gap", "1m", "59s", "7d", "8d"),
        ("telemetry_gap", "1m", "30s", "30d", "31d"),
    ],
)
def test_duration_ranges(
    option: str, low_ok: str, too_low: str, high_ok: str, too_high: str
) -> None:
    make_params(**{option: low_ok})
    make_params(**{option: high_ok})
    for value in (too_low, too_high):
        with pytest.raises(UsageError):
            make_params(**{option: value})


def test_integer_ranges() -> None:
    make_params(max_steps=10, max_records=1, max_file_size_mb=65_536)
    for options in (
        {"max_steps": 9},
        {"max_steps": 10_001},
        {"max_records": 0},
        {"max_records": 50_000_001},
        {"max_file_size_mb": 0},
    ):
        with pytest.raises(UsageError):
            make_params(**options)


def test_min_severity_levels() -> None:
    assert make_params(min_severity="high").min_severity == "high"
    with pytest.raises(UsageError):
        make_params(min_severity="critical")


def test_time_window() -> None:
    # Offsets are honoured: 12:30+02:00 is 10:30Z.
    params = make_params(since="2026-10-12T10:00:00Z", until="2026-10-12T12:30:00+02:00")
    assert params.window_us == (
        parse_iso("2026-10-12T10:00:00Z"),
        parse_iso("2026-10-12T10:30:00Z"),
    )
    params = make_params(since="2026-10-12T10:00:00Z", until="2026-10-12T11:00:00Z")
    assert params.window_us == (
        parse_iso("2026-10-12T10:00:00Z"),
        parse_iso("2026-10-12T11:00:00Z"),
    )
    assert make_params(since="2026-10-12T10:00:00+05:30").window_us[1] is None


def test_around_and_window() -> None:
    center = parse_iso("2026-10-12T10:42:00Z")
    assert make_params(around="2026-10-12T10:42:00Z").window_us == (
        center - 900_000_000,
        center + 900_000_000,
    )
    assert make_params(around="2026-10-12T10:42:00Z", window="1h").window_us == (
        center - 3_600_000_000,
        center + 3_600_000_000,
    )


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"since": "2026-10-12T10:00:00"}, "offset"),
        ({"until": "2026-10-12 10:00:00"}, "offset|RFC 3339"),
        ({"since": "yesterday"}, "RFC 3339"),
        ({"since": "2026-10-12T11:00:00Z", "until": "2026-10-12T10:00:00Z"}, "before"),
        ({"since": "2026-10-12T10:00:00Z", "until": "2026-10-12T10:00:00Z"}, "before"),
        ({"window": "5m"}, "--around"),
        ({"around": "2026-10-12T10:00:00Z", "since": "2026-10-12T09:00:00Z"}, "--around"),
        ({"around": "2026-10-12T10:00:00Z", "until": "2026-10-12T11:00:00Z"}, "--around"),
    ],
)
def test_time_errors(options: dict[str, str], message: str) -> None:
    with pytest.raises(UsageError, match=message):
        make_params(**options)


def test_hosts_are_lowercased() -> None:
    assert make_params(hosts=("WS-14.corp.example",)).hosts == ("ws-14.corp.example",)


def _ids(spec: str | None) -> list[str]:
    rules, graph_rules = select_rules(load_rules(), GRAPH_RULES, spec)
    return [r.id for r in rules] + [g.info.id for g in graph_rules]


def test_select_all_by_default() -> None:
    assert len(_ids(None)) == 24


def test_select_by_id_and_family_prefix() -> None:
    assert _ids("CMD") == [f"CMD-00{n}" for n in range(1, 8)]
    assert _ids("per-001, GR") == ["PER-001", "GR-001", "GR-002", "GR-003", "GR-004"]
    assert _ids("LIN-002,LIN-002") == ["LIN-002"]


@pytest.mark.parametrize("spec", ["XYZ", "CMD-999", "CM", "LIN,NOPE", ""])
def test_unknown_rules_list_the_valid_ids(spec: str) -> None:
    with pytest.raises(UsageError) as info:
        _ids(spec)
    assert "CMD-001" in str(info.value) and "GR-004" in str(info.value)
    assert info.value.exit_code == 2
