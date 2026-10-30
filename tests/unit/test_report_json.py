"""The 7d7b report (§12.3), its JSON Schema and the inspect document."""

import json
from typing import Any

import pytest

from helpers.reports import (
    FIXTURES,
    RUN_ID,
    frozen_analysis,
    report,
    report_text,
    validator,
)
from lineage_ir.analyze.anchors import load_anchors
from lineage_ir.config import INSPECT_ITEMS_PER_KIND
from lineage_ir.engine import AnalysisResult
from lineage_ir.graph.traverse import ancestors
from lineage_ir.render import report_json

REPORT_KEYS = [
    "envelope",
    "status",
    "result",
    "input",
    "parameters",
    "coverage",
    "summary",
    "findings",
    "storylines",
    "errors",
    "errors_truncated",
]
FIXTURE_NAMES = [
    "phish_chain",
    "benign_host",
    "missing_telemetry",
    "masquerade",
    "hostile_strings",
    "duplicates",
    "cycle",
    "ghosts",
]


@pytest.fixture(scope="module")
def phish() -> AnalysisResult:
    return frozen_analysis(FIXTURES / "phish_chain.jsonl")


def test_envelope_matches_the_series_contract(phish: AnalysisResult) -> None:
    envelope = report(phish)["envelope"]
    assert list(envelope) == [
        "schema",
        "schema_version",
        "tool",
        "tool_version",
        "run_id",
        "started_at",
        "completed_at",
    ]
    assert envelope["schema"] == "7d7b-report"
    assert envelope["schema_version"] == 1
    assert envelope["tool"] == "lineage"
    assert envelope["run_id"] == RUN_ID
    assert envelope["started_at"] == envelope["completed_at"] == "2026-10-14T17:46:40Z"


def test_keys_in_contract_order(phish: AnalysisResult) -> None:
    document = report(phish)
    assert list(document) == REPORT_KEYS
    assert list(document["parameters"])[:12] == [
        "hosts",
        "rules",
        "min_severity",
        "since",
        "until",
        "focus",
        "gap_seconds",
        "telemetry_gap_seconds",
        "max_records",
        "timestamp_source",
        "rule_set_sha256",
        "attack_version",
    ]


def test_text_is_ascii_lf_two_space_json(phish: AnalysisResult) -> None:
    text = report_text(phish)
    assert text.isascii()
    assert "\r" not in text
    assert text.endswith("}\n")
    assert text.startswith('{\n  "envelope": {\n    "schema"')


def test_status_result_and_findings(phish: AnalysisResult) -> None:
    document = report(phish)
    assert (document["status"], document["result"]) == ("findings_detected", "findings_detected")
    first = document["findings"][0]
    assert list(first) == ["event", "category", "subject", "details"]
    assert first["category"] == "detection"
    assert first["subject"].startswith("process:ws-14.corp.example/")
    assert first["details"]["storyline"] == "S1"
    assert first["details"]["evidence"][0].keys() == {"file", "index", "record_id"}
    assert len(document["findings"]) == 11


def test_findings_keep_the_engine_order(phish: AnalysisResult) -> None:
    ids = [f["details"]["finding_id"] for f in report(phish)["findings"]]
    assert ids == [f.finding_id for f in phish.findings]


def test_summary(phish: AnalysisResult) -> None:
    summary = report(phish)["summary"]
    assert summary["findings_total"] == 11
    assert summary["findings_by_severity"] == {"high": 5, "medium": 5, "low": 1, "info": 0}
    assert summary["storylines"] == 2
    assert summary["rules_evaluable"] + summary["rules_not_evaluable"] <= 24


def test_storyline_times_are_rfc3339(phish: AnalysisResult) -> None:
    s2 = report(phish)["storylines"][1]
    assert (s2["start"], s2["end"]) == ("2026-10-12T11:00:00Z", "2026-10-12T11:01:10Z")
    assert s2["steps"][0]["time"] == "2026-10-12T11:00:00Z"
    assert s2["steps"][0]["source"].keys() == {"file", "index", "record_id"}


def test_display_filters_are_recorded_but_never_trim_the_report() -> None:
    path = FIXTURES / "phish_chain.jsonl"
    full = report(frozen_analysis(path))
    filtered = report(
        frozen_analysis(path, since="2026-10-12T10:59:00Z", focus="image:upd.exe", hot_only=True)
    )
    params = filtered["parameters"]
    assert params["since"] == "2026-10-12T10:59:00Z"
    assert params["focus"] == "image:upd.exe"
    assert params["hot_only"] is True
    for key in ("status", "result", "coverage", "summary", "findings", "storylines"):
        assert filtered[key] == full[key]


def test_around_resolves_into_the_window() -> None:
    document = report(
        frozen_analysis(
            FIXTURES / "phish_chain.jsonl", around="2026-10-12T11:00:00+01:00", window="5m"
        )
    )
    params = document["parameters"]
    assert (params["since"], params["until"]) == ("2026-10-12T09:55:00Z", "2026-10-12T10:05:00Z")
    assert (params["around"], params["window"]) == ("2026-10-12T11:00:00+01:00", "5m")


def test_errors_are_capped(monkeypatch: pytest.MonkeyPatch, phish: AnalysisResult) -> None:
    monkeypatch.setattr(report_json, "REPORT_ERRORS_CAP", 0)
    from lineage_ir.models import ErrorEntry

    noisy = phish.model_copy(update={"errors": (ErrorEntry(kind="k", subject="s", message="m"),)})
    document = report_json.report_document(noisy, "0" * 64)
    assert document["errors"] == [] and document["errors_truncated"] is True


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_reports_validate_against_the_schema(name: str) -> None:
    document = report(frozen_analysis(FIXTURES / f"{name}.jsonl"))
    errors = sorted(validator("report-1.0.json").iter_errors(document), key=str)
    assert errors == []


def test_schema_rejects_a_wrong_envelope(phish: AnalysisResult) -> None:
    document: dict[str, Any] = report(phish)
    document["envelope"]["schema_version"] = "1.0"
    assert not validator("report-1.0.json").is_valid(document)
    document = report(phish)
    document["surprise"] = True
    assert not validator("report-1.0.json").is_valid(document)


def _inspect(result: AnalysisResult, image: str) -> dict[str, Any]:
    graph = result.graphs["ws-14.corp.example"]
    guid = next(g for g, n in graph.nodes.items() if n.image_name == image)
    anchors = load_anchors()
    ancestry = [(g, anchors(graph.nodes[g])) for g in ancestors(graph, guid)]
    document = report_json.inspect_document(
        result, "ws-14.corp.example", guid, ancestry, INSPECT_ITEMS_PER_KIND
    )
    return json.loads(report_json.dumps(document))


def test_inspect_document(phish: AnalysisResult) -> None:
    document = _inspect(phish, "powershell.exe")
    assert document["kind"] == "inspect"
    assert document["node"]["image_name"] == "powershell.exe"
    assert [a["image_name"] for a in document["ancestry"]][:2] == ["cmd.exe", "winword.exe"]
    assert document["ancestry"][-2]["anchor"] is True
    assert set(document["activity"]) == {"dns", "file_create", "network"}
    assert document["activity"]["file_create"]["total"] == 2
    assert {f["event"] for f in document["findings"]} == {"CMD-001", "CMD-002", "GR-001"}
    assert document["storylines"] == ["S1"]
    assert validator("report-1.0.json", "inspectDocument").is_valid(document)


def test_inspect_lists_capped_activity_and_image_loads(tmp_path: Any) -> None:
    from helpers.chain import EXPLORER, SYS32, Chain

    chain = Chain().create(1, EXPLORER)
    chain.create(2, SYS32 + "svc.exe", 1, 1)
    for n in range(60):
        chain.event(7, 2, 2 + n, ImageLoaded=f"C:\\Windows\\System32\\m{n}.dll", Signed="true")
        chain.event(17, 2, 2 + n, PipeName=f"\\pipe\\p{n}")
    result = frozen_analysis(chain.write(tmp_path / "in.jsonl"))
    document = _inspect(result, "svc.exe")
    assert document["activity"]["image_load"]["total"] == 60
    assert len(document["activity"]["image_load"]["items"]) == 50
    assert document["activity"]["pipe"]["total"] == 60
    assert len(document["activity"]["pipe"]["items"]) == 50
    errors = list(validator("report-1.0.json", "inspectDocument").iter_errors(document))
    assert errors == []
