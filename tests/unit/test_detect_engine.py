"""Event-rule matching (§8.2, §8.3), aggregation and attachment (§8.8)."""

import base64
import hashlib
import inspect
import random
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

from helpers.anchors import stub_is_anchor
from helpers.detection import detect_file
from lineage_ir.detect.engine import run_detection
from lineage_ir.detect.loader import load_rules, parse_rule
from lineage_ir.detect.schema import Rule
from lineage_ir.engine import build_host_graphs
from lineage_ir.ingest.reader import read_inputs

HOST = "ws-14.corp.example"
G1 = "{6c1e0a2b-7d3f-4e5a-9b8c-00000000a001}"
G2 = "{6c1e0a2b-7d3f-4e5a-9b8c-00000000a002}"


def make_rule(rule_id: str = "TST-001", **body: Any) -> Rule:
    data = {
        "id": rule_id,
        "title": f"Rule {rule_id}",
        "severity": body.pop("severity", "medium"),
        "attack": [],
        "tactics": ["execution"],
        "why": "Test rule.",
        **body,
    }
    return parse_rule(yaml.safe_dump(data), f"{rule_id}.yaml")


def proc(make_record: Callable[..., dict[str, Any]], rid: int, guid: str, **fields: Any) -> dict:
    second = rid % 60
    defaults = {
        "ProcessGuid": guid,
        "ProcessId": str(rid),
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe",
    }
    return make_record(1, rid, f"2026-10-12 10:00:{second:02d}.000", **{**defaults, **fields})


def hits(write_jsonl: Callable[..., Path], records: list[dict], rule: Rule) -> list[Any]:
    return detect_file(write_jsonl(records), (rule,)).by_rule(rule.id)


@pytest.mark.parametrize(
    ("condition", "value", "expected"),
    [
        ({"image_name": ["notepad.exe", "CMD.EXE"]}, "C:\\Windows\\System32\\cmd.exe", True),
        ({"image_name": "powershell.exe"}, "C:\\Windows\\System32\\cmd.exe", False),
        ({"image|contains": "\\users\\public\\"}, "C:/Users/Public/x.exe", True),
        ({"image|startswith": "c:\\windows\\"}, "\\\\?\\C:\\Windows\\x.exe", True),
        ({"image|startswith": "c:\\windows\\"}, "\\??\\C:\\Windows\\x.exe", True),
        ({"image|endswith": "\\X.EXE"}, "C:\\Windows\\x.exe", True),
        ({"image|contains|all": ["windows", "x.exe"]}, "C:\\Windows\\x.exe", True),
        ({"image|contains|all": ["windows", "y.exe"]}, "C:\\Windows\\x.exe", False),
        ({"image|contains": ["nope", "windows"]}, "C:\\Windows\\x.exe", True),
    ],
)
def test_condition_semantics(
    write_jsonl: Callable[..., Path],
    make_record: Callable[..., dict[str, Any]],
    condition: dict[str, Any],
    value: str,
    expected: bool,
) -> None:
    rule = make_rule(match={"event_id": 1, **condition})
    found = hits(write_jsonl, [proc(make_record, 1, G1, Image=value)], rule)
    assert bool(found) is expected


def test_missing_or_empty_field_is_false(
    write_jsonl: Callable[..., Path], make_record: Callable[..., dict[str, Any]]
) -> None:
    rule = make_rule(match={"event_id": 1, "command_line|contains|all": ["a"]})
    records = [proc(make_record, 1, G1, CommandLine=""), proc(make_record, 2, G2)]
    records[1].pop("CommandLine")
    assert hits(write_jsonl, records, rule) == []
    negated = make_rule(match={"event_id": 1, "parent_image_name": "x.exe"})
    assert hits(write_jsonl, records, negated) == []


def test_integer_values_compare_numerically(
    write_jsonl: Callable[..., Path], make_record: Callable[..., dict[str, Any]]
) -> None:
    rule = make_rule(match={"event_id": 3, "destination_port": [443, 8443]})
    rows = [
        make_record(3, n, ProcessGuid=G1, DestinationPort=port)
        for n, port in enumerate(["443", "0443", "8443 ", "80", "x"], start=1)
    ]
    found = hits(write_jsonl, rows, rule)
    assert [f.count for f in found] == [3]
    text_rule = make_rule(match={"event_id": 22, "query_status": 0})
    rows = [make_record(22, 9, ProcessGuid=G1, QueryStatus="0", QueryName="a.example")]
    assert len(hits(write_jsonl, rows, text_rule)) == 1


def test_match_any_and_exclude(
    write_jsonl: Callable[..., Path], make_record: Callable[..., dict[str, Any]]
) -> None:
    rule = make_rule(
        match_any=[
            {"event_id": 1, "image_name": "a.exe"},
            {"event_id": 1, "command_line|contains": "magic"},
        ],
        exclude=[
            {"parent_image_name": "trusted.exe"},
            {"event_id": 3, "image_name": "b.exe"},
        ],
    )
    guids = [f"{{6c1e0a2b-7d3f-4e5a-9b8c-0000000001{n:02x}}}" for n in range(5)]
    rows = [
        proc(make_record, 1, guids[0], Image="C:\\a.exe"),
        proc(make_record, 2, guids[1], Image="C:\\b.exe", CommandLine="b.exe magic"),
        proc(make_record, 3, guids[2], Image="C:\\a.exe", ParentImage="C:\\trusted.exe"),
        proc(make_record, 4, guids[3], Image="C:\\c.exe"),
        # The second exclude names event 3 only, so it does not apply to event 1.
        proc(make_record, 5, guids[4], Image="C:\\b.exe", CommandLine="magic"),
    ]
    found = hits(write_jsonl, rows, rule)
    assert sorted(f.guid for f in found) == sorted(
        g.strip("{}") for g in (guids[0], guids[1], guids[4])
    )


def enc(text: str) -> str:
    return base64.b64encode(text.encode("utf-16-le")).decode("ascii")


def test_virtual_fields(
    write_jsonl: Callable[..., Path], make_record: Callable[..., dict[str, Any]]
) -> None:
    ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    rows = [
        proc(
            make_record,
            1,
            G1,
            Image=ps,
            CommandLine="powershell -enc " + enc("IEX downloadstring"),
            ParentImage="C:\\Office\\WINWORD.EXE",
        ),
        make_record(
            10,
            2,
            SourceProcessGuid=G1,
            SourceImage=ps,
            TargetProcessGuid=G2,
            TargetImage="C:\\Windows\\System32\\lsass.exe",
            GrantedAccess="0x1010",
        ),
        make_record(11, 3, ProcessGuid=G1, Image=ps, TargetFilename="C:\\Temp\\Drop.EXE"),
    ]
    path = write_jsonl(rows)
    cases = {
        "image_name": (1, "powershell.exe"),
        "parent_image_name": (1, "winword.exe"),
        "decoded_command|contains": (1, "downloadstring"),
        "command_line_full|contains": (1, "downloadstring"),
        "encoded_command_present": (1, "true"),
        "source_image_name": (10, "powershell.exe"),
        "target_image_name": (10, "lsass.exe"),
        "target_filename_name": (11, "drop.exe"),
    }
    for key, (event_id, value) in cases.items():
        rule = make_rule(match={"event_id": event_id, key: value})
        assert len(detect_file(path, (rule,)).by_rule("TST-001")) == 1, key
    plain = make_rule(match={"event_id": 1, "encoded_command_present": "false"})
    assert detect_file(path, (plain,)).by_rule("TST-001") == []


def test_aggregation_and_evidence_truncation(
    write_jsonl: Callable[..., Path], make_record: Callable[..., dict[str, Any]]
) -> None:
    rule = make_rule(match={"event_id": 3, "destination_port": "443"})
    rows = [
        make_record(
            3,
            100 + n,
            f"2026-10-12 10:{n // 60:02d}:{n % 60:02d}.000",
            ProcessGuid=G1,
            DestinationIp="203.0.113.9",
            DestinationPort="443",
            Protocol="tcp",
            DestinationHostname="c2.example",
        )
        for n in range(25)
    ]
    (finding,) = hits(write_jsonl, rows, rule)
    assert finding.count == 25
    assert finding.evidence_truncated
    assert [e.record_id for e in finding.evidence] == [*range(100, 110), *range(115, 125)]
    assert finding.first_us < finding.last_us
    assert finding.details == {
        "destination": "203.0.113.9:443/tcp",
        "destination_hostname": "c2.example",
    }
    (exact,) = hits(write_jsonl, rows[:20], rule)
    assert exact.count == 20 and not exact.evidence_truncated and len(exact.evidence) == 20


def test_details_by_event_type_and_truncation(
    write_jsonl: Callable[..., Path], make_record: Callable[..., dict[str, Any]]
) -> None:
    long_command = "cmd.exe /c " + "x" * 400
    rows = [
        proc(make_record, 1, G1, CommandLine=long_command),
        make_record(
            10,
            2,
            SourceProcessGuid=G1,
            TargetProcessGuid=G2,
            TargetImage="C:\\Windows\\System32\\lsass.exe",
            GrantedAccess="0x1010",
        ),
        make_record(11, 3, ProcessGuid=G1, TargetFilename="C:\\Temp\\a.exe"),
        make_record(13, 4, ProcessGuid=G1, TargetObject="HKLM\\Run\\x", Details="d" * 300),
    ]
    path = write_jsonl(rows)
    expected = {
        1: {"command_line": long_command[:299] + "\u2026"},
        10: {"target_image": "C:\\Windows\\System32\\lsass.exe", "granted_access": "0x1010"},
        11: {"target_filename": "C:\\Temp\\a.exe"},
        13: {"target_object": "HKLM\\Run\\x", "details": "d" * 199 + "\u2026"},
    }
    for event_id, details in expected.items():
        rule = make_rule(match={"event_id": event_id})
        (finding,) = detect_file(path, (rule,)).by_rule("TST-001")
        assert finding.details == details, event_id
        assert all(len(v) <= 300 for v in finding.details.values())


def test_finding_ids_are_stable(
    write_jsonl: Callable[..., Path], make_record: Callable[..., dict[str, Any]]
) -> None:
    path = write_jsonl([proc(make_record, 1, G1)])
    rule = make_rule(match={"event_id": 1})
    first = detect_file(path, (rule,)).by_rule("TST-001")[0]
    second = detect_file(path, (rule,)).by_rule("TST-001")[0]
    guid = G1.strip("{}")
    expected = hashlib.sha256(f"TST-001\x1f{HOST}\x1f{guid}".encode()).hexdigest()[:12]
    assert first.finding_id == second.finding_id == expected


def test_attachment_by_event_type(
    write_jsonl: Callable[..., Path], make_record: Callable[..., dict[str, Any]]
) -> None:
    rows = [
        proc(make_record, 1, G1),
        make_record(8, 2, SourceProcessGuid=G2, TargetProcessGuid=G1, SourceImage="C:\\m.exe"),
    ]
    path = write_jsonl(rows)
    created = detect_file(path, (make_rule(match={"event_id": 1}),)).by_rule("TST-001")
    accessed = detect_file(path, (make_rule(match={"event_id": 8}),)).by_rule("TST-001")
    assert [f.guid for f in created] == [G1.strip("{}")]
    assert [f.guid for f in accessed] == [G2.strip("{}")]
    assert accessed[0].image_name == "m.exe"


def test_unattached_event_hit_goes_to_host_pseudo_node(
    write_jsonl: Callable[..., Path], make_record: Callable[..., dict[str, Any]]
) -> None:
    rows = [
        make_record(3, 1, ProcessGuid="-", Image="C:\\Windows\\System32\\rundll32.exe"),
        make_record(3, 2, ProcessGuid="{bad}", Image="C:\\Windows\\System32\\rundll32.exe"),
    ]
    run = detect_file(write_jsonl(rows), (make_rule(match={"event_id": 3}),))
    graph = run.graphs[HOST]
    assert len(graph.unattached_events) == 2
    assert all(not n.activity for n in graph.nodes.values())
    (finding,) = run.by_rule("TST-001")
    assert finding.guid == f"host:{HOST}"
    assert finding.count == 2
    assert finding.image_name == "rundll32.exe"
    assert run.detection.unattached_findings == 1


def test_rule_order_never_changes_findings(
    write_jsonl: Callable[..., Path], make_record: Callable[..., dict[str, Any]]
) -> None:
    rows = [
        proc(make_record, n, f"{{6c1e0a2b-7d3f-4e5a-9b8c-0000000002{n:02x}}}") for n in range(8)
    ]
    path = write_jsonl(rows)
    ingest = read_inputs([path])
    graphs = build_host_graphs(ingest)
    rules = [make_rule(f"TST-{n:03d}", match={"event_id": 1}) for n in range(1, 9)]
    baseline = run_detection(ingest, graphs, rules, is_anchor=stub_is_anchor)
    for seed in range(10):
        shuffled = rules[:]
        random.Random(seed).shuffle(shuffled)
        assert run_detection(ingest, graphs, shuffled, is_anchor=stub_is_anchor) == baseline


def test_loaded_rule_order_ignores_file_order(tmp_path: Path) -> None:
    bundled = load_rules()
    texts = {
        r.id: yaml.safe_dump(
            {
                "id": r.id,
                "title": r.title,
                "severity": r.severity,
                "attack": list(r.attack),
                "tactics": list(r.tactics),
                "why": r.why,
                "match": {"event_id": 1, "image_name": "a.exe"},
            }
        )
        for r in bundled
    }
    for seed in range(5):
        directory = tmp_path / f"s{seed}"
        directory.mkdir()
        order = list(texts)
        random.Random(seed).shuffle(order)
        for rule_id in order:
            (directory / f"{rule_id}.yaml").write_text(texts[rule_id], encoding="utf-8")
        assert [r.id for r in load_rules(directory)] == sorted(texts)


def test_findings_sorted_and_events_examined(
    write_jsonl: Callable[..., Path], make_record: Callable[..., dict[str, Any]]
) -> None:
    rows = [
        proc(make_record, 5, G2, Image="C:\\b.exe"),
        proc(make_record, 1, G1, Image="C:\\a.exe"),
        make_record(3, 9, ProcessGuid=G1),
    ]
    rules = (
        make_rule("TST-002", match={"event_id": 1}),
        make_rule("TST-001", match={"event_id": [1, 3]}),
    )
    run = detect_file(write_jsonl(rows), rules)
    keys = [(f.host, f.first_us, f.rule_id, f.guid) for f in run.detection.findings]
    assert keys == sorted(keys)
    assert run.detection.events_examined["TST-001"] == 3
    assert run.detection.events_examined["TST-002"] == 2


def test_anchor_test_is_a_required_keyword() -> None:
    parameter = inspect.signature(run_detection).parameters["is_anchor"]
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default is inspect.Parameter.empty
