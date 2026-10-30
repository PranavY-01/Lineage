from pathlib import Path
from typing import Any

import pytest

from lineage_ir.graph.builder import build_graphs
from lineage_ir.graph.model import ProcessGraph
from lineage_ir.ingest.reader import read_inputs

HOST = "ws-14.corp.example"
CMD = "C:\\Windows\\System32\\cmd.exe"


def guid(tag: int) -> str:
    return f"6c1e0a2b-7d3f-4e5a-9b8c-{tag:012x}"


def build(write_jsonl: Any, rows: list[dict[str, Any]], **kwargs: Any) -> ProcessGraph:
    result = read_inputs([write_jsonl(rows)])
    return build_graphs(result.events, result.image_loads, **kwargs)[HOST]


def create(make_record: Any, rid: int, t: str, tag: int, parent: int | None = None, **f: Any):
    fields = {"ProcessGuid": "{" + guid(tag) + "}", "ProcessId": str(tag), "Image": CMD}
    if parent is not None:
        fields["ParentProcessGuid"] = "{" + guid(parent) + "}"
    fields.update(f)
    return make_record(1, rid, f"2026-10-12 10:00:{t}", **fields)


def test_creation_fields(write_jsonl: Any, make_record: Any) -> None:
    rows = [
        create(
            make_record,
            1,
            "00.000",
            1,
            CommandLine="cmd.exe /c dir",
            User="CORP\\jdoe",
            IntegrityLevel="Medium",
            Hashes="SHA256=AA,MD5=BB",
            CurrentDirectory="C:\\Users\\jdoe\\",
            LogonId="0x3e7",
        )
    ]
    node = build(write_jsonl, rows).nodes[guid(1)]
    assert node.image_name == "cmd.exe"
    assert node.command_line == "cmd.exe /c dir"
    assert node.hashes == {"sha256": "aa", "md5": "bb"}
    assert node.integrity_level == "Medium"
    assert node.logon_id == "0x3e7"
    assert node.pid == 1
    assert node.start_us is not None and node.end_us is None
    assert not node.is_ghost and node.ghost_reason is None
    assert node.create_record is not None and node.create_record.record_id == 1


def test_children_sorted_by_start_with_ghosts_last(write_jsonl: Any, make_record: Any) -> None:
    rows = [
        create(make_record, 1, "00.000", 1),
        create(make_record, 2, "05.000", 3, parent=1),
        create(make_record, 3, "02.000", 4, parent=1),
        create(make_record, 4, "02.000", 2, parent=1),
    ]
    graph = build(write_jsonl, rows)
    assert graph.nodes[guid(1)].children == (guid(2), guid(4), guid(3))
    assert graph.roots == (guid(1),)


def test_identical_and_conflicting_creations(write_jsonl: Any, make_record: Any) -> None:
    first = create(make_record, 1, "00.000", 1, CommandLine="a")
    identical = dict(first, RecordNumber=2)
    conflict = create(make_record, 3, "09.000", 1, CommandLine="b")
    graph = build(write_jsonl, [first, identical, conflict])
    assert graph.nodes[guid(1)].command_line == "a"
    assert graph.counters.duplicate_creations == 1
    assert graph.counters.creation_conflicts == 1


def test_conflicting_creation_adds_no_parent_ghost(write_jsonl: Any, make_record: Any) -> None:
    rows = [
        create(make_record, 1, "00.000", 1),
        create(make_record, 2, "01.000", 1, parent=9, CommandLine="other"),
    ]
    graph = build(write_jsonl, rows)
    assert guid(9) not in graph.nodes
    assert graph.counters.ghosts == {}


def test_event5_sets_end_time_first_wins(write_jsonl: Any, make_record: Any) -> None:
    pg = "{" + guid(1) + "}"
    rows = [
        create(make_record, 1, "00.000", 1),
        make_record(5, 2, "2026-10-12 10:00:30.000", ProcessGuid=pg),
        make_record(5, 3, "2026-10-12 10:00:40.000", ProcessGuid=pg),
    ]
    node = build(write_jsonl, rows).nodes[guid(1)]
    assert node.end_us is not None
    assert [a.kind for a in node.activity] == ["terminate", "terminate"]
    assert node.end_us == node.activity[0].ts_us


@pytest.mark.parametrize(
    ("event_id", "kind"),
    [
        (3, "network"),
        (11, "file_create"),
        (12, "registry"),
        (13, "registry"),
        (14, "registry"),
        (15, "file_stream"),
        (17, "pipe"),
        (18, "pipe"),
        (22, "dns"),
        (23, "file_delete"),
        (26, "file_delete"),
        (2, "other"),
        (255, "other"),
    ],
)
def test_activity_kinds(write_jsonl: Any, make_record: Any, event_id: int, kind: str) -> None:
    rows = [
        create(make_record, 1, "00.000", 1),
        make_record(event_id, 2, "2026-10-12 10:00:01.000", ProcessGuid="{" + guid(1) + "}"),
    ]
    activity = build(write_jsonl, rows).nodes[guid(1)].activity
    assert [(a.kind, a.role, a.event_id) for a in activity] == [(kind, "actor", event_id)]


def test_event15_is_not_file_create(write_jsonl: Any, make_record: Any) -> None:
    rows = [
        create(make_record, 1, "00.000", 1),
        make_record(
            15,
            2,
            "2026-10-12 10:00:01.000",
            ProcessGuid="{" + guid(1) + "}",
            TargetFilename="C:\\Users\\Public\\a.exe:Zone.Identifier",
        ),
    ]
    activity = build(write_jsonl, rows).nodes[guid(1)].activity
    assert activity[0].kind == "file_stream"
    assert activity[0].summary == "stream C:\\Users\\Public\\a.exe:Zone.Identifier"


def test_wmi_events_go_to_host_list_only(write_jsonl: Any, make_record: Any) -> None:
    rows = [
        make_record(19, 1, Name="filter1", EventType="WmiFilterEvent"),
        make_record(20, 2, Name="consumer1"),
        make_record(21, 3, Consumer="consumer1", Filter="filter1"),
    ]
    graph = build(write_jsonl, rows)
    assert [e.event_id for e in graph.wmi_events] == [19, 20, 21]
    assert graph.unattached_events == ()
    assert graph.counters.unattached_events == 0
    assert graph.nodes == {}


def test_access_events_attach_to_both_sides(write_jsonl: Any, make_record: Any) -> None:
    rows = [
        create(make_record, 1, "00.000", 1),
        create(make_record, 2, "00.500", 2),
        make_record(
            10,
            3,
            "2026-10-12 10:00:01.000",
            SourceProcessGUID="{" + guid(1) + "}",
            TargetProcessGUID="{" + guid(2) + "}",
            SourceImage=CMD,
            TargetImage="C:\\Windows\\System32\\lsass.exe",
            GrantedAccess="0x1010",
        ),
    ]
    graph = build(write_jsonl, rows)
    source = graph.nodes[guid(1)].activity
    target = graph.nodes[guid(2)].activity
    assert [(a.kind, a.role) for a in source] == [("process_access", "actor")]
    assert [(a.kind, a.role) for a in target] == [("process_access", "target")]
    assert source[0].summary == "accessed C:\\Windows\\System32\\lsass.exe (0x1010)"
    assert target[0].summary == f"accessed by {CMD} (0x1010)"
    assert source[0].source == target[0].source


def test_decoder_is_injected(write_jsonl: Any, make_record: Any) -> None:
    calls: list[tuple[str | None, str | None]] = []

    def decode(command_line: str | None, name: str | None) -> tuple[str | None, str | None]:
        calls.append((command_line, name))
        return ("decoded", None) if name == "cmd.exe" else (None, None)

    rows = [create(make_record, 1, "00.000", 1, CommandLine="cmd /c x")]
    node = build(write_jsonl, rows, decode=decode).nodes[guid(1)]
    assert node.decoded_command == "decoded"
    assert calls == [("cmd /c x", "cmd.exe")]


def test_default_decoder_leaves_fields_empty(write_jsonl: Any, make_record: Any) -> None:
    node = build(write_jsonl, [create(make_record, 1, "00.000", 1)]).nodes[guid(1)]
    assert node.decoded_command is None and node.decode_note is None


@pytest.mark.parametrize(
    ("fields", "expected"),
    [
        (
            {
                "Protocol": "tcp",
                "Initiated": "true",
                "DestinationIp": "203.0.113.50",
                "DestinationPort": "80",
                "DestinationHostname": "cdn.example",
            },
            "→ 203.0.113.50:80/tcp (cdn.example)",
        ),
        (
            {
                "Protocol": "tcp",
                "Initiated": "false",
                "SourceIp": "198.51.100.3",
                "SourcePort": "5555",
            },
            "← 198.51.100.3:5555/tcp",
        ),
        (
            {
                "Protocol": "tcp",
                "Initiated": "true",
                "DestinationIp": "2001:db8::1",
                "DestinationPort": "443",
            },
            "→ [2001:db8::1]:443/tcp",
        ),
    ],
)
def test_network_summaries(
    write_jsonl: Any, make_record: Any, fields: dict[str, str], expected: str
) -> None:
    rows = [
        create(make_record, 1, "00.000", 1),
        make_record(3, 2, "2026-10-12 10:00:01.000", ProcessGuid="{" + guid(1) + "}", **fields),
    ]
    assert build(write_jsonl, rows).nodes[guid(1)].activity[0].summary == expected


def test_hosts_are_separate_graphs(fixtures_dir: Path) -> None:
    graphs = build_graphs(read_inputs([fixtures_dir / "multi_host.jsonl"]).events)
    assert list(graphs) == ["ws-14.corp.example", "ws-15.corp.example"]
    shared = guid(0xE1)
    assert graphs["ws-14.corp.example"].nodes[shared].image_name == "cmd.exe"
    assert graphs["ws-15.corp.example"].nodes[shared].image_name == "powershell.exe"
    assert graphs["ws-15.corp.example"].nodes[shared].end_us is not None
    assert graphs["ws-14.corp.example"].nodes[shared].end_us is None


def _load(make_record: Any, rid: int | None, second: int, tag: int | str, dll: str) -> dict:
    process = tag if isinstance(tag, str) else "{" + guid(tag) + "}"
    return make_record(
        7,
        rid,
        f"2026-10-12 10:01:{second:02d}.000",
        ProcessGuid=process,
        ProcessId="77",
        Image="C:\\Tools\\loader.exe",
        User="CORP\\svc",
        ImageLoaded=f"C:\\Windows\\System32\\{dll}",
        Signed="true",
    )


def test_image_loads_are_counted_and_capped(write_jsonl: Any, make_record: Any) -> None:
    rows = [create(make_record, 1, "00.000", 1)]
    rows += [_load(make_record, 100 + i, i % 60, 1, f"lib{i:03d}.dll") for i in range(70)]
    node = build(write_jsonl, rows).nodes[guid(1)]
    assert node.image_load_count == 70
    assert len(node.image_loads) == 50
    assert node.activity == ()
    order = [(load.ts_us, load.source.record_id) for load in node.image_loads]
    assert order == sorted(order)
    assert node.image_loads[0].image_loaded == "C:\\Windows\\System32\\lib000.dll"
    assert node.image_loads[0].signed == "true"


def test_image_load_from_unknown_process_creates_ghost(write_jsonl: Any, make_record: Any) -> None:
    graph = build(write_jsonl, [_load(make_record, 1, 0, 9, "a.dll")])
    ghost = graph.nodes[guid(9)]
    assert ghost.is_ghost and ghost.ghost_reason == "activity_reference"
    assert (ghost.image_name, ghost.pid, ghost.user) == ("loader.exe", 77, "CORP\\svc")
    assert ghost.image_load_count == 1
    assert graph.counters.ghosts == {"activity_reference": 1}


def test_image_loads_without_guid_are_counted_unattached(
    write_jsonl: Any, make_record: Any
) -> None:
    rows = [_load(make_record, 10 + i, i, "{bad}", f"x{i}.dll") for i in range(55)]
    rows.append(_load(make_record, 99, 59, "{00000000-0000-0000-0000-000000000000}", "z.dll"))
    graph = build(write_jsonl, rows)
    assert graph.nodes == {}
    assert graph.counters.unattached_events == 56
    assert len(graph.unattached_image_loads) == 50
    assert graph.unattached_events == ()


def test_image_loads_count_in_event_ids_seen(write_jsonl: Any, make_record: Any) -> None:
    rows = [create(make_record, 1, "00.000", 1), _load(make_record, 2, 1, 1, "a.dll")]
    result = read_inputs([write_jsonl(rows)])
    assert result.event_ids_seen == {"1": 1, "7": 1}
    assert result.event_count == 2
    assert len(result.events) == 1 and len(result.image_loads) == 1


def test_image_load_dedupe_without_record_id(write_jsonl: Any, make_record: Any) -> None:
    same = _load(make_record, None, 5, 1, "a.dll")
    other = _load(make_record, None, 5, 1, "b.dll")
    result = read_inputs([write_jsonl([same, dict(same), other])])
    assert len(result.image_loads) == 2
    assert result.counters.duplicates_dropped == 1
    assert result.counters.duplicate_conflicts == 0


def test_trusted_models_share_fields_set_but_copy_safely() -> None:
    from lineage_ir.models import ImageLoad, SourceRef, construct_trusted

    source = construct_trusted(SourceRef, file="f", file_sha256="0", index=1, record_id=None)
    first = construct_trusted(ImageLoad, ts_us=1, image_loaded=None, signed=None, source=source)
    second = construct_trusted(ImageLoad, ts_us=2, image_loaded="x", signed="true", source=source)
    assert first.model_fields_set is second.model_fields_set
    changed = first.model_copy(update={"ts_us": 5})
    assert changed.ts_us == 5 and first.ts_us == 1
    assert second.model_fields_set == {"ts_us", "image_loaded", "signed", "source"}
    with pytest.raises(ValueError):
        first.ts_us = 9  # type: ignore[misc]
