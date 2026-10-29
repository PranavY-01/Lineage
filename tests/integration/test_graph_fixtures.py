"""Graph fixtures, invariants (§7.6), shuffle invariance and scale (§14.3 item 1)."""

import json
import random
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from lineage_ir.graph.builder import build_graphs
from lineage_ir.graph.model import ProcessGraph
from lineage_ir.graph.traverse import ancestors, descendants
from lineage_ir.ingest.normalize import WMI_EVENT_IDS, canonical_guid
from lineage_ir.ingest.reader import read_inputs
from lineage_ir.models import Event

HOST = "ws-14.corp.example"
GRAPH_FIXTURES = ("ghosts", "zero_guid", "bad_guid", "cycle", "multi_host", "duplicates")
# duplicates.jsonl holds a conflicting duplicate, which §6.8 resolves by input order, so a
# shuffle legitimately changes which copy survives; it is checked for invariants only.
SHUFFLE_FIXTURES = tuple(name for name in GRAPH_FIXTURES if name != "duplicates")


def guid(tag: int) -> str:
    return f"6c1e0a2b-7d3f-4e5a-9b8c-{tag:012x}"


def load(path: Path) -> tuple[tuple[Event, ...], dict[str, ProcessGraph]]:
    events = read_inputs([path]).events
    return events, build_graphs(events)


def _valid(event: Event, key: str) -> str | None:
    return canonical_guid(event.fields.get(key))[0]


def assert_invariants(events: tuple[Event, ...], graphs: dict[str, ProcessGraph]) -> None:
    """§7.6 invariants 1, 2 and 5 (as amended): every event is accounted for exactly once."""
    actor: Counter[tuple[str, int]] = Counter()
    target: Counter[tuple[str, int]] = Counter()
    created: Counter[tuple[str, int]] = Counter()
    parked: Counter[tuple[str, int]] = Counter()
    ignored_creations = 0
    for graph in graphs.values():
        for node in graph.nodes.values():
            # Invariant 1: created by event 1, or a ghost with a reason.
            assert (node.create_record is not None) != node.is_ghost
            assert node.is_ghost == (node.ghost_reason is not None)
            # Invariant 2: parents exist in the same host graph; children point back.
            if node.parent_guid is not None:
                assert node.parent_guid in graph.nodes
                assert node.guid in graph.nodes[node.parent_guid].children
            for child in node.children:
                assert graph.nodes[child].parent_guid == node.guid
            if node.create_record:
                created[(node.create_record.file, node.create_record.index)] += 1
            for item in node.activity:
                counter = actor if item.role == "actor" else target
                counter[(item.source.file, item.source.index)] += 1
        for event in graph.wmi_events + graph.unattached_events:
            parked[(event.source.file, event.source.index)] += 1
        ignored_creations += graph.counters.duplicate_creations + graph.counters.creation_conflicts

    unplaced_creations = 0
    for event in events:
        key = (event.source.file, event.source.index)
        if event.event_id == 1:
            placed = created[key] + parked[key]
            assert placed <= 1
            unplaced_creations += 1 - placed
            continue
        if event.event_id in WMI_EVENT_IDS:
            assert (parked[key], actor[key], target[key]) == (1, 0, 0)
            continue
        if event.event_id in (8, 10):
            has_source = _valid(event, "source_process_guid") is not None
            has_target = _valid(event, "target_process_guid") is not None
            assert actor[key] == int(has_source)
            assert target[key] == int(has_target)
            assert parked[key] == int(not has_source and not has_target)
            continue
        has_actor = event.process_guid is not None
        assert (actor[key], target[key], parked[key]) == (int(has_actor), 0, int(not has_actor))
    # Event 1 records that made no node were ignored as duplicates or conflicts.
    assert unplaced_creations == ignored_creations


@pytest.mark.parametrize("name", GRAPH_FIXTURES)
def test_invariants_hold_on_fixtures(fixtures_dir: Path, name: str) -> None:
    events, graphs = load(fixtures_dir / f"{name}.jsonl")
    assert_invariants(events, graphs)


def test_ghost_reasons_and_seeding(fixtures_dir: Path) -> None:
    _, graphs = load(fixtures_dir / "ghosts.jsonl")
    graph = graphs[HOST]
    assert graph.counters.ghosts == {
        "access_reference": 3,
        "activity_reference": 2,
        "parent_reference": 1,
    }
    parent = graph.nodes[guid(0xF1)]
    assert parent.is_ghost and parent.ghost_reason == "parent_reference"
    assert (parent.image, parent.pid, parent.command_line, parent.user) == (
        "C:\\Windows\\explorer.exe",
        1000,
        "C:\\Windows\\Explorer.EXE",
        "CORP\\jdoe",
    )
    assert parent.start_us is None and parent.parent_guid is None
    assert parent.children == (guid(0xC1),)

    beacon = graph.nodes[guid(0x61)]
    assert beacon.ghost_reason == "activity_reference"
    assert (beacon.image_name, beacon.pid, beacon.user) == ("beacon.exe", 2222, "CORP\\jdoe")
    assert [a.kind for a in beacon.activity] == ["network", "file_create"]

    dumper = graph.nodes[guid(0x51)]
    lsass = graph.nodes[guid(0x71)]
    assert (dumper.ghost_reason, dumper.image_name, dumper.pid) == (
        "access_reference",
        "dump.exe",
        3333,
    )
    assert (lsass.ghost_reason, lsass.image_name, lsass.pid) == (
        "access_reference",
        "lsass.exe",
        700,
    )
    assert [a.role for a in lsass.activity] == ["target"]

    # First reference wins: agent.exe was seen acting before it appeared as a parent.
    agent = graph.nodes[guid(0x81)]
    assert agent.ghost_reason == "activity_reference"
    assert agent.user is None
    assert agent.children == (guid(0xC2),)


def test_ghosts_sort_after_created_children(fixtures_dir: Path) -> None:
    _, graphs = load(fixtures_dir / "ghosts.jsonl")
    graph = graphs[HOST]
    created_roots = [g for g in graph.roots if not graph.nodes[g].is_ghost]
    ghost_roots = [g for g in graph.roots if graph.nodes[g].is_ghost]
    assert list(graph.roots) == created_roots + ghost_roots
    assert ghost_roots == sorted(ghost_roots)


def test_zero_guids(fixtures_dir: Path) -> None:
    _, graphs = load(fixtures_dir / "zero_guid.jsonl")
    graph = graphs[HOST]
    assert list(graph.nodes) == [guid(0xA1)]
    node = graph.nodes[guid(0xA1)]
    assert node.parent_guid is None
    assert graph.counters.ghosts == {}
    assert [e.source.record_id for e in graph.unattached_events] == [202, 203, 204]
    assert graph.counters.unattached_events == 3
    assert [(a.kind, a.role) for a in node.activity] == [("process_access", "target")]


def test_bad_guids(fixtures_dir: Path) -> None:
    result = read_inputs([fixtures_dir / "bad_guid.jsonl"])
    assert result.counters.bad_guid == 6
    graph = build_graphs(result.events)[HOST]
    assert list(graph.nodes) == [guid(0xB1)]
    assert graph.nodes[guid(0xB1)].parent_guid is None
    assert graph.counters.ghosts == {}
    assert [e.source.record_id for e in graph.unattached_events] == [302, 304, 305]
    assert [(a.kind, a.role) for a in graph.nodes[guid(0xB1)].activity] == [
        ("remote_thread", "target")
    ]


def test_cycle_is_broken_deterministically(fixtures_dir: Path) -> None:
    _, graphs = load(fixtures_dir / "cycle.jsonl")
    graph = graphs[HOST]
    a, b, c = guid(0xD1), guid(0xD2), guid(0xD3)
    assert graph.counters.cycles_broken == 1
    assert [(e.child, e.parent) for e in graph.broken_edges] == [(b, a)]
    assert graph.roots == (b,)
    assert graph.nodes[a].parent_guid == b
    assert ancestors(graph, c) == [a, b]
    assert descendants(graph, b) == [a, c]


def _comparable(value: Any) -> Any:
    """Drop provenance (indexes change when lines are shuffled) and keep everything else."""
    if isinstance(value, dict):
        return {
            k: _comparable(v)
            for k, v in value.items()
            if k not in {"source", "create_record", "index"}
        }
    if isinstance(value, list | tuple):
        return [_comparable(v) for v in value]
    return value


def _graph_dump(graphs: dict[str, ProcessGraph]) -> Any:
    return _comparable({h: g.model_dump() for h, g in graphs.items()})


@pytest.mark.parametrize("name", SHUFFLE_FIXTURES)
def test_shuffle_invariance(fixtures_dir: Path, tmp_path: Path, name: str) -> None:
    lines = (fixtures_dir / f"{name}.jsonl").read_text(encoding="utf-8").splitlines()
    baseline = _graph_dump(load(fixtures_dir / f"{name}.jsonl")[1])
    for seed in range(20):
        shuffled = lines[:]
        random.Random(seed).shuffle(shuffled)
        path = tmp_path / f"{name}-{seed}.jsonl"
        path.write_text("\n".join(shuffled) + "\n", encoding="utf-8", newline="\n")
        events, graphs = load(path)
        assert _graph_dump(graphs) == baseline
        assert_invariants(events, graphs)


def _create(rid: int, tag: int, parent: int | None, second: int) -> dict[str, Any]:
    record: dict[str, Any] = {
        "EventID": 1,
        "Hostname": HOST,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "RecordNumber": rid,
        "UtcTime": f"2026-10-12 {second // 3600:02d}:{second // 60 % 60:02d}:{second % 60:02d}.000",
        "ProcessGuid": "{" + guid(tag) + "}",
        "ProcessId": str(tag),
        "Image": "C:\\Windows\\System32\\cmd.exe",
    }
    if parent is not None:
        record["ParentProcessGuid"] = "{" + guid(parent) + "}"
    return record


def test_deep_chain_does_not_recurse(tmp_path: Path) -> None:
    depth = 10_000
    rows = [_create(i + 1, i + 1, i if i else None, i) for i in range(depth)]
    path = tmp_path / "deep_chain.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8", newline="\n")
    events, graphs = load(path)
    graph = graphs[HOST]
    assert len(graph.nodes) == depth
    chain = ancestors(graph, guid(depth))
    assert len(chain) == depth - 1 and chain[0] == guid(depth - 1) and chain[-1] == guid(1)
    assert len(descendants(graph, guid(1))) == depth - 1
    assert_invariants(events, graphs)


def test_wide_fanout(tmp_path: Path) -> None:
    rows = [_create(1, 1, None, 0)] + [_create(i + 2, i + 2, 1, 1 + i) for i in range(500)]
    path = tmp_path / "wide_fanout.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8", newline="\n")
    _, graphs = load(path)
    root = graphs[HOST].nodes[guid(1)]
    assert len(root.children) == 500
    assert list(root.children) == [guid(i + 2) for i in range(500)]
