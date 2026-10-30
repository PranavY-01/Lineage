from typing import Any

from lineage_ir.graph.builder import build_graphs
from lineage_ir.graph.model import ProcessGraph
from lineage_ir.graph.traverse import (
    CollapsedGroup,
    ancestors,
    collapse_children,
    descendants,
    hot_only_children,
    hot_set,
)
from lineage_ir.ingest.reader import read_inputs

HOST = "ws-14.corp.example"


def guid(tag: int) -> str:
    return f"6c1e0a2b-7d3f-4e5a-9b8c-{tag:012x}"


def tree(
    write_jsonl: Any, make_record: Any, spec: list[tuple[int, int | None, str]]
) -> ProcessGraph:
    """Build a graph from (tag, parent_tag, image_name) triples, one second apart."""
    rows = []
    for i, (tag, parent, name) in enumerate(spec):
        fields = {
            "ProcessGuid": "{" + guid(tag) + "}",
            "ProcessId": str(tag),
            "Image": f"C:\\Windows\\System32\\{name}",
        }
        if parent is not None:
            fields["ParentProcessGuid"] = "{" + guid(parent) + "}"
        rows.append(
            make_record(1, i + 1, f"2026-10-12 10:{i // 60:02d}:{i % 60:02d}.000", **fields)
        )
    return build_graphs(read_inputs([write_jsonl(rows)]).events)[HOST]


SPEC = [
    (1, None, "explorer.exe"),
    (2, 1, "outlook.exe"),
    (3, 2, "winword.exe"),
    (4, 3, "cmd.exe"),
    (5, 1, "notepad.exe"),
    (6, 4, "conhost.exe"),
]


def test_ancestors_nearest_first(write_jsonl: Any, make_record: Any) -> None:
    graph = tree(write_jsonl, make_record, SPEC)
    assert ancestors(graph, guid(4)) == [guid(3), guid(2), guid(1)]
    assert ancestors(graph, guid(1)) == []
    assert ancestors(graph, "missing") == []


def test_descendants_breadth_first(write_jsonl: Any, make_record: Any) -> None:
    graph = tree(write_jsonl, make_record, SPEC)
    assert descendants(graph, guid(1)) == [guid(2), guid(5), guid(3), guid(4), guid(6)]
    assert descendants(graph, guid(6)) == []
    assert descendants(graph, "missing") == []


def test_hot_set(write_jsonl: Any, make_record: Any) -> None:
    graph = tree(write_jsonl, make_record, SPEC)
    assert hot_set(graph, [guid(4), "missing"]) == {guid(4), guid(3), guid(2), guid(1)}


def test_collapse_groups_same_named_siblings(write_jsonl: Any, make_record: Any) -> None:
    spec = [(1, None, "services.exe")]
    spec += [(10 + i, 1, "svchost.exe") for i in range(4)]
    spec += [(20, 1, "spoolsv.exe"), (21, 1, "dllhost.exe"), (22, 1, "dllhost.exe")]
    graph = tree(write_jsonl, make_record, spec)
    children = graph.nodes[guid(1)].children
    items = collapse_children(graph, children, frozenset(), min_count=3)
    group = items[0]
    assert isinstance(group, CollapsedGroup)
    assert group.image_name == "svchost.exe"
    assert group.guids == tuple(guid(10 + i) for i in range(4))
    assert group.first_start_us == graph.nodes[guid(10)].start_us
    assert group.last_start_us == graph.nodes[guid(13)].start_us
    assert items[1:] == [guid(20), guid(21), guid(22)]


def test_collapse_never_folds_kept_nodes(write_jsonl: Any, make_record: Any) -> None:
    spec = [(1, None, "services.exe")] + [(10 + i, 1, "svchost.exe") for i in range(4)]
    graph = tree(write_jsonl, make_record, spec)
    children = graph.nodes[guid(1)].children
    keep = hot_set(graph, [guid(11)])
    items = collapse_children(graph, children, keep, min_count=3)
    assert items[1] == guid(11)
    groups = [i for i in items if isinstance(i, CollapsedGroup)]
    assert len(groups) == 1 and guid(11) not in groups[0].guids
    assert len(groups[0].guids) == 3
    keep_more = keep | {guid(12)}
    assert all(isinstance(i, str) for i in collapse_children(graph, children, keep_more, 3))


def test_hot_only_children(write_jsonl: Any, make_record: Any) -> None:
    graph = tree(write_jsonl, make_record, SPEC)
    hot = hot_set(graph, [guid(4)])
    kept, hidden = hot_only_children(graph.nodes[guid(1)].children, hot)
    assert kept == [guid(2)] and hidden == 1
