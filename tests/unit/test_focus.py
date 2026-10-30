"""Focus resolution and the focus set (§9.7)."""

from pathlib import Path

import pytest

from helpers.chain import EXPLORER, HOST, Chain, guid
from lineage_ir.analyze.focus import focus_set, resolve_focus
from lineage_ir.engine import build_host_graphs
from lineage_ir.errors import UsageError
from lineage_ir.graph.model import ProcessGraph
from lineage_ir.ingest.reader import read_inputs


def graphs_for(tmp_path: Path, chain: Chain) -> dict[str, ProcessGraph]:
    return build_host_graphs(read_inputs([chain.write(tmp_path / "in.jsonl")]))


@pytest.fixture
def tree(tmp_path: Path) -> dict[str, ProcessGraph]:
    chain = Chain().create(1, EXPLORER)
    chain.create(2, "C:\\Tools\\a.exe", 1, 1, pid=500)
    chain.create(3, "C:\\Tools\\b.exe", 2, 2)
    chain.create(4, "C:\\Tools\\c.exe", 3, 3)
    chain.create(5, "C:\\Tools\\a.exe", 1, 4, pid=500)
    chain.create(6, "C:\\Tools\\d.exe", 1, 5, host="ws-15.corp.example")
    return graphs_for(tmp_path, chain)


def test_guid_with_or_without_braces(tree: dict[str, ProcessGraph]) -> None:
    assert resolve_focus(tree, guid(3)) == ((HOST, guid(3)),)
    assert resolve_focus(tree, "{" + guid(3).upper() + "}") == ((HOST, guid(3)),)
    assert resolve_focus(tree, guid(6)) == (("ws-15.corp.example", guid(6)),)


def test_guid_not_found(tree: dict[str, ProcessGraph]) -> None:
    with pytest.raises(UsageError, match="not found"):
        resolve_focus(tree, guid(99))
    with pytest.raises(UsageError):
        resolve_focus(tree, "not-a-guid")


def test_pid(tree: dict[str, ProcessGraph]) -> None:
    assert resolve_focus(tree, "pid:1003") == ((HOST, guid(3)),)
    with pytest.raises(UsageError) as info:
        resolve_focus(tree, "pid:500")
    message = str(info.value)
    assert guid(2) in message and guid(5) in message and "a.exe" in message
    with pytest.raises(UsageError, match="not found"):
        resolve_focus(tree, "pid:4242")
    with pytest.raises(UsageError):
        resolve_focus(tree, "pid:abc")


def test_image(tree: dict[str, ProcessGraph]) -> None:
    assert resolve_focus(tree, "image:A.EXE") == ((HOST, guid(2)), (HOST, guid(5)))
    with pytest.raises(UsageError, match="not found"):
        resolve_focus(tree, "image:zzz.exe")


def test_image_cap(tmp_path: Path) -> None:
    chain = Chain()
    for tag in range(1, 22):
        chain.create(tag, "C:\\Tools\\many.exe", None, tag)
    graphs = graphs_for(tmp_path, chain)
    with pytest.raises(UsageError, match="21"):
        resolve_focus(graphs, "image:many.exe")
    chain.rows.pop()
    assert len(resolve_focus(graphs_for(tmp_path, chain), "image:many.exe")) == 20


def test_unknown_form(tree: dict[str, ProcessGraph]) -> None:
    with pytest.raises(UsageError):
        resolve_focus(tree, "name:a.exe")


def test_focus_set_is_node_ancestors_and_descendants(tree: dict[str, ProcessGraph]) -> None:
    targets = resolve_focus(tree, guid(3))
    assert focus_set(tree, targets) == {HOST: frozenset({guid(1), guid(2), guid(3), guid(4)})}
    both = resolve_focus(tree, "image:a.exe")
    assert focus_set(tree, both)[HOST] == frozenset({guid(t) for t in (1, 2, 3, 4, 5)})
