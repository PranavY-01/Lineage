"""Iterative graph walks and the display collapse rule (§7.3, §7.4); no recursion."""

from collections import deque
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from lineage_ir.graph.model import ProcessGraph


def ancestors(graph: ProcessGraph, guid: str) -> list[str]:
    """Ancestors nearest-first; stops at a node with no parent or at a revisit."""
    result: list[str] = []
    seen = {guid}
    node = graph.nodes.get(guid)
    parent = node.parent_guid if node else None
    while parent is not None and parent not in seen:
        result.append(parent)
        seen.add(parent)
        parent = graph.nodes[parent].parent_guid
    return result


def descendants(graph: ProcessGraph, guid: str) -> list[str]:
    """All descendants in breadth-first order, following each node's child order."""
    result: list[str] = []
    seen = {guid}
    queue = deque(graph.nodes[guid].children if guid in graph.nodes else ())
    while queue:
        child = queue.popleft()
        if child in seen:
            continue
        seen.add(child)
        result.append(child)
        queue.extend(graph.nodes[child].children)
    return result


def hot_set(graph: ProcessGraph, flagged: Iterable[str]) -> frozenset[str]:
    """Flagged nodes plus every ancestor: the nodes with a finding in their subtree."""
    hot: set[str] = set()
    for guid in flagged:
        if guid in graph.nodes:
            hot.add(guid)
            hot.update(ancestors(graph, guid))
    return frozenset(hot)


@dataclass(frozen=True, slots=True)
class CollapsedGroup:
    """Siblings shown as one line: ``× N image_name (first start – last start)``."""

    image_name: str
    guids: tuple[str, ...]
    first_start_us: int | None
    last_start_us: int | None


def collapse_children(
    graph: ProcessGraph,
    children: Sequence[str],
    keep: frozenset[str],
    min_count: int,
) -> list[str | CollapsedGroup]:
    """Fold same-named siblings outside ``keep`` into groups of at least ``min_count``.

    ``keep`` holds nodes that must stay visible: hot nodes (see ``hot_set``) and any focus
    set. A group takes the position of its first member; order is otherwise unchanged.
    """
    members: dict[str, list[str]] = {}
    for guid in children:
        name = graph.nodes[guid].image_name
        if guid not in keep and name:
            members.setdefault(name, []).append(guid)
    groups = {name: guids for name, guids in members.items() if len(guids) >= min_count}
    grouped = {guid for guids in groups.values() for guid in guids}

    result: list[str | CollapsedGroup] = []
    for guid in children:
        if guid not in grouped:
            result.append(guid)
            continue
        name = graph.nodes[guid].image_name or ""
        guids = groups[name]
        if guid != guids[0]:
            continue
        starts = [s for g in guids if (s := graph.nodes[g].start_us) is not None]
        result.append(
            CollapsedGroup(
                image_name=name,
                guids=tuple(guids),
                first_start_us=min(starts) if starts else None,
                last_start_us=max(starts) if starts else None,
            )
        )
    return result


def hot_only_children(children: Sequence[str], hot: frozenset[str]) -> tuple[list[str], int]:
    """Children kept in ``--hot-only`` mode and the number hidden (``… N benign children``)."""
    kept = [guid for guid in children if guid in hot]
    return kept, len(children) - len(kept)
