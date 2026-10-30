"""Storyline roots and membership (§9.2), assembled with steps, gaps and scope, then ranked."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from lineage_ir.analyze.filters import SEVERITY_RANK
from lineage_ir.analyze.gaps import storyline_gaps
from lineage_ir.analyze.ranking import rank
from lineage_ir.analyze.scope import build_scope
from lineage_ir.analyze.steps import SourceKey, build_steps, source_key
from lineage_ir.detect.engine import HOST_NODE_PREFIX
from lineage_ir.detect.graph_rules import AnchorTest
from lineage_ir.graph.model import ProcessGraph
from lineage_ir.graph.traverse import ancestors, descendants
from lineage_ir.models import Event, Finding, IngestResult, Storyline


@dataclass
class _Group:
    host: str
    root: str
    anchor_image_name: str | None
    flagged: set[str] = field(default_factory=set)


def find_root(graph: ProcessGraph, guid: str, is_anchor: AnchorTest) -> tuple[str, str | None]:
    """(root, anchor image name): the last node before the first anchor walking up, the
    topmost ancestor when no anchor is met, or the node itself when it is an anchor."""
    if is_anchor(graph.nodes[guid]):
        return guid, None
    previous = guid
    for ancestor in ancestors(graph, guid):
        node = graph.nodes[ancestor]
        if is_anchor(node):
            return previous, node.image_name
        previous = ancestor
    return previous, None


def _group_findings(
    graphs: Mapping[str, ProcessGraph], findings: Sequence[Finding], is_anchor: AnchorTest
) -> dict[tuple[str, str], _Group]:
    groups: dict[tuple[str, str], _Group] = {}
    for finding in findings:
        graph = graphs.get(finding.host)
        if graph is None or finding.guid not in graph.nodes:
            # Host-level findings (and any GUID that has no node) share one storyline per host.
            root, anchor, flagged = f"{HOST_NODE_PREFIX}{finding.host}", None, None
        else:
            root, anchor = find_root(graph, finding.guid, is_anchor)
            flagged = finding.guid
        group = groups.setdefault((finding.host, root), _Group(finding.host, root, anchor))
        group.flagged.add(flagged or root)
    return groups


def _members(graph: ProcessGraph, group: _Group) -> tuple[list[str], set[str], set[str]]:
    """Nodes in pre-order from the root, the path nodes and the descendant nodes."""
    path: set[str] = set()
    for guid in group.flagged:
        for node in (guid, *ancestors(graph, guid)):
            path.add(node)
            if node == group.root:
                break
    path -= group.flagged
    below: set[str] = set()
    for guid in group.flagged:
        below.update(descendants(graph, guid))
    below -= group.flagged | path
    members = group.flagged | path | below
    order: list[str] = []
    stack = [group.root]
    while stack:
        guid = stack.pop()
        order.append(guid)
        stack.extend(reversed([c for c in graph.nodes[guid].children if c in members]))
    return order, path, below


def evidence_events(ingest: IngestResult, findings: Sequence[Finding]) -> dict[SourceKey, Event]:
    wanted = {source_key(s) for f in findings for s in f.evidence}
    return {source_key(e.source): e for e in ingest.events if source_key(e.source) in wanted}


def _tactics(findings: Sequence[Finding]) -> tuple[str, ...]:
    ordered: list[str] = []
    for finding in sorted(findings, key=lambda f: (f.first_us, f.rule_id)):
        ordered.extend(t for t in finding.tactics if t not in ordered)
    return tuple(ordered)


def _storyline(
    group: _Group,
    graph: ProcessGraph | None,
    findings: Sequence[Finding],
    events: Mapping[SourceKey, Event],
    gap_seconds: int,
) -> Storyline:
    if graph is None or group.root.startswith(HOST_NODE_PREFIX):
        nodes, path, below = [group.root], set(), set()
        node_graph = None
        mine = [
            f
            for f in findings
            if f.host == group.host and f.guid not in (graph.nodes if graph else {})
        ]
    else:
        nodes, path, below = _members(graph, group)
        node_graph = graph
        member_set = set(nodes)
        mine = [f for f in findings if f.host == group.host and f.guid in member_set]
    steps = build_steps(node_graph, nodes, group.flagged, mine, events)
    root_node = node_graph.nodes[group.root] if node_graph is not None else None
    users: list[str] = []
    if node_graph is not None:
        for guid in nodes:
            user = node_graph.nodes[guid].user
            if user and user not in users:
                users.append(user)
    if steps:
        start_us, end_us = steps[0].ts_us, steps[-1].ts_us
    else:
        start_us = min(f.first_us for f in mine)
        end_us = max(f.last_us for f in mine)
    return Storyline(
        storyline_id="",
        host=group.host,
        root_guid=group.root,
        root_image_name=root_node.image_name if root_node is not None else None,
        anchor_image_name=group.anchor_image_name,
        flagged=tuple(g for g in nodes if g in group.flagged),
        path_nodes=tuple(g for g in nodes if g in path),
        descendant_nodes=tuple(g for g in nodes if g in below),
        nodes=tuple(nodes),
        finding_ids=tuple(f.finding_id for f in mine),
        max_severity=max(mine, key=lambda f: SEVERITY_RANK[f.severity]).severity,
        tactics=_tactics(mine),
        users=tuple(users),
        start_us=start_us,
        end_us=end_us,
        steps=steps,
        gaps=storyline_gaps(steps, gap_seconds),
        scope=build_scope(node_graph, nodes, mine),
        links=(),
    )


def build_storylines(
    ingest: IngestResult,
    graphs: Mapping[str, ProcessGraph],
    findings: Sequence[Finding],
    is_anchor: AnchorTest,
    gap_seconds: int,
) -> tuple[Storyline, ...]:
    """One storyline per (host, root) of flagged nodes, ranked and numbered S1…Sn."""
    groups = _group_findings(graphs, findings, is_anchor)
    events = evidence_events(ingest, findings)
    stories = [
        _storyline(group, graphs.get(group.host), findings, events, gap_seconds)
        for _, group in sorted(groups.items())
    ]
    return rank(stories)
