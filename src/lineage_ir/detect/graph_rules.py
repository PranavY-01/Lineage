"""Graph heuristics GR-001 to GR-004 (§8.7)."""

from collections import Counter, defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from lineage_ir.detect.fields import destination
from lineage_ir.detect.schema import fold
from lineage_ir.graph.model import ProcessGraph
from lineage_ir.graph.traverse import ancestors
from lineage_ir.models import Event, ProcessNode, RuleInfo, Severity, SourceRef

# Whether a node is an anchor (§9.1). The engine supplies it; detection never assumes one.
AnchorTest = Callable[[ProcessNode], bool]

# The LIN-001 parent list.
OFFICE_IMAGES = frozenset(
    f"{name}.exe"
    for name in ("winword", "excel", "powerpnt", "outlook", "msaccess", "mspub", "onenote")
)
DISCOVERY_IMAGES = frozenset(
    f"{name}.exe"
    for name in (
        "whoami",
        "systeminfo",
        "nltest",
        "net",
        "net1",
        "ipconfig",
        "quser",
        "tasklist",
        "netstat",
        "arp",
        "route",
        "nslookup",
    )
)
DISCOVERY_WINDOW_US = 120 * 1_000_000
DISCOVERY_MIN_BINARIES = 3


@dataclass(frozen=True, slots=True)
class GraphHit:
    """Matches for one node: (time, record) pairs in time order and the finding details."""

    guid: str
    matches: tuple[tuple[int, SourceRef], ...]
    details: dict[str, str]


Evaluate = Callable[[ProcessGraph, Sequence[Event], AnchorTest], list[GraphHit]]


@dataclass(frozen=True, slots=True)
class GraphRule:
    info: RuleInfo
    evaluate: Evaluate


def _office_descendant_connected(
    graph: ProcessGraph, _events: Sequence[Event], is_anchor: AnchorTest
) -> list[GraphHit]:
    hits = []
    for guid in sorted(graph.nodes):
        connections = [
            a
            for a in graph.nodes[guid].activity
            if a.kind == "network"
            and a.role == "actor"
            and a.fields.get("initiated", "").casefold() == "true"
        ]
        if not connections:
            continue
        office = None
        for ancestor in ancestors(graph, guid):
            node = graph.nodes[ancestor]
            if is_anchor(node):
                break
            if node.image_name in OFFICE_IMAGES:
                office = node.image_name
                break
        if office is None:
            continue
        details = {"office_ancestor": office}
        target = destination(connections[0].fields)
        if target:
            details["destination"] = target
        hits.append(GraphHit(guid, tuple((a.ts_us, a.source) for a in connections), details))
    return hits


def _discovery_burst(
    graph: ProcessGraph, _events: Sequence[Event], _is_anchor: AnchorTest
) -> list[GraphHit]:
    by_parent: defaultdict[str, list[ProcessNode]] = defaultdict(list)
    for node in graph.nodes.values():
        if (
            node.parent_guid is not None
            and node.image_name in DISCOVERY_IMAGES
            and node.start_us is not None
            and node.create_record is not None
        ):
            by_parent[node.parent_guid].append(node)
    hits = []
    for parent in sorted(by_parent):
        children = sorted(by_parent[parent], key=lambda n: (n.start_us or 0, n.guid))
        starts = [n.start_us or 0 for n in children]
        names: Counter[str] = Counter()
        members: list[ProcessNode] = []
        left = 0
        marked = -1
        # Sliding window: first to last creation at most DISCOVERY_WINDOW_US apart.
        for right, child in enumerate(children):
            names[child.image_name or ""] += 1
            while starts[right] - starts[left] > DISCOVERY_WINDOW_US:
                gone = children[left].image_name or ""
                names[gone] -= 1
                if not names[gone]:
                    del names[gone]
                left += 1
            if len(names) >= DISCOVERY_MIN_BINARIES:
                members.extend(children[max(left, marked + 1) : right + 1])
                marked = right
        if members:
            binaries = ", ".join(sorted({m.image_name or "" for m in members}))
            matches = tuple(
                (m.start_us or 0, m.create_record) for m in members if m.create_record is not None
            )
            hits.append(GraphHit(parent, matches, {"binaries": binaries}))
    return hits


def _dropped_file_executed(
    graph: ProcessGraph, events: Sequence[Event], _is_anchor: AnchorTest
) -> list[GraphHit]:
    # Events arrive in global order, so "later" means after the file creation in that order.
    drops: dict[str, Event] = {}
    hits = []
    for event in events:
        if event.event_id == 11:
            target = event.fields.get("target_filename")
            if target:
                drops[fold("target_filename", target)] = event
            continue
        if event.event_id != 1 or event.process_guid is None:
            continue
        node = graph.nodes.get(event.process_guid)
        image = event.fields.get("image")
        if node is None or node.create_record != event.source or not image:
            continue
        drop = drops.get(fold("image", image))
        if drop is None:
            continue
        details = {"target_filename": drop.fields["target_filename"]}
        if drop.process_guid:
            details["creator_guid"] = drop.process_guid
        if drop.image:
            details["creator_image"] = drop.image
        # Evidence is the execution only; the write is referenced in details (amendment 18).
        details["write_file"] = drop.source.file
        details["write_index"] = str(drop.source.index)
        hits.append(GraphHit(event.process_guid, ((event.ts_us, event.source),), details))
    return hits


def _active_ghost(
    graph: ProcessGraph, _events: Sequence[Event], _is_anchor: AnchorTest
) -> list[GraphHit]:
    hits = []
    for guid in sorted(graph.nodes):
        node = graph.nodes[guid]
        if not node.is_ghost or node.ghost_reason != "activity_reference":
            continue
        # Only network and file_create: file_stream and other never count (amendment 4).
        active = [a for a in node.activity if a.kind in ("network", "file_create")]
        if active:
            kinds = ", ".join(sorted({a.kind for a in active}))
            hits.append(
                GraphHit(guid, tuple((a.ts_us, a.source) for a in active), {"activity": kinds})
            )
    return hits


def _info(
    rule_id: str,
    title: str,
    severity: Severity,
    event_ids: tuple[int, ...],
    *,
    attack: tuple[str, ...],
    tactics: tuple[str, ...],
    why: str,
) -> RuleInfo:
    return RuleInfo(
        id=rule_id,
        kind="graph",
        title=title,
        severity=severity,
        event_ids=event_ids,
        attack=attack,
        tactics=tactics,
        why=why,
    )


GRAPH_RULES = (
    GraphRule(
        _info(
            "GR-001",
            "Office-descended process connected out",
            "high",
            (1, 3),
            attack=("T1204.002",),
            tactics=("execution", "command-and-control"),
            why=(
                "A process started below an Office application made an outbound connection; "
                "documents that launch helpers which then reach the network are a common "
                "phishing delivery pattern."
            ),
        ),
        _office_descendant_connected,
    ),
    GraphRule(
        _info(
            "GR-002",
            "Discovery burst",
            "medium",
            (1,),
            attack=("T1033", "T1082", "T1016", "T1087", "T1482", "T1057"),
            tactics=("discovery",),
            why=(
                "Three or more different discovery tools started by one parent within two "
                "minutes look like hands-on or scripted reconnaissance rather than routine use."
            ),
        ),
        _discovery_burst,
    ),
    GraphRule(
        _info(
            "GR-003",
            "Dropped file later executed",
            "medium",
            (1, 11),
            attack=("T1105",),
            tactics=("execution",),
            why=(
                "A file written to disk and then started as a process on the same host is how "
                "dropped payloads usually begin."
            ),
        ),
        _dropped_file_executed,
    ),
    GraphRule(
        _info(
            "GR-004",
            "Active process with no creation record",
            "info",
            (1,),
            attack=(),
            tactics=(),
            why=(
                "A process used the network or created files, but its creation was never "
                "recorded, so its origin is unknown."
            ),
        ),
        _active_ghost,
    ),
)
