"""Event-rule evaluation, graph heuristics and finding aggregation (§8.8)."""

import hashlib
from collections import defaultdict, deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field

from lineage_ir.detect.fields import EventFields, destination, rule_matches
from lineage_ir.detect.graph_rules import GRAPH_RULES, AnchorTest, GraphRule
from lineage_ir.detect.schema import Rule
from lineage_ir.graph.model import ProcessGraph
from lineage_ir.ingest.normalize import image_name
from lineage_ir.models import Event, Finding, FrozenModel, IngestResult, RuleInfo, SourceRef

EVIDENCE_HEAD = 10
EVIDENCE_TAIL = 10
COMMAND_DETAIL_CHARS = 300
REGISTRY_DETAIL_CHARS = 200
HOST_NODE_PREFIX = "host:"


class DetectionResult(FrozenModel):
    """Findings sorted by (host, first_us, rule_id, guid), plus counters for coverage."""

    findings: tuple[Finding, ...]
    unattached_findings: int
    events_examined: dict[str, int]


def finding_id(rule_id: str, host: str, guid: str) -> str:
    """Stable across runs: first 12 hex characters of SHA-256 over the 0x1F-joined key."""
    key = "\x1f".join((rule_id, host, guid)).encode("utf-8")
    return hashlib.sha256(key).hexdigest()[:12]


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def event_details(event: Event, decoded: str | None) -> dict[str, str]:
    """Rule-specific extras by event type (§8.8 item 4)."""
    f = event.fields
    details: dict[str, str] = {}
    if event.event_id == 1:
        if f.get("command_line"):
            details["command_line"] = _clip(f["command_line"], COMMAND_DETAIL_CHARS)
        if decoded:
            details["decoded"] = _clip(decoded, COMMAND_DETAIL_CHARS)
    elif event.event_id == 3:
        target = destination(f)
        if target:
            details["destination"] = target
        if f.get("destination_hostname"):
            details["destination_hostname"] = f["destination_hostname"]
    elif event.event_id == 10:
        for key in ("target_image", "granted_access"):
            if f.get(key):
                details[key] = f[key]
    elif event.event_id == 11:
        if f.get("target_filename"):
            details["target_filename"] = f["target_filename"]
    elif event.event_id == 13:
        if f.get("target_object"):
            details["target_object"] = f["target_object"]
        if f.get("details"):
            details["details"] = _clip(f["details"], REGISTRY_DETAIL_CHARS)
    return details


@dataclass
class _Aggregate:
    """Matches for one (rule, host, guid); keeps only the first and last evidence records."""

    image_name: str | None
    details: dict[str, str]
    first_us: int = 0
    last_us: int = 0
    count: int = 0
    head: list[SourceRef] = field(default_factory=list)
    tail: deque[SourceRef] = field(default_factory=lambda: deque(maxlen=EVIDENCE_TAIL))

    def add(self, ts_us: int, source: SourceRef) -> None:
        if self.count == 0:
            self.first_us = self.last_us = ts_us
        self.first_us = min(self.first_us, ts_us)
        self.last_us = max(self.last_us, ts_us)
        self.count += 1
        if len(self.head) < EVIDENCE_HEAD:
            self.head.append(source)
        else:
            self.tail.append(source)

    def finding(self, info: RuleInfo, host: str, guid: str) -> Finding:
        return Finding(
            finding_id=finding_id(info.id, host, guid),
            rule_id=info.id,
            title=info.title,
            severity=info.severity,
            attack=info.attack,
            tactics=info.tactics,
            why=info.why,
            host=host,
            guid=guid,
            image_name=self.image_name,
            first_us=self.first_us,
            last_us=self.last_us,
            count=self.count,
            evidence=(*self.head, *self.tail),
            evidence_truncated=self.count > EVIDENCE_HEAD + EVIDENCE_TAIL,
            details=self.details,
        )


def _events_by_id(rules: Sequence[Rule]) -> dict[int, list[Rule]]:
    by_id: defaultdict[int, list[Rule]] = defaultdict(list)
    for rule in rules:
        for event_id in rule.info.event_ids:
            by_id[event_id].append(rule)
    return by_id


def _event_findings(
    events: Iterable[Event],
    graphs: Mapping[str, ProcessGraph],
    rules: Sequence[Rule],
    examined: dict[str, int],
) -> dict[tuple[str, str, str], _Aggregate]:
    by_id = _events_by_id(rules)
    aggregates: dict[tuple[str, str, str], _Aggregate] = {}
    for event in events:
        candidates = by_id.get(event.event_id)
        if not candidates:
            continue
        graph = graphs.get(event.host)
        guid = event.process_guid
        node = graph.nodes.get(guid) if graph is not None and guid is not None else None
        view = EventFields(event, node)
        for rule in candidates:
            examined[rule.id] += 1
            if not rule_matches(rule, view):
                continue
            # Event 1 attaches to the created process, 8 and 10 to the source, others to the
            # actor: all are the event's process_guid. No valid GUID: the host pseudo node.
            target = guid if guid is not None else f"{HOST_NODE_PREFIX}{event.host}"
            key = (rule.id, event.host, target)
            aggregate = aggregates.get(key)
            if aggregate is None:
                name = node.image_name if node is not None else image_name(event.image)
                decoded = node.decoded_command if node is not None and event.event_id == 1 else None
                aggregate = _Aggregate(name, event_details(event, decoded))
                aggregates[key] = aggregate
            aggregate.add(event.ts_us, event.source)
    return aggregates


def _graph_findings(
    events: Sequence[Event],
    graphs: Mapping[str, ProcessGraph],
    graph_rules: Sequence[GraphRule],
    is_anchor: AnchorTest,
    examined: dict[str, int],
) -> dict[tuple[str, str, str], _Aggregate]:
    by_host: defaultdict[str, list[Event]] = defaultdict(list)
    for event in events:
        by_host[event.host].append(event)
    aggregates: dict[tuple[str, str, str], _Aggregate] = {}
    for rule in graph_rules:
        needed = set(rule.info.event_ids)
        examined[rule.info.id] = sum(1 for e in events if e.event_id in needed)
        for host in sorted(graphs):
            graph = graphs[host]
            for hit in rule.evaluate(graph, by_host.get(host, []), is_anchor):
                key = (rule.info.id, host, hit.guid)
                aggregate = aggregates.get(key)
                if aggregate is None:
                    node = graph.nodes.get(hit.guid)
                    aggregate = _Aggregate(node.image_name if node else None, hit.details)
                    aggregates[key] = aggregate
                for ts_us, source in hit.matches:
                    aggregate.add(ts_us, source)
    return aggregates


def run_detection(
    ingest: IngestResult,
    graphs: Mapping[str, ProcessGraph],
    rules: Sequence[Rule],
    *,
    is_anchor: AnchorTest,
    graph_rules: Sequence[GraphRule] = GRAPH_RULES,
) -> DetectionResult:
    """Evaluate enabled event rules over the sorted event list and the graph heuristics.

    Events come from ``ingest.events`` (never from graph activities), so records with no
    acting process are evaluated too. Image loads are never evaluated (amendment 12). Rules
    run in ascending ID order. ``is_anchor`` has no default: GR-001 must stop at anchors.
    """
    ordered_rules = sorted((r for r in rules if r.enabled), key=lambda r: r.id)
    ordered_graph_rules = sorted(graph_rules, key=lambda r: r.info.id)
    examined = {r.id: 0 for r in ordered_rules}
    info = {r.id: r.info for r in ordered_rules} | {r.info.id: r.info for r in ordered_graph_rules}

    aggregates = _event_findings(ingest.events, graphs, ordered_rules, examined)
    aggregates |= _graph_findings(ingest.events, graphs, ordered_graph_rules, is_anchor, examined)

    findings = sorted(
        (
            agg.finding(info[rule_id], host, guid)
            for (rule_id, host, guid), agg in aggregates.items()
        ),
        key=lambda f: (f.host, f.first_us, f.rule_id, f.guid),
    )
    unattached = sum(1 for f in findings if f.guid.startswith(HOST_NODE_PREFIX))
    return DetectionResult(
        findings=tuple(findings),
        unattached_findings=unattached,
        events_examined=dict(sorted(examined.items())),
    )
