"""Story steps (§9.4): process creations, decoded payloads, finding evidence and the first
network, DNS and executable-file activity of flagged nodes, merged by record."""

from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field

from lineage_ir.analyze.filters import SEVERITY_RANK
from lineage_ir.detect.fields import destination
from lineage_ir.graph.model import ProcessGraph
from lineage_ir.ingest.normalize import image_name
from lineage_ir.models import Activity, Event, Finding, SourceRef, Step, StepAction

EXECUTABLE_EXTENSIONS = (
    ".exe",
    ".dll",
    ".ps1",
    ".vbs",
    ".js",
    ".jse",
    ".bat",
    ".cmd",
    ".hta",
    ".scr",
    ".msi",
    ".lnk",
)
SHORT_COMMAND_CHARS = 80
DECODED_STEP_CHARS = 160

# Within one record: the creation first, its decoded payload right after, then the rest.
_ACTION_ORDER: Mapping[str, int] = {"process_create": 0, "decoded": 1, "finding": 3}

SourceKey = tuple[str, int]


def source_key(source: SourceRef) -> SourceKey:
    return source.file, source.index


def clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def is_executable(path: str) -> bool:
    return path.casefold().endswith(EXECUTABLE_EXTENSIONS)


@dataclass
class _Draft:
    ts_us: int
    source: SourceRef
    action: StepAction
    guid: str
    image_name: str | None
    text: str
    hits: list[Finding] = field(default_factory=list)

    def sort_key(self) -> tuple[int, int, str, int, int]:
        s = self.source
        return (self.ts_us, s.record_id or 0, s.file, s.index, _ACTION_ORDER.get(self.action, 2))


def event_detail(event: Event) -> str:
    """The short subject of an event for a finding step."""
    f = event.fields
    by_type = {
        1: lambda: clip(f.get("command_line") or event.image or "", SHORT_COMMAND_CHARS),
        3: lambda: destination(f) or "",
        8: lambda: f.get("target_image") or "",
        10: lambda: f.get("target_image") or "",
        11: lambda: f.get("target_filename") or "",
        12: lambda: f.get("target_object") or "",
        13: lambda: f.get("target_object") or "",
        22: lambda: f.get("query_name") or "",
    }
    detail = by_type.get(event.event_id, lambda: "")()
    return detail or image_name(event.image) or f"event {event.event_id}"


def _creation_drafts(graph: ProcessGraph, nodes: Iterable[str]) -> list[_Draft]:
    drafts = []
    for guid in nodes:
        node = graph.nodes[guid]
        if node.create_record is None or node.start_us is None:
            continue  # ghosts have no step
        parent = graph.nodes.get(node.parent_guid or "")
        parent_name = (parent.image_name if parent else None) or "unknown parent"
        name = node.image_name or "?"
        command = clip(node.command_line or "", SHORT_COMMAND_CHARS)
        text = f"{parent_name} spawned {name} {command}".rstrip()
        drafts.append(_Draft(node.start_us, node.create_record, "process_create", guid, name, text))
        if node.decoded_command:
            decoded = clip(node.decoded_command, DECODED_STEP_CHARS)
            drafts.append(
                _Draft(
                    node.start_us,
                    node.create_record,
                    "decoded",
                    guid,
                    name,
                    f"{name} decoded: {decoded}",
                )
            )
    return drafts


def _activity_drafts(graph: ProcessGraph, flagged: Iterable[str]) -> list[_Draft]:
    candidates: list[tuple[Activity, str]] = [
        (a, guid)
        for guid in flagged
        for a in graph.nodes[guid].activity
        if a.role == "actor" and a.kind in ("network", "dns", "file_create")
    ]
    candidates.sort(
        key=lambda item: (item[0].ts_us, item[0].source.record_id or 0, item[0].source.index)
    )
    seen: set[tuple[str, str]] = set()
    drafts = []
    for activity, guid in candidates:
        name = graph.nodes[guid].image_name or "?"
        f = activity.fields
        if activity.kind == "network":
            target = destination(f)
            if target is None:
                continue
            key = ("network", target)
            host = f.get("destination_hostname")
            text = f"{name} → {target}" + (f" ({host})" if host else "")
        elif activity.kind == "dns":
            query = f.get("query_name")
            if not query:
                continue
            key = ("dns", query.casefold())
            text = f"{name} resolved {query}"
        else:
            path = f.get("target_filename")
            if not path or not is_executable(path):
                continue
            key = ("file_create", path.casefold())
            text = f"{name} wrote {path}"
        if key in seen:
            continue
        seen.add(key)
        drafts.append(_Draft(activity.ts_us, activity.source, activity.kind, guid, name, text))  # type: ignore[arg-type]
    return drafts


def _finding_drafts(
    graph: ProcessGraph | None,
    findings: Iterable[Finding],
    events: Mapping[SourceKey, Event],
) -> list[_Draft]:
    drafts = []
    for finding in findings:
        for source in finding.evidence:
            event = events.get(source_key(source))
            if event is None:
                continue
            guid = event.process_guid or finding.guid
            node = graph.nodes.get(guid) if graph is not None else None
            name = node.image_name if node is not None else image_name(event.image)
            text = f"{finding.title}: {event_detail(event)}"
            drafts.append(_Draft(event.ts_us, event.source, "finding", guid, name, text, [finding]))
    return drafts


def _best(hits: Sequence[Finding]) -> Finding:
    return min(hits, key=lambda f: (-SEVERITY_RANK[f.severity], f.rule_id))


def build_steps(
    graph: ProcessGraph | None,
    nodes: Sequence[str],
    flagged: Collection[str],
    findings: Iterable[Finding],
    events: Mapping[SourceKey, Event],
) -> tuple[Step, ...]:
    """Steps sorted by (time, record order); a step for an already-used record is merged into
    the earlier step, which then carries the finding's rule IDs, tactic and technique."""
    drafts: list[_Draft] = []
    if graph is not None:
        drafts += _creation_drafts(graph, (g for g in nodes if g in graph.nodes))
        drafts += _activity_drafts(graph, (g for g in nodes if g in flagged and g in graph.nodes))
    drafts += _finding_drafts(graph, findings, events)
    drafts.sort(key=_Draft.sort_key)

    merged: list[_Draft] = []
    by_record: dict[SourceKey, _Draft] = {}
    for draft in drafts:
        key = source_key(draft.source)
        earlier = by_record.get(key)
        if draft.action != "decoded" and earlier is not None:
            earlier.hits.extend(draft.hits)
            continue
        merged.append(draft)
        if draft.action != "decoded":
            by_record[key] = draft

    steps = []
    for n, draft in enumerate(merged, start=1):
        tactic = technique = severity = None
        text = draft.text
        if draft.hits:
            best = _best(draft.hits)
            tactic = best.tactics[0] if best.tactics else None
            technique = best.attack[0] if best.attack else None
            severity = best.severity
            rule_ids = sorted({f.rule_id for f in draft.hits})
            if draft.action != "finding" or len(rule_ids) > 1:
                text = f"{text} [{', '.join(rule_ids)}]"
        steps.append(
            Step(
                n=n,
                ts_us=draft.ts_us,
                tactic=tactic,
                technique=technique,
                guid=draft.guid,
                image_name=draft.image_name,
                action=draft.action,
                text=text,
                severity=severity,
                source=draft.source,
            )
        )
    return tuple(steps)
