"""Three-pass process graph build (§7.1): creations, ghosts, then edges and activity."""

from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from itertools import groupby
from typing import Literal

from lineage_ir.graph.model import BrokenEdge, GraphCounters, ProcessGraph
from lineage_ir.ingest.normalize import (
    WMI_EVENT_IDS,
    activity_kind,
    activity_summary,
    canonical_guid,
    image_name,
    parse_hashes,
    parse_pid,
)
from lineage_ir.models import Activity, Event, GhostReason, ProcessNode, SourceRef

# Returns (decoded_command, decode_note) for a command line and image name.
Decoder = Callable[[str | None, str | None], tuple[str | None, str | None]]

_ACCESS_EVENT_IDS = frozenset({8, 10})


def _no_decode(_command_line: str | None, _image_name: str | None) -> tuple[None, None]:
    return None, None


@dataclass
class _Draft:
    """Mutable node state; frozen into a ProcessNode at the end of the build."""

    guid: str
    pid: int | None = None
    image: str | None = None
    command_line: str | None = None
    user: str | None = None
    integrity_level: str | None = None
    hashes: str | None = None
    current_directory: str | None = None
    logon_id: str | None = None
    start_us: int | None = None
    end_us: int | None = None
    parent_guid: str | None = None
    ghost_reason: GhostReason | None = None
    create_record: SourceRef | None = None
    create_fields: dict[str, str] | None = None
    activity: list[Activity] = field(default_factory=list)
    children: list[str] = field(default_factory=list)


def _guid(event: Event, key: str) -> str | None:
    return canonical_guid(event.fields.get(key))[0]


def _creation_draft(event: Event, guid: str) -> _Draft:
    f = event.fields
    return _Draft(
        guid=guid,
        pid=event.pid,
        image=event.image,
        command_line=f.get("command_line"),
        user=f.get("user"),
        integrity_level=f.get("integrity_level"),
        hashes=f.get("hashes"),
        current_directory=f.get("current_directory"),
        logon_id=f.get("logon_id"),
        start_us=event.ts_us,
        parent_guid=_guid(event, "parent_process_guid"),
        create_record=event.source,
        create_fields=f,
    )


def _ghost(
    guid: str, reason: GhostReason, image: str | None, pid: str | None, **extra: str | None
) -> _Draft:
    return _Draft(guid=guid, ghost_reason=reason, image=image, pid=parse_pid(pid), **extra)


def _references(event: Event) -> Iterable[tuple[str, _Draft]]:
    """GUIDs an event refers to, each with the ghost it would seed (§7.1 pass 2)."""
    f = event.fields
    if event.event_id == 1:
        parent = _guid(event, "parent_process_guid")
        if parent:
            yield (
                parent,
                _ghost(
                    parent,
                    "parent_reference",
                    f.get("parent_image"),
                    f.get("parent_pid"),
                    command_line=f.get("parent_command_line"),
                    user=f.get("parent_user"),
                ),
            )
    elif event.event_id in _ACCESS_EVENT_IDS:
        for side in ("source", "target"):
            guid = _guid(event, f"{side}_process_guid")
            if guid:
                yield (
                    guid,
                    _ghost(guid, "access_reference", f.get(f"{side}_image"), f.get(f"{side}_pid")),
                )
    elif event.event_id not in WMI_EVENT_IDS and event.process_guid:
        yield (
            event.process_guid,
            _ghost(
                event.process_guid,
                "activity_reference",
                event.image,
                event.fields.get("pid"),
                user=f.get("user"),
            ),
        )


def _activity(event: Event, role: Literal["actor", "target"]) -> Activity:
    # Built from an already validated Event; sharing its fields avoids a copy per record.
    return Activity.model_construct(
        kind=activity_kind(event.event_id),
        event_id=event.event_id,
        ts_us=event.ts_us,
        role=role,
        summary=activity_summary(event, role),
        fields=event.fields,
        source=event.source,
    )


def _break_cycles(drafts: dict[str, _Draft]) -> list[BrokenEdge]:
    """Remove one parent edge per parent loop, walking nodes in GUID order (§7.3)."""
    broken: list[BrokenEdge] = []
    done: set[str] = set()
    for start in sorted(drafts):
        path: list[str] = []
        on_path: set[str] = set()
        current: str | None = start
        while current is not None and current not in done:
            if current in on_path:
                child = path[-1]
                broken.append(BrokenEdge(child=child, parent=current))
                drafts[child].parent_guid = None
                break
            on_path.add(current)
            path.append(current)
            current = drafts[current].parent_guid
        done.update(path)
    return broken


def _child_key(draft: _Draft) -> tuple[bool, int, str]:
    return (draft.start_us is None, draft.start_us or 0, draft.guid)


def build_host_graph(
    host: str, events: Sequence[Event], decode: Decoder = _no_decode
) -> ProcessGraph:
    """Build one host's graph from its events in global sort order."""
    drafts: dict[str, _Draft] = {}
    unattached: list[Event] = []
    wmi: list[Event] = []
    conflicts = duplicates = 0

    # Pass 1: creations. Events arrive sorted, so the first creation is the earliest.
    for event in events:
        if event.event_id != 1:
            continue
        guid = event.process_guid
        if guid is None:
            unattached.append(event)
            continue
        existing = drafts.get(guid)
        if existing is None:
            drafts[guid] = _creation_draft(event, guid)
        elif existing.create_fields == event.fields:
            duplicates += 1
        else:
            conflicts += 1

    # Pass 2: one ghost per referenced but uncreated GUID, seeded by its first reference.
    ghosts: Counter[str] = Counter()
    for event in events:
        if event.event_id == 1:
            creator = drafts.get(event.process_guid or "")
            if creator is None or creator.create_record is not event.source:
                continue  # only nodes contribute parent references
        for guid, ghost in _references(event):
            if guid not in drafts:
                drafts[guid] = ghost
                ghosts[ghost.ghost_reason or ""] += 1

    # Pass 3: activity (in time order) and end times.
    for event in events:
        if event.event_id == 1:
            continue
        if event.event_id in WMI_EVENT_IDS:
            wmi.append(event)
            continue
        if event.event_id in _ACCESS_EVENT_IDS:
            source = _guid(event, "source_process_guid")
            target = _guid(event, "target_process_guid")
            if source is None and target is None:
                unattached.append(event)
            if source is not None:
                drafts[source].activity.append(_activity(event, "actor"))
            if target is not None:
                drafts[target].activity.append(_activity(event, "target"))
            continue
        guid = event.process_guid
        if guid is None:
            unattached.append(event)
            continue
        node = drafts[guid]
        node.activity.append(_activity(event, "actor"))
        if event.event_id == 5 and node.end_us is None:
            node.end_us = event.ts_us

    broken = _break_cycles(drafts)

    # Edges, after loops are broken.
    for draft in drafts.values():
        if draft.parent_guid is not None:
            drafts[draft.parent_guid].children.append(draft.guid)

    nodes: dict[str, ProcessNode] = {}
    for guid in sorted(drafts):
        draft = drafts[guid]
        name = image_name(draft.image)
        decoded, note = decode(draft.command_line, name)
        children = sorted(draft.children, key=lambda g: _child_key(drafts[g]))
        nodes[guid] = ProcessNode(
            host=host,
            guid=guid,
            pid=draft.pid,
            image=draft.image or None,
            image_name=name,
            command_line=draft.command_line,
            decoded_command=decoded,
            decode_note=note,
            user=draft.user,
            integrity_level=draft.integrity_level,
            hashes=parse_hashes(draft.hashes),
            current_directory=draft.current_directory,
            logon_id=draft.logon_id,
            start_us=draft.start_us,
            end_us=draft.end_us,
            parent_guid=draft.parent_guid,
            children=tuple(children),
            is_ghost=draft.create_record is None,
            ghost_reason=draft.ghost_reason,
            create_record=draft.create_record,
            activity=tuple(draft.activity),
        )

    roots = sorted(
        (d for d in drafts.values() if d.parent_guid is None),
        key=_child_key,
    )
    return ProcessGraph(
        host=host,
        nodes=nodes,
        roots=tuple(d.guid for d in roots),
        wmi_events=tuple(wmi),
        unattached_events=tuple(unattached),
        broken_edges=tuple(broken),
        counters=GraphCounters(
            ghosts=dict(sorted(ghosts.items())),
            creation_conflicts=conflicts,
            duplicate_creations=duplicates,
            cycles_broken=len(broken),
            unattached_events=len(unattached),
        ),
    )


def build_graphs(events: Sequence[Event], decode: Decoder = _no_decode) -> dict[str, ProcessGraph]:
    """One independent graph per host; events must be in the global sort order (§6.8)."""
    return {
        host: build_host_graph(host, list(group), decode)
        for host, group in groupby(events, key=lambda e: e.host)
    }
