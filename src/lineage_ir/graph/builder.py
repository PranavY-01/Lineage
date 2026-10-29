"""Three-pass process graph build (§7.1): creations, ghosts, then edges and activity."""

from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from typing import Literal

from lineage_ir.graph.model import BrokenEdge, GraphCounters, ProcessGraph
from lineage_ir.ingest.normalize import (
    WMI_EVENT_IDS,
    DigestCache,
    activity_kind,
    activity_summary,
    canonical_guid,
    image_load_record,
    image_name,
    parse_hashes,
    parse_pid,
)
from lineage_ir.models import (
    IMAGE_LOAD_EVENT_ID,
    IMAGE_LOADS_KEPT,
    Activity,
    Event,
    GhostReason,
    ImageLoad,
    ImageLoadRecord,
    ProcessNode,
    SourceRef,
)

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
    create_event: Event | None = None
    activity: list[Activity] = field(default_factory=list)
    image_load_count: int = 0
    image_loads: list[ImageLoad] = field(default_factory=list)
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
        create_event=event,
    )


def _ghost(
    guid: str, reason: GhostReason, image: str | None, pid: int | None, **extra: str | None
) -> _Draft:
    return _Draft(guid=guid, ghost_reason=reason, image=image, pid=pid, **extra)


def _references(item: Event | ImageLoadRecord) -> Iterable[tuple[str, _Draft]]:
    """GUIDs a record refers to, each with the ghost it would seed (§7.1 pass 2)."""
    if isinstance(item, ImageLoadRecord):
        if item.process_guid:
            yield (
                item.process_guid,
                _ghost(
                    item.process_guid, "activity_reference", item.image, item.pid, user=item.user
                ),
            )
        return
    f = item.fields
    if item.event_id == 1:
        parent = _guid(item, "parent_process_guid")
        if parent:
            yield (
                parent,
                _ghost(
                    parent,
                    "parent_reference",
                    f.get("parent_image"),
                    parse_pid(f.get("parent_pid")),
                    command_line=f.get("parent_command_line"),
                    user=f.get("parent_user"),
                ),
            )
    elif item.event_id in _ACCESS_EVENT_IDS:
        for side in ("source", "target"):
            guid = _guid(item, f"{side}_process_guid")
            if guid:
                pid = parse_pid(f.get(f"{side}_pid"))
                yield guid, _ghost(guid, "access_reference", f.get(f"{side}_image"), pid)
    elif item.event_id not in WMI_EVENT_IDS and item.process_guid:
        yield (
            item.process_guid,
            _ghost(
                item.process_guid,
                "activity_reference",
                item.image,
                parse_pid(f.get("pid")),
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


def _in_order(
    events: Sequence[Event], loads: Sequence[ImageLoadRecord], digest: DigestCache
) -> Iterator[Event | ImageLoadRecord]:
    """Merge two globally ordered streams of one host into one global order (§6.8)."""
    i = j = 0
    while i < len(events) and j < len(loads):
        a, b = events[i], loads[j]
        key_a, key_b = (a.ts_us, a.record_id or 0), (b.ts_us, b.record_id or 0)
        if key_a < key_b or (key_a == key_b and digest(a) < digest(b)):
            yield a
            i += 1
        else:
            yield b
            j += 1
    yield from events[i:]
    yield from loads[j:]


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
    host: str,
    events: Sequence[Event],
    image_loads: Sequence[ImageLoadRecord] = (),
    decode: Decoder = _no_decode,
) -> ProcessGraph:
    """Build one host's graph from its events and image loads, each in global sort order.

    A full Event 7 among ``events`` is handled exactly like an ImageLoadRecord.
    """
    if any(e.event_id == IMAGE_LOAD_EVENT_ID for e in events):
        if image_loads:
            raise ValueError("pass image loads either as events or as image_loads, not both")
        image_loads = [image_load_record(e) for e in events if e.event_id == IMAGE_LOAD_EVENT_ID]
        events = [e for e in events if e.event_id != IMAGE_LOAD_EVENT_ID]

    digest = DigestCache()
    drafts: dict[str, _Draft] = {}
    unattached: list[Event] = []
    unattached_loads: list[ImageLoad] = []
    unattached_load_count = 0
    wmi: list[Event] = []
    conflicts = duplicates = 0

    # Pass 1: creations. A repeat with different fields is a conflict; the earliest by
    # ts_us, then the smallest content hash, is kept (§7.1 as amended).
    creators: dict[str, Event] = {}
    for event in events:
        if event.event_id != 1:
            continue
        guid = event.process_guid
        if guid is None:
            unattached.append(event)
            continue
        current = creators.get(guid)
        if current is None:
            creators[guid] = event
            drafts[guid] = _creation_draft(event, guid)
            continue
        if current.fields == event.fields:
            duplicates += 1
            continue
        conflicts += 1
        if (event.ts_us, digest(event)) < (current.ts_us, digest(current)):
            creators[guid] = event
            drafts[guid] = _creation_draft(event, guid)

    # Pass 2: one ghost per referenced but uncreated GUID, seeded by its first reference.
    ghosts: Counter[str] = Counter()
    for item in _in_order(events, image_loads, digest):
        if isinstance(item, Event) and item.event_id == 1:
            creator = drafts.get(item.process_guid or "")
            if creator is None or creator.create_event is not item:
                continue  # only nodes contribute parent references
        for guid, ghost in _references(item):
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

    # Image loads: exact counts, first IMAGE_LOADS_KEPT kept in global order.
    for load in image_loads:
        if load.process_guid is None:
            unattached_load_count += 1
            if len(unattached_loads) < IMAGE_LOADS_KEPT:
                unattached_loads.append(load.to_image_load())
            continue
        node = drafts[load.process_guid]
        node.image_load_count += 1
        if len(node.image_loads) < IMAGE_LOADS_KEPT:
            node.image_loads.append(load.to_image_load())

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
        record: SourceRef | None = draft.create_event.source if draft.create_event else None
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
            is_ghost=record is None,
            ghost_reason=draft.ghost_reason,
            create_record=record,
            activity=tuple(draft.activity),
            image_load_count=draft.image_load_count,
            image_loads=tuple(draft.image_loads),
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
        unattached_image_loads=tuple(unattached_loads),
        broken_edges=tuple(broken),
        counters=GraphCounters(
            ghosts=dict(sorted(ghosts.items())),
            creation_conflicts=conflicts,
            duplicate_creations=duplicates,
            cycles_broken=len(broken),
            unattached_events=len(unattached) + unattached_load_count,
        ),
    )


def build_graphs(
    events: Sequence[Event],
    image_loads: Sequence[ImageLoadRecord] = (),
    decode: Decoder = _no_decode,
) -> dict[str, ProcessGraph]:
    """One independent graph per host; inputs must be in the global sort order (§6.8)."""
    by_host_events: defaultdict[str, list[Event]] = defaultdict(list)
    by_host_loads: defaultdict[str, list[ImageLoadRecord]] = defaultdict(list)
    for event in events:
        by_host_events[event.host].append(event)
    for load in image_loads:
        by_host_loads[load.host].append(load)
    hosts = sorted(set(by_host_events) | set(by_host_loads))
    return {
        host: build_host_graph(host, by_host_events[host], by_host_loads[host], decode)
        for host in hosts
    }
