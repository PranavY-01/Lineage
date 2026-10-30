"""Scope summary of one storyline (§5.7, §9.6)."""

from collections.abc import Iterable, Sequence

from lineage_ir.analyze.steps import is_executable, source_key
from lineage_ir.detect.fields import destination
from lineage_ir.graph.model import ProcessGraph
from lineage_ir.models import Activity, Finding, ProcessNode, Scope

LIST_CAP = 50
PERSISTENCE_FAMILY = "PER"


def _distinct(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result = []
    for value in values:
        key = value.casefold()
        if key not in seen:
            seen.add(key)
            result.append(value)
    return result


def _actor_activity(nodes: Sequence[ProcessNode]) -> list[Activity]:
    activity = [a for n in nodes for a in n.activity if a.role == "actor"]
    activity.sort(key=lambda a: (a.ts_us, a.source.record_id or 0, a.source.file, a.source.index))
    return activity


def _persistence_target(finding: Finding) -> str:
    d = finding.details
    return d.get("target_object") or d.get("target_filename") or d.get("command_line") or "?"


def build_scope(
    graph: ProcessGraph | None, nodes: Sequence[str], findings: Sequence[Finding]
) -> Scope:
    """Users, processes, files, registry, persistence, destinations and DNS names."""
    real = [graph.nodes[g] for g in nodes if graph is not None and g in graph.nodes]
    activity = _actor_activity(real)
    persistence = [f for f in findings if f.rule_id.split("-", 1)[0] == PERSISTENCE_FAMILY]
    persistence_records = {source_key(s) for f in persistence for s in f.evidence}

    files = _distinct(
        a.fields["target_filename"]
        for a in activity
        if a.kind == "file_create" and a.fields.get("target_filename")
    )
    executables = [f for f in files if is_executable(f)]
    ordered_files = executables + [f for f in files if not is_executable(f)]

    registry = [
        a
        for a in activity
        if a.kind == "registry" and a.event_id in (12, 13) and a.fields.get("target_object")
    ]
    first_persistent = [a for a in registry if source_key(a.source) in persistence_records]
    keys = _distinct(a.fields["target_object"] for a in (*first_persistent, *registry))

    network = [a for a in activity if a.kind == "network"]
    destinations = _distinct(d for a in network if (d := destination(a.fields)))
    names = _distinct(
        name
        for a in activity
        if a.kind in ("dns", "network")
        and (name := a.fields.get("query_name" if a.kind == "dns" else "destination_hostname"))
    )
    lines = [f"{f.title} → {_persistence_target(f)}" for f in persistence]
    users = _distinct(n.user for n in real if n.user)
    return Scope(
        users=tuple(users),
        process_count=len(real),
        ghost_count=sum(1 for n in real if n.is_ghost),
        files_created=tuple(ordered_files[:LIST_CAP]),
        executable_files=len(executables),
        registry_set=tuple(keys[:LIST_CAP]),
        persistence=tuple(lines),
        destinations=tuple(destinations[:LIST_CAP]),
        dns_names=tuple(names[:LIST_CAP]),
        decoded_payloads=sum(1 for n in real if n.decoded_command),
        review={
            "processes": len(real),
            "files": len(files),
            "registry_keys": len(keys),
            "persistence": len(lines),
            "destinations": len(destinations),
        },
        # Filled in by analyze.persistence_links once storylines are numbered.
        unlinked_targets=(),
    )
