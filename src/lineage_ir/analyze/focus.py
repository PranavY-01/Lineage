"""Focus resolution and the focus set (§9.7)."""

from collections.abc import Mapping, Sequence

from lineage_ir.errors import UsageError
from lineage_ir.graph.model import ProcessGraph
from lineage_ir.graph.traverse import ancestors, descendants
from lineage_ir.ingest.normalize import canonical_guid
from lineage_ir.ingest.timeparse import format_rfc3339

IMAGE_FOCUS_CAP = 20

Target = tuple[str, str]  # (host, guid)


def _describe(graphs: Mapping[str, ProcessGraph], targets: Sequence[Target]) -> str:
    lines = []
    for host, guid in targets:
        node = graphs[host].nodes[guid]
        start = format_rfc3339(node.start_us) if node.start_us is not None else "unknown start"
        lines.append(f"{host} {guid} {node.image_name or '?'} {start}")
    return "; ".join(lines)


def resolve_focus(
    graphs: Mapping[str, ProcessGraph], spec: str, option: str = "--focus"
) -> tuple[Target, ...]:
    """Nodes named by ``--focus``: a GUID (braces optional), ``pid:N`` or ``image:NAME``."""
    text = spec.strip()
    every = [(host, guid) for host in sorted(graphs) for guid in graphs[host].nodes]
    if text.lower().startswith("pid:"):
        value = text[4:].strip()
        if not value.isdigit():
            raise UsageError(f"{option} {spec!r}: pid must be a decimal number")
        pid = int(value)
        found = [t for t in every if graphs[t[0]].nodes[t[1]].pid == pid]
        if len(found) > 1:
            raise UsageError(
                f"{option} {spec!r} matches {len(found)} processes; pick one by GUID: "
                + _describe(graphs, found)
            )
    elif text.lower().startswith("image:"):
        name = text[6:].strip().lower()
        found = [t for t in every if graphs[t[0]].nodes[t[1]].image_name == name]
        if len(found) > IMAGE_FOCUS_CAP:
            raise UsageError(
                f"{option} {spec!r} matches {len(found)} processes (at most {IMAGE_FOCUS_CAP})"
            )
    else:
        guid, malformed = canonical_guid(text)
        if guid is None or malformed:
            raise UsageError(f"{option} {spec!r} is not a GUID, pid:N or image:NAME")
        found = [t for t in every if t[1] == guid]
    if not found:
        raise UsageError(f"{option} {spec!r}: process not found")
    return tuple(found)


def focus_set(
    graphs: Mapping[str, ProcessGraph], targets: Sequence[Target]
) -> dict[str, frozenset[str]]:
    """The focused nodes plus all their ancestors and descendants, per host."""
    members: dict[str, set[str]] = {}
    for host, guid in targets:
        graph = graphs[host]
        members.setdefault(host, set()).update(
            (guid, *ancestors(graph, guid), *descendants(graph, guid))
        )
    return {host: frozenset(nodes) for host, nodes in sorted(members.items())}


def resolve_one(graphs: Mapping[str, ProcessGraph], spec: str, option: str) -> Target:
    """Exactly one node for ``inspect``; several matches list the candidates (exit 2)."""
    found = resolve_focus(graphs, spec, option)
    if len(found) > 1:
        raise UsageError(
            f"{option} {spec!r} matches {len(found)} processes; pick one by GUID: "
            + _describe(graphs, found)
        )
    return found[0]
