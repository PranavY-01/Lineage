"""Persistence and drop links between storylines (§9.8, stretch S1).

A storyline that set something up (a Run key, a scheduled task, a service, a Startup file) is
linked to the storyline of a later process that ran the target. GR-003 findings link the
storyline of the process that wrote a file to the storyline of the process that ran it.
Targets that link nowhere are kept in the setting storyline's scope (amendment 21).
"""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from lineage_ir.analyze.decode import command_tokens
from lineage_ir.analyze.steps import SourceKey, source_key
from lineage_ir.detect.schema import fold
from lineage_ir.graph.model import ProcessGraph
from lineage_ir.models import (
    Event,
    Finding,
    ProcessNode,
    SourceRef,
    Storyline,
    StorylineLink,
    UnlinkedTarget,
)

Match = Literal["exact", "suffix"]

HOST_PROGRAMS = frozenset(
    {
        "rundll32.exe",
        "powershell.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "regsvr32.exe",
    }
)
# An extension ends at the end of the value, whitespace, a quote or a comma, so ".js" inside
# ".json" is not one.
_EXTENSION = re.compile(r"\.(?:exe|dll|bat|cmd|ps1|vbs|js|hta)(?=$|[\s\"',])", re.IGNORECASE)
_VARIABLE = re.compile(r"%([A-Za-z_][A-Za-z0-9_()]*)%")
_ABSOLUTE = re.compile(r"[a-z]:\\|\\\\")
EXPANDED = {
    "systemroot": "c:\\windows",
    "windir": "c:\\windows",
    "programdata": "c:\\programdata",
    "public": "c:\\users\\public",
}
# Per-user locations: only the part after the variable is known, so it is matched as a suffix.
SUFFIX_VARIABLES = frozenset({"appdata", "localappdata", "temp", "userprofile"})
UNLINKED_CAP = 50


@dataclass(frozen=True, slots=True)
class LinkTarget:
    """A normalized path to look for in later process images."""

    path: str
    match: Match


def _normal(path: str) -> str:
    return fold("image", path.strip())


def _resolve(path: str) -> LinkTarget | None:
    path = path.strip()
    variable = _VARIABLE.match(path)
    if variable is not None:
        name, rest = variable[1].casefold(), path[variable.end() :]
        if name in SUFFIX_VARIABLES:
            # Kept as written: "%TEMP%\x.exe" gives "\x.exe", "%TEMP%x.exe" gives "x.exe".
            suffix = _normal(rest)
            return LinkTarget(suffix, "suffix") if suffix.strip("\\") else None
        if name not in EXPANDED:
            return None
        path = EXPANDED[name] + rest
    normal = _normal(path)
    if not _ABSOLUTE.match(normal):
        return None
    return LinkTarget(normal, "exact")


def _leading_path(value: str) -> tuple[str, str] | None:
    """The quoted part, or the text up to and including the first extension, and the rest."""
    text = value.strip()
    if not text:
        return None
    if text[0] in "\"'":
        end = text.find(text[0], 1)
        end = len(text) if end < 0 else end
        return text[1:end], text[end + 1 :]
    found = _EXTENSION.search(text)
    if found is None:
        return None
    return text[: found.end()], text[found.end() :]


def _is_switch(token: str) -> bool:
    return token[:1] in ("-", "/") and "\\" not in token


def _looks_like_path(token: str) -> bool:
    return "\\" in token or token.startswith("%") or bool(re.match(r"[A-Za-z]:", token))


def extract_target(value: str) -> LinkTarget | None:
    """The executable a persistence value runs (§9.8 "Path extraction"), or None."""
    found = _leading_path(value)
    if found is None:
        return None
    path, rest = found
    program = _normal(path).rsplit("\\", 1)[-1]
    if program not in HOST_PROGRAMS:
        return _resolve(path)
    for token, _quoted in command_tokens(rest):
        if program == "rundll32.exe":
            token = token.split(",", 1)[0]
        if not token or _is_switch(token) or not _looks_like_path(token):
            continue
        inner = _leading_path(token)
        return _resolve(inner[0] if inner is not None else token)
    return None


def schtasks_target(command_line: str) -> LinkTarget | None:
    """The target of a schtasks ``/tr`` (or ``-tr``) argument."""
    tokens = list(command_tokens(command_line))
    for n, (token, quoted) in enumerate(tokens[:-1]):
        if not quoted and token.casefold() in ("/tr", "-tr"):
            return extract_target(tokens[n + 1][0])
    return None


def sc_binpath_target(command_line: str) -> LinkTarget | None:
    """The target of an sc.exe ``binPath=`` argument, with or without a space after ``=``."""
    tokens = list(command_tokens(command_line))
    for n, (token, quoted) in enumerate(tokens):
        if quoted or not token.casefold().startswith("binpath="):
            continue
        attached = token[len("binpath=") :]
        if attached:
            return extract_target(attached)
        if n + 1 < len(tokens):
            return extract_target(tokens[n + 1][0])
    return None


def _target_of(rule_id: str, event: Event) -> LinkTarget | None:
    fields = event.fields
    if rule_id == "PER-001" and event.event_id == 13:
        return extract_target(fields.get("details", ""))
    if rule_id == "PER-002" and event.event_id == 1:
        return schtasks_target(fields.get("command_line", ""))
    if rule_id == "PER-003" and event.event_id == 1:
        return sc_binpath_target(fields.get("command_line", ""))
    if rule_id == "PER-003" and event.event_id == 13:
        return extract_target(fields.get("details", ""))
    if rule_id == "PER-004" and event.event_id == 11:
        # A written file is already a path; it is not a command line.
        return _resolve(fields.get("target_filename", ""))
    return None


def _matches(node: ProcessNode, target: LinkTarget) -> bool:
    if node.image is None:
        return False
    image = _normal(node.image)
    return image == target.path if target.match == "exact" else image.endswith(target.path)


def _owners(guid: str, host: str, storylines: Sequence[Storyline]) -> list[Storyline]:
    """Storylines that hold a process: the one it roots if any, else every one containing it."""
    holding = [s for s in storylines if s.host == host and guid in s.nodes]
    rooted = [s for s in holding if s.root_guid == guid]
    return rooted or holding


@dataclass
class _Pending:
    links: list[StorylineLink]
    unlinked: list[UnlinkedTarget]


def _persistence(
    finding: Finding,
    setters: Sequence[Storyline],
    graph: ProcessGraph,
    storylines: Sequence[Storyline],
    events: Mapping[SourceKey, Event],
    pending: Mapping[str, _Pending],
) -> None:
    seen: set[LinkTarget] = set()
    later = sorted(
        (
            n
            for n in graph.nodes.values()
            if n.start_us is not None and n.start_us > finding.first_us and n.create_record
        ),
        key=lambda n: (n.start_us or 0, n.guid),
    )
    for ref in finding.evidence:
        event = events.get(source_key(ref))
        target = _target_of(finding.rule_id, event) if event is not None else None
        if target is None or target in seen:
            continue
        seen.add(target)
        ran = [n for n in later if _matches(n, target)]
        for setter in setters:
            out = pending[setter.storyline_id]
            if not ran:
                out.unlinked.append(_unlinked("not_seen_running", finding, target, ref, None))
            for node in ran:
                owners = _owners(node.guid, graph.host, storylines)
                if not owners:
                    out.unlinked.append(
                        _unlinked("target_not_in_storyline", finding, target, ref, node)
                    )
                created = node.create_record
                for owner in owners:
                    if owner.storyline_id == setter.storyline_id or created is None:
                        continue  # persistence never links a storyline to itself
                    out.links.append(
                        StorylineLink(
                            from_storyline=setter.storyline_id,
                            to_storyline=owner.storyline_id,
                            kind="persistence",
                            match=target.match,
                            path=target.path,
                            evidence=(ref, created),
                        )
                    )


def _unlinked(
    reason: Literal["target_not_in_storyline", "not_seen_running"],
    finding: Finding,
    target: LinkTarget,
    source: SourceRef,
    node: ProcessNode | None,
) -> UnlinkedTarget:
    return UnlinkedTarget(
        reason=reason,
        rule_id=finding.rule_id,
        path=target.path,
        match=target.match,
        guid=node.guid if node is not None else None,
        start_us=node.start_us if node is not None else None,
        source=source,
    )


def _dropped(
    finding: Finding,
    graph: ProcessGraph,
    storylines: Sequence[Storyline],
    write_refs: Mapping[SourceKey, SourceRef],
    pending: Mapping[str, _Pending],
) -> None:
    creator = finding.details.get("creator_guid")
    executed = graph.nodes.get(finding.guid)
    write = write_refs.get(
        (finding.details.get("write_file", ""), int(finding.details.get("write_index", "-1")))
    )
    if creator is None or executed is None or executed.create_record is None or write is None:
        return
    path = _normal(finding.details.get("target_filename", ""))
    for setter in _owners(creator, graph.host, storylines):
        for owner in _owners(executed.guid, graph.host, storylines):
            # A drop link may stay inside one storyline (§9.8 "Matching").
            pending[setter.storyline_id].links.append(
                StorylineLink(
                    from_storyline=setter.storyline_id,
                    to_storyline=owner.storyline_id,
                    kind="dropped_executed",
                    match="exact",
                    path=path,
                    evidence=(write, executed.create_record),
                )
            )


def _link_key(link: StorylineLink) -> tuple[int, int, str, str, str]:
    return (
        int(link.from_storyline[1:]),
        int(link.to_storyline[1:]),
        link.kind,
        link.path,
        link.match,
    )


def attach_links(
    storylines: Sequence[Storyline],
    graphs: Mapping[str, ProcessGraph],
    findings: Sequence[Finding],
    events: Sequence[Event],
) -> tuple[Storyline, ...]:
    """Storylines with ``links`` and ``scope.unlinked_targets`` filled in (§9.8)."""
    pending = {s.storyline_id: _Pending([], []) for s in storylines}
    wanted = {source_key(e) for f in findings for e in f.evidence}
    wanted |= {
        (f.details["write_file"], int(f.details["write_index"]))
        for f in findings
        if f.rule_id == "GR-003" and "write_file" in f.details
    }
    by_source = {source_key(e.source): e for e in events if source_key(e.source) in wanted}
    write_refs = {key: event.source for key, event in by_source.items()}
    for finding in findings:
        graph = graphs.get(finding.host)
        if graph is None:
            continue
        if finding.rule_id == "GR-003":
            _dropped(finding, graph, storylines, write_refs, pending)
        elif finding.rule_id.startswith("PER-"):
            setters = [s for s in storylines if finding.finding_id in s.finding_ids]
            _persistence(finding, setters, graph, storylines, by_source, pending)
    result = []
    for story in storylines:
        out = pending[story.storyline_id]
        links = sorted(set(out.links), key=_link_key)
        unlinked = tuple(dict.fromkeys(out.unlinked))[:UNLINKED_CAP]
        scope = story.scope.model_copy(update={"unlinked_targets": unlinked})
        result.append(story.model_copy(update={"links": tuple(links), "scope": scope}))
    return tuple(result)
