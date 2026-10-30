"""Rich terminal views: overview, validate, rules, analyze, tree, story and inspect.

Views only format results. Every evidence-derived string goes through ``safe`` (control
characters, URL defanging, truncation, markup escaping) before it reaches Rich.
"""

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from lineage_ir import __version__
from lineage_ir.analyze.filters import (
    SEVERITY_RANK,
    AnalysisParams,
    visible_findings,
    visible_steps,
    visible_storylines,
)
from lineage_ir.config import (
    ACTIVITY_LINES_PER_KIND,
    COMMAND_LINE_WIDTH,
    DEFAULT_COLLAPSE_MIN,
    DEFAULT_MAX_DEPTH,
    INSPECT_ITEMS_PER_KIND,
    SYSMON_EVENT_NAMES,
    UNKNOWN_KEYS_SHOWN,
)
from lineage_ir.detect.engine import HOST_NODE_PREFIX
from lineage_ir.engine import AnalysisResult
from lineage_ir.graph.model import ProcessGraph
from lineage_ir.graph.traverse import (
    CollapsedGroup,
    ancestors,
    collapse_children,
    hot_only_children,
    hot_set,
)
from lineage_ir.ingest.timeparse import format_rfc3339
from lineage_ir.models import (
    Activity,
    Coverage,
    Finding,
    ProcessNode,
    RuleInfo,
    Scope,
    Storyline,
    StorylineLink,
    ValidateResult,
)
from lineage_ir.render.safe import defang_host, safe

TAGLINE = "Process lineage & attack storylines"

OVERVIEW_COMMANDS = (
    ("validate", "Check what telemetry an input holds", "lineage validate case.evtx"),
    ("analyze", "Full run: storylines, scope, coverage", "lineage analyze case.evtx --hot-only"),
    ("tree", "Process tree per host", "lineage tree case.evtx --focus pid:4242"),
    ("story", "A storyline as a numbered narrative", "lineage story case.evtx --storyline 1"),
    ("inspect", "Everything about one process", "lineage inspect case.evtx image:powershell.exe"),
    ("rules", "Bundled rules and the events they need", "lineage rules"),
)

_STATE_STYLE = {"ready": "green", "partial": "yellow", "missing": "red"}


def make_console(*, no_color: bool = False, stderr: bool = False) -> Console:
    """A console that never interprets emoji codes or auto-highlights evidence text."""
    return Console(stderr=stderr, no_color=no_color, emoji=False, highlight=False)


def print_error(console: Console, message: str) -> None:
    """Print an error line; the message is treated as untrusted text."""
    console.print(f"[bold red]error[/] {safe(message)}")


def print_warning(console: Console, message: str) -> None:
    """Print a warning line; the message is treated as untrusted text."""
    console.print(f"[yellow]warning[/] {safe(message)}")


def _banner(command: str | None) -> Text:
    title = Text()
    title.append(" LINEAGE ", style="bold reverse")
    title.append(f"  v{__version__}")
    if command:
        title.append(f" › {command}")
    title.append(f"      {TAGLINE}", style="dim")
    return title


def render_overview(console: Console) -> None:
    """The screen shown when `lineage` runs without a command."""
    console.print(_banner(None))
    console.print(
        "Offline reconstruction of Windows process lineage and attack storylines "
        "from Sysmon telemetry.\n"
    )
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    table.add_column("Command")
    table.add_column("Purpose")
    table.add_column("Example", style="cyan")
    for name, purpose, example in OVERVIEW_COMMANDS:
        table.add_row(name, purpose, example)
    console.print(table)
    console.print("Run [bold]lineage COMMAND --help[/] for options.")


def _size(size_bytes: int) -> str:
    value = float(size_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size_bytes} B"


def _duration(seconds: int) -> str:
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours}h{minutes:02d}m"
    if minutes:
        return f"{minutes}m{secs:02d}s"
    return f"{secs}s"


def _kv(label: str, value: str) -> str:
    return f" [bold]{label:<12}[/]{value}"


def render_validate(console: Console, result: ValidateResult, max_errors: int) -> None:
    """Human-readable view of `lineage validate`."""
    ingest = result.ingest
    counters = ingest.counters
    console.print(_banner("validate"))

    for item in ingest.inputs:
        console.print(
            _kv(
                "Input",
                f"{safe(item.label)} · {item.format} · {_size(item.size_bytes)}\n"
                f"             sha256 {item.sha256}",
            )
        )
    hosts = ", ".join(safe(h) for h in ingest.hosts) or "[dim]none[/]"
    console.print(_kv("Hosts", hosts))
    if ingest.span:
        seconds = (ingest.span.end_us - ingest.span.start_us) // 1_000_000
        console.print(
            _kv(
                "Span",
                f"{format_rfc3339(ingest.span.start_us)} → "
                f"{format_rfc3339(ingest.span.end_us)} ({_duration(seconds)})",
            )
        )
    else:
        console.print(_kv("Span", "[dim]no events[/]"))
    console.print(
        _kv(
            "Records",
            f"{counters.records_total} total · {counters.sysmon} Sysmon · "
            f"{counters.irrelevant} irrelevant · {counters.invalid} invalid · "
            f"{counters.duplicates_dropped} duplicates dropped · "
            f"{counters.duplicate_conflicts} conflicting duplicates",
        )
    )
    if counters.bad_guid or counters.out_of_order:
        console.print(
            _kv(
                "Notes",
                f"{counters.bad_guid} malformed GUIDs · "
                f"{counters.out_of_order} records out of time order",
            )
        )
    if counters.irrelevant_by_channel:
        parts = " · ".join(f"{safe(ch)} {n}" for ch, n in counters.irrelevant_by_channel.items())
        console.print(_kv("Irrelevant", parts))
    if counters.invalid_by_reason:
        parts = " · ".join(f"{r} {n}" for r, n in counters.invalid_by_reason.items())
        console.print(_kv("Invalid", f"[red]{parts}[/]"))

    histogram = Table(title="Event IDs", box=box.SIMPLE, title_justify="left")
    histogram.add_column("ID", justify="right")
    histogram.add_column("Name")
    histogram.add_column("Events", justify="right")
    for key, count in ingest.event_ids_seen.items():
        histogram.add_row(key, SYSMON_EVENT_NAMES.get(int(key), "other"), str(count))
    console.print(histogram)

    missing = ", ".join(str(i) for i in result.event_ids_missing) or "none"
    console.print(_kv("Missing", f"standard event IDs: {missing}"))

    ready = Table(title="Readiness by rule family", box=box.SIMPLE, title_justify="left")
    ready.add_column("Family")
    ready.add_column("Needs")
    ready.add_column("State")
    ready.add_column("Missing")
    for r in result.readiness:
        joiner = " or " if r.mode == "any" else ", "
        ready.add_row(
            r.family,
            joiner.join(str(i) for i in r.needs),
            f"[{_STATE_STYLE[r.state]}]{r.state}[/]",
            ", ".join(str(i) for i in r.missing) or "-",
        )
    console.print(ready)

    if ingest.unknown_keys:
        keys = list(ingest.unknown_keys)
        shown = ", ".join(safe(k) for k in keys[:UNKNOWN_KEYS_SHOWN])
        more = len(keys) - UNKNOWN_KEYS_SHOWN
        suffix = f" (+{more} more)" if more > 0 else ""
        console.print(_kv("Unknown", f"EventData keys: {shown}{suffix}"))

    samples = ingest.invalid_samples[:max_errors]
    if samples:
        console.print(" [bold]Invalid records[/] (file:index reason)")
        for sample in samples:
            console.print(f"   {safe(sample.file)}:{sample.index} {sample.reason}")
        hidden = counters.invalid - len(samples)
        if hidden > 0:
            console.print(f"   … {hidden} more")

    for warning in ingest.warnings:
        print_warning(console, warning)
    if ingest.record_cap_reached:
        # Reading stops exactly at the cap, so the records read are the cap.
        console.print(
            f"[red]Record cap of {counters.records_total:,} reached: reading stopped before "
            "the end of the input. Raise the cap with --max-records.[/]"
        )

    if result.valid:
        status = "[bold green]VALID[/]"
        summary = "every record usable · Sysmon events present"
    else:
        status = "[bold red]PROBLEMS[/]"
        summary = " · ".join(ingest.reasons) or "see above"
    console.print(
        Panel(
            Group(Text.from_markup(f"{status}   {summary}")),
            title="Result",
            title_align="left",
            subtitle=f"exit {result.exit_code}",
            subtitle_align="right",
            box=box.ROUNDED,
        )
    )


_SEVERITY_STYLE = {"high": "bold red", "medium": "yellow", "low": "cyan", "info": "dim"}


def render_rules(console: Console, rules: Sequence[RuleInfo]) -> None:
    """The `lineage rules` table: event rules and graph heuristics, sorted by ID."""
    console.print(_banner("rules"))
    table = Table(box=box.SIMPLE, header_style="bold")
    for column in ("ID", "Kind", "Title", "Severity", "Events", "ATT&CK", "Tactics"):
        table.add_column(column)
    for rule in sorted(rules, key=lambda r: r.id):
        style = _SEVERITY_STYLE[rule.severity]
        table.add_row(
            rule.id,
            rule.kind,
            safe(rule.title),
            f"[{style}]{rule.severity}[/]",
            ", ".join(str(i) for i in rule.event_ids),
            ", ".join(rule.attack) or "-",
            ", ".join(rule.tactics) or "-",
        )
    console.print(table)
    console.print(f"{len(rules)} rules")


# ---------------------------------------------------------------- analysis views


@dataclass(frozen=True)
class View:
    """Display options for the analysis views; none of them changes the analysis."""

    params: AnalysisParams = field(default_factory=AnalysisParams)
    focus: Mapping[str, frozenset[str]] | None = None
    wide: bool = False
    max_depth: int = DEFAULT_MAX_DEPTH
    collapse_min: int = DEFAULT_COLLAPSE_MIN
    storyline: int | None = None
    is_anchor: Callable[[ProcessNode], bool] = lambda _node: False

    @property
    def width(self) -> int | None:
        return None if self.wide else COMMAND_LINE_WIDTH


_STATUS_BADGE = {
    "no_findings": "[bold green]NO FINDINGS[/]",
    "findings_detected": "[bold yellow]FINDINGS DETECTED[/]",
    "incomplete": "[bold red]INCOMPLETE[/]",
}
PARTIAL_LINE = "Coverage is partial: no findings in what could be analyzed is NOT a clean result."
LOW_SIGNAL = frozenset({"low", "info"})
TREE_LEGEND = (
    "[dim]! flagged · ? ghost (no creation record) · (anchor) system anchor · "
    "×N collapsed siblings · dim: context on the path to a finding[/]"
)
_ACTIVITY_LABELS = (
    ("network", "net"),
    ("dns", "dns"),
    ("file_create", "file"),
    ("registry", "reg"),
    ("process_access", "access"),
    ("remote_thread", "thread"),
)


def _short_sha(sha256: str) -> str:
    return f"{sha256[:4]}…{sha256[-4:]}"


def _clock(ts_us: int) -> str:
    return format_rfc3339(ts_us)[11:]


def _span_text(start_us: int, end_us: int) -> str:
    seconds = (end_us - start_us) // 1_000_000
    start = format_rfc3339(start_us)
    end = format_rfc3339(end_us)
    if start[:10] == end[:10]:
        end = end[11:]
    return f"{start} → {end} ({_duration(seconds)})"


def _gap_text(seconds: int) -> str:
    hours, rest = divmod(seconds, 3600)
    minutes = rest // 60
    return f"{hours} h {minutes} min" if hours else f"{minutes} min"


def _severity_badge(severity: str) -> str:
    return f"[{_SEVERITY_STYLE[severity]}]{severity.upper()}[/]"


def _filters_text(params: AnalysisParams) -> str:
    parts = []
    since, until = params.window_us
    if since is not None:
        parts.append(f"since {format_rfc3339(since)}")
    if until is not None:
        parts.append(f"until {format_rfc3339(until)}")
    if params.focus is not None:
        parts.append(f"focus {safe(params.focus)}")
    if params.hot_only:
        parts.append("hot only")
    return " · ".join(parts)


def _header(console: Console, result: AnalysisResult, command: str) -> None:
    span = result.coverage.timeline.span
    hosts = ", ".join(safe(h) for h in result.hosts) or "[dim]none[/]"
    if console.width < 80:
        span_text = f" · {_span_text(span.start_us, span.end_us)}" if span else ""
        console.print(
            f"[bold reverse] LINEAGE [/] v{__version__} › {command} · "
            f"{len(result.inputs)} input(s) · {hosts}{span_text}"
        )
        return
    console.print(_banner(command))
    for item in result.inputs:
        console.print(
            _kv(
                "Input",
                f"{safe(item.label)} · sha256 {_short_sha(item.sha256)} · {_size(item.size_bytes)}",
            )
        )
    console.print(_kv("Hosts", hosts))
    console.print(_kv("Span", _span_text(span.start_us, span.end_us) if span else "[dim]none[/]"))
    params = result.parameters
    rules = safe(params.rules) if params.rules else "all"
    console.print(
        _kv(
            "Parameters",
            f"rules {rules} · min severity {params.min_severity} · gap {safe(params.gap)} · "
            f"telemetry gap {safe(params.telemetry_gap)}",
        )
    )
    filters = _filters_text(params)
    if filters:
        console.print(_kv("Showing", f"{filters} [dim](display only)[/]"))


def _reason_lines(coverage: Coverage) -> list[str]:
    lines = []
    for reason in coverage.reasons:
        state, _, rule_id = reason.partition(":")
        if state in ("not_evaluable", "partially_evaluable") and rule_id in coverage.rules:
            missing = ", ".join(str(i) for i in coverage.rules[rule_id].missing_event_ids)
            label = "not evaluable" if state == "not_evaluable" else "partially evaluable"
            lines.append(f"{rule_id} {label} (needs {missing})")
        elif reason == "invalid_records":
            lines.append(f"{coverage.counters.invalid} invalid records")
        elif reason == "duplicate_conflicts":
            lines.append(f"{coverage.counters.duplicate_conflicts} conflicting duplicates")
        elif reason == "cycles_broken":
            lines.append(f"{coverage.counters.cycles_broken} parent loops broken")
        elif reason == "record_cap_reached":
            lines.append(
                f"record cap of {coverage.counters.records_total:,} reached: reading stopped "
                "before the end of the input. Raise the cap with --max-records"
            )
        elif reason == "no_events":
            lines.append("no Sysmon events survived")
        else:
            lines.append(safe(reason))
    return lines


def _coverage_block(console: Console, coverage: Coverage) -> None:
    missing = ", ".join(str(i) for i in coverage.event_ids_missing)
    if coverage.complete:
        text = "[green]✓ COMPLETE[/]"
        if missing:
            text += f" · events {missing} absent (no enabled rule needs them)"
    else:
        text = "[red]✗ PARTIAL[/]"
        if missing:
            text += f" · events {missing} absent"
    console.print(_kv("Coverage", text))
    for line in _reason_lines(coverage):
        console.print(f"             {line}")


def _ranking_table(
    stories: Sequence[Storyline], graphs: Mapping[str, ProcessGraph], title: str = "Storylines"
) -> Table:
    table = Table(title=title, box=box.SIMPLE, title_justify="left", header_style="bold")
    for column in ("ID", "Root", "Host", "Max", "Tactics", "Findings", "Start"):
        table.add_column(column, justify="right" if column in ("Tactics", "Findings") else "left")
    for story in stories:
        table.add_row(
            story.storyline_id,
            _root_name(story, graphs),
            safe(story.host),
            _severity_badge(story.max_severity),
            str(len(story.tactics)),
            str(len(story.finding_ids)),
            format_rfc3339(story.start_us),
        )
    return table


def _root_name(story: Storyline, graphs: Mapping[str, ProcessGraph]) -> str:
    if story.root_guid.startswith(HOST_NODE_PREFIX):
        return "Unattributed activity"
    node = graphs.get(story.host, None)
    if node is not None and story.root_guid in node.nodes:
        return safe(_display_name(node.nodes[story.root_guid]))
    return safe(story.root_image_name or story.root_guid)


def _display_name(node: ProcessNode) -> str:
    if node.image:
        return node.image.replace("/", "\\").rsplit("\\", 1)[-1] or node.image
    return node.image_name or node.guid


def _arguments(node: ProcessNode) -> str:
    """The command line without the leading program, which the label already names."""
    command = (node.command_line or "").strip()
    candidates = [c for c in (node.image, _display_name(node)) if c]
    for candidate in candidates:
        for prefix in (f'"{candidate}"', candidate):
            if command.lower().startswith(prefix.lower()):
                return command[len(prefix) :].strip()
    return command


def _findings_by_node(findings: Iterable[Finding]) -> dict[tuple[str, str], list[Finding]]:
    grouped: dict[tuple[str, str], list[Finding]] = {}
    for finding in findings:
        grouped.setdefault((finding.host, finding.guid), []).append(finding)
    return grouped


def _node_label(
    node: ProcessNode,
    findings: Sequence[Finding],
    *,
    context: bool,
    dimmed: bool,
    view: View,
    marks: Sequence[str] = (),
) -> str:
    anchor = view.is_anchor(node)
    name = safe(_display_name(node))
    arguments = _arguments(node)
    text = name
    if arguments:
        text += f" {safe(arguments, view.width)}"
    if node.decoded_command:
        text += f"  [dim]decoded:[/] {safe(node.decoded_command, None if view.wide else 60)}"
    if node.is_ghost:
        text = f"[italic]? {text}[/]"
    if marks:
        text += "  " + " ".join(f"[bold]{m}[/]" for m in marks)
    if findings:
        worst = max(findings, key=lambda f: SEVERITY_RANK[f.severity]).severity
        ids = " ".join(sorted({f.rule_id for f in findings}))
        style = _SEVERITY_STYLE[worst]
        return f"[{style}]![/] {text}  [{style}]{ids}[/]"
    if anchor:
        return f"[dim]{text} (anchor)[/]"
    if context or dimmed:
        return f"[dim]{text}[/]"
    return text


def _activity_lines(node: ProcessNode) -> list[str]:
    lines = []
    for kind, label in _ACTIVITY_LABELS:
        seen: list[str] = []
        for activity in node.activity:
            if activity.kind != kind or activity.role != "actor":
                continue
            line = _activity_text(activity)
            if line is not None and line not in seen:
                seen.append(line)
        for line in seen[:ACTIVITY_LINES_PER_KIND]:
            lines.append(f"[dim]{label}[/] {line}")
        if len(seen) > ACTIVITY_LINES_PER_KIND:
            lines.append(f"[dim]+{len(seen) - ACTIVITY_LINES_PER_KIND} more {label}[/]")
    return lines


def _activity_text(activity: Activity) -> str | None:
    fields = activity.fields
    if activity.kind == "dns":
        return safe(defang_host(fields.get("query_name", "?")))
    if activity.kind == "file_create":
        return safe(fields.get("target_filename", "?"))
    if activity.kind == "registry":
        if activity.event_id != 13:
            return None
        value = fields.get("details", "")
        return f"{safe(fields.get('target_object', '?'), 160)} = {safe(value, 120)}"
    if activity.kind == "network":
        hostname = fields.get("destination_hostname", "")
        summary = activity.summary.split(" (", 1)[0] if hostname else activity.summary
        suffix = f" ({safe(defang_host(hostname))})" if hostname and hostname != "-" else ""
        return safe(summary) + suffix
    return safe(activity.summary, 160)


@dataclass(frozen=True)
class _TreeScope:
    """Which nodes a tree shows and how they are marked."""

    findings: Mapping[tuple[str, str], Sequence[Finding]]
    keep: frozenset[str]
    members: frozenset[str] | None = None
    dimmed: frozenset[str] = frozenset()
    hot_only: bool = False
    marks: Mapping[str, Sequence[str]] = field(default_factory=dict)


def _incoming(result: AnalysisResult, graph: ProcessGraph) -> dict[str, list[str]]:
    """Markers for processes that a link points at (§9.8 "Display"), by GUID."""
    created = {
        (n.create_record.file, n.create_record.index): guid
        for guid, n in graph.nodes.items()
        if n.create_record is not None
    }
    marks: dict[str, list[str]] = {}
    for story in result.storylines:
        if story.host != graph.host:
            continue
        for link in story.links:
            last = link.evidence[-1]
            guid = created.get((last.file, last.index))
            if guid is None:
                continue
            verb = "persistence of" if link.kind == "persistence" else "dropped by"
            mark = f"↩ {verb} {link.from_storyline}"
            if mark not in marks.setdefault(guid, []):
                marks[guid].append(mark)
    return marks


def _grow(
    tree: Tree, graph: ProcessGraph, roots: Sequence[str], scope: _TreeScope, view: View
) -> None:
    """Add ``roots`` and their visible descendants under ``tree``, iteratively."""
    flagged = {guid for (host, guid) in scope.findings if host == graph.host}
    stack: list[tuple[str | CollapsedGroup, Tree, int]] = [
        (guid, tree, 1) for guid in reversed(roots)
    ]
    while stack:
        item, parent, depth = stack.pop()
        if isinstance(item, CollapsedGroup):
            first = _clock(item.first_start_us) if item.first_start_us is not None else "?"
            last = _clock(item.last_start_us) if item.last_start_us is not None else "?"
            parent.add(f"[dim]× {len(item.guids)} {safe(item.image_name)} ({first} – {last})[/]")
            continue
        node = graph.nodes[item]
        found = scope.findings.get((graph.host, item), ())
        branch = parent.add(
            _node_label(
                node,
                found,
                context=item in scope.keep and item not in flagged,
                dimmed=item in scope.dimmed,
                view=view,
                marks=scope.marks.get(item, ()),
            )
        )
        if found:
            for line in _activity_lines(node):
                branch.add(line)
        children = [c for c in node.children if scope.members is None or c in scope.members]
        if scope.hot_only:
            children, hidden = hot_only_children(children, scope.keep)
            if hidden:
                branch.add(f"[dim]… {_plural(hidden, 'benign child', 'benign children')} hidden[/]")
        if not children:
            continue
        if depth >= view.max_depth:
            branch.add(f"[dim]… deeper levels hidden (--max-depth {view.max_depth})[/]")
            continue
        shown = collapse_children(graph, children, scope.keep, view.collapse_min)
        stack.extend((child, branch, depth + 1) for child in reversed(shown))


def _story_tree(result: AnalysisResult, story: Storyline, view: View) -> Tree | None:
    graph = result.graphs.get(story.host)
    if graph is None or story.root_guid not in graph.nodes:
        return None
    findings = _findings_by_node(visible_findings(result.findings, view.params, view.focus))
    keep = set(story.flagged) | set(story.path_nodes) | {story.root_guid}
    if view.focus is not None:
        keep |= view.focus.get(story.host, frozenset())
    scope = _TreeScope(
        findings=findings,
        keep=frozenset(keep),
        members=frozenset(story.nodes),
        marks=_incoming(result, graph),
    )
    label = (
        f"[dim]{safe(story.anchor_image_name)} (anchor)[/]"
        if story.anchor_image_name
        else "[dim](no anchor above the root)[/]"
    )
    tree = Tree(label, guide_style="dim")
    _grow(tree, graph, [story.root_guid], scope, view)
    return tree


def _story_title(story: Storyline, graphs: Mapping[str, ProcessGraph]) -> str:
    users = ", ".join(safe(u) for u in story.users) or "unknown user"
    return (
        f"[bold]{story.storyline_id}[/] · root {_root_name(story, graphs)} · {safe(story.host)} · "
        f"{users} · {_severity_badge(story.max_severity)} · {len(story.tactics)} tactics · "
        f"{len(story.finding_ids)} findings · {_span_text(story.start_us, story.end_us)}"
    )


def _plural(count: int, word: str, plural: str | None = None) -> str:
    return f"{count} {word if count == 1 else plural or word + 's'}"


def _scope_lines(scope: Scope) -> list[str]:
    summary = " · ".join(
        [
            _plural(len(scope.users), "user"),
            _plural(scope.process_count, "process", "processes"),
            f"{_plural(scope.review.get('files', 0), 'file')} "
            f"({scope.executable_files} executable)",
            _plural(scope.review.get("persistence", 0), "persistence key"),
            _plural(scope.review.get("destinations", 0), "destination"),
        ]
    )
    if scope.ghost_count:
        summary += f" · {_plural(scope.ghost_count, 'ghost')}"
    review = scope.review
    actions = " · ".join(
        [
            f"verify {_plural(review.get('processes', 0), 'process', 'processes')}",
            f"review {_plural(review.get('persistence', 0), 'persistence key')}",
            f"review {_plural(review.get('files', 0), 'file')}",
            f"hunt {_plural(review.get('destinations', 0), 'destination')}",
        ]
    )
    return [_kv("Scope", summary), _kv("Review", actions)]


def _scope_details(scope: Scope) -> list[str]:
    lines = []
    for label, values, host_like in (
        ("Persistence", scope.persistence, False),
        ("Files", scope.files_created, False),
        ("Registry", scope.registry_set, False),
        ("Destination", scope.destinations, False),
        ("DNS", scope.dns_names, True),
    ):
        for n, value in enumerate(values[:ACTIVITY_LINES_PER_KIND]):
            shown = safe(defang_host(value) if host_like else value, 160)
            lines.append(_kv(label if n == 0 else "", shown))
        if len(values) > ACTIVITY_LINES_PER_KIND:
            lines.append(_kv("", f"[dim]+{len(values) - ACTIVITY_LINES_PER_KIND} more[/]"))
    for n, item in enumerate(scope.unlinked_targets):
        if item.reason == "target_not_in_storyline":
            start = format_rfc3339(item.start_us) if item.start_us is not None else "?"
            state = f"ran as {safe(item.guid or '?')} at {start}, in no storyline"
        else:
            state = "not seen running"
        lines.append(
            _kv("Not linked" if n == 0 else "", f"{safe(item.path)} · {state} ({item.rule_id})")
        )
    return lines


def _findings_table(findings: Sequence[Finding], owners: Mapping[str, str]) -> Table:
    table = Table(title="Findings", box=box.SIMPLE, title_justify="left", header_style="bold")
    for column in ("Severity", "Rule", "Title", "Process", "Host", "First seen", "Count", "Story"):
        table.add_column(
            column,
            justify="right" if column == "Count" else "left",
            no_wrap=column not in ("Title", "Process", "Host"),
        )
    for finding in findings:
        table.add_row(
            _severity_badge(finding.severity),
            finding.rule_id,
            safe(finding.title),
            safe(finding.image_name or finding.guid),
            safe(finding.host),
            format_rfc3339(finding.first_us),
            str(finding.count),
            owners.get(finding.finding_id, "-"),
        )
    return table


def _telemetry_gaps(console: Console, coverage: Coverage) -> None:
    if not coverage.timeline.gaps:
        return
    console.print(" [bold]Telemetry gaps[/] [dim](informational)[/]")
    for gap in coverage.timeline.gaps:
        console.print(
            f"   {safe(gap.host)} {format_rfc3339(gap.from_us)} → {format_rfc3339(gap.to_us)} "
            f"({_gap_text(gap.seconds)} with no events)"
        )


def _result_panel(console: Console, result: AnalysisResult) -> None:
    coverage = "complete" if result.coverage.complete else "partial"
    lines = [
        f"{_STATUS_BADGE[result.status]}   {_plural(len(result.storylines), 'storyline')} · "
        f"{_plural(len(result.findings), 'finding')} · coverage {coverage}"
    ]
    if result.status == "incomplete":
        lines.append(f"[red]{PARTIAL_LINE}[/]")
    console.print(
        Panel(
            Group(*(Text.from_markup(line) for line in lines)),
            title="Result",
            title_align="left",
            subtitle=f"exit {result.exit_code}",
            subtitle_align="right",
            box=box.ROUNDED,
        )
    )


def _split_low_signal(stories: Sequence[Storyline]) -> tuple[list[Storyline], list[Storyline]]:
    main = [s for s in stories if s.max_severity not in LOW_SIGNAL]
    low = [s for s in stories if s.max_severity in LOW_SIGNAL]
    return main, low


def owners_of(result: AnalysisResult) -> dict[str, str]:
    """Finding ID → storyline ID."""
    return {fid: s.storyline_id for s in result.storylines for fid in s.finding_ids}


def render_written(console: Console, written: Sequence[tuple[str, Path]]) -> None:
    """List the files an analysis wrote."""
    for label, path in written:
        console.print(_kv("Wrote", f"{label} {safe(str(path))}"))


def render_analyze(
    console: Console,
    result: AnalysisResult,
    view: View,
    written: Sequence[tuple[str, Path]] = (),
) -> None:
    """The full `analyze` screen (§11.2)."""
    _header(console, result, "analyze")
    _coverage_block(console, result.coverage)
    stories = visible_storylines(result.storylines, view.params, view.focus)
    main, low = _split_low_signal(stories)
    if stories:
        console.print(_ranking_table(main + low, result.graphs))
    else:
        console.print(" [dim]No storylines to show.[/]")
    for story in main:
        console.print()
        console.print(_story_title(story, result.graphs))
        tree = _story_tree(result, story, view)
        if tree is not None:
            console.print(tree)
        for line in _scope_lines(story.scope):
            console.print(line)
    if low:
        console.print()
        console.print(
            f" [bold]Low-signal storylines[/] [dim]({len(low)}, collapsed; "
            "use `lineage story --storyline N`)[/]"
        )
        for story in low:
            console.print(f"   {_story_title(story, result.graphs)}")
    findings = visible_findings(result.findings, view.params, view.focus)
    if findings:
        console.print(_findings_table(findings, owners_of(result)))
    _telemetry_gaps(console, result.coverage)
    _result_panel(console, result)
    render_written(console, written)


def render_tree(console: Console, result: AnalysisResult, view: View) -> None:
    """Process trees per host (§11.2 `tree`), honouring --hot-only and --focus."""
    _header(console, result, "tree")
    findings = _findings_by_node(visible_findings(result.findings, view.params, view.focus))
    stories = visible_storylines(result.storylines, view.params, view.focus)
    for host in result.hosts:
        graph = result.graphs.get(host)
        if graph is None:
            continue
        flagged = [guid for (h, guid) in findings if h == host]
        keep = set(hot_set(graph, flagged))
        members: frozenset[str] | None = None
        dimmed: frozenset[str] = frozenset()
        if view.params.hot_only:
            for story in stories:
                if story.host == host:
                    for guid in story.nodes:
                        if guid in graph.nodes:
                            keep.add(guid)
                            keep.update(ancestors(graph, guid))
        if view.focus is not None:
            focus = view.focus.get(host, frozenset())
            members = focus
            keep |= focus
            targets = {g for g in focus if g in graph.nodes}
            dimmed = frozenset(a for g in targets for a in ancestors(graph, g) if a in focus)
        scope = _TreeScope(
            findings=findings,
            keep=frozenset(keep),
            members=members,
            dimmed=dimmed,
            hot_only=view.params.hot_only,
            marks=_incoming(result, graph),
        )
        roots = [r for r in graph.roots if members is None or r in members]
        if view.params.hot_only:
            hidden = sum(1 for r in roots if r not in scope.keep)
            roots = [r for r in roots if r in scope.keep]
        else:
            hidden = 0
        tree = Tree(f"[bold]{safe(host)}[/]", guide_style="dim")
        _grow(tree, graph, roots, scope, view)
        if hidden:
            tree.add(f"[dim]… {hidden} process trees without findings hidden[/]")
        console.print(tree)
    console.print(TREE_LEGEND)
    _result_line(console, result)


def _result_line(console: Console, result: AnalysisResult) -> None:
    console.print(
        f" [bold]Result[/]   {_STATUS_BADGE[result.status]} · "
        f"{_plural(len(result.storylines), 'storyline')} · "
        f"{_plural(len(result.findings), 'finding')} · exit {result.exit_code}"
    )
    if result.status == "incomplete":
        console.print(f" [red]{PARTIAL_LINE}[/]")


def _step_lines(story: Storyline, view: View) -> list[str]:
    steps = visible_steps(story, view.params)
    limit = view.params.max_steps
    omitted = 0
    if len(steps) > limit:
        tail = 10
        omitted = len(steps) - limit
        steps = steps[: limit - tail] + steps[-tail:]
        cut_after = steps[limit - tail - 1].n
    else:
        cut_after = None
    gaps = {g.after_step: g.seconds for g in story.gaps}
    day = format_rfc3339(story.start_us)[:10]
    pending = _links_by_setting_record(story)
    lines = []
    last_tactic: str | None = None
    for step in steps:
        if step.tactic and step.tactic != last_tactic:
            lines.append(f"   [bold]── {step.tactic.replace('-', ' ').title()} ──[/]")
            last_tactic = step.tactic
        stamp = format_rfc3339(step.ts_us)
        when = stamp[11:] if stamp[:10] == day else stamp
        marker = f"[{_SEVERITY_STYLE[step.severity]}]![/]" if step.severity is not None else " "
        technique = f"  [dim]{step.technique}[/]" if step.technique else ""
        lines.append(f"   {step.n:>3}  {when}  {marker} {safe(step.text)}{technique}")
        for link in pending.pop((step.source.file, step.source.index), []):
            lines.append(f"        {_link_text(link)}")
        if step.n in gaps:
            lines.append(f"        [dim]⏸ {_gap_text(gaps[step.n])} with no storyline activity[/]")
        if cut_after is not None and step.n == cut_after:
            lines.append(f"        [dim]… {omitted} steps omitted[/]")
    # Links whose setting step is not shown (no step for it, or hidden by a filter).
    rest = [link for links in pending.values() for link in links]
    if rest:
        lines.append("   [bold]Links[/]")
        lines.extend(f"        {_link_text(link)}" for link in rest)
    return lines


def _links_by_setting_record(story: Storyline) -> dict[tuple[str, int], list[StorylineLink]]:
    pending: dict[tuple[str, int], list[StorylineLink]] = {}
    for link in story.links:
        first = link.evidence[0]
        pending.setdefault((first.file, first.index), []).append(link)
    return pending


def _link_text(link: StorylineLink) -> str:
    what = "fires later as" if link.kind == "persistence" else "dropped file runs later as"
    return f"[bold]↪ {what} {link.to_storyline}[/] ({link.match} match: {safe(link.path)})"


def render_story(console: Console, result: AnalysisResult, view: View) -> None:
    """Storylines as numbered narratives (§11.2 `story`)."""
    _header(console, result, "story")
    if view.storyline is not None:
        stories: Sequence[Storyline] = [result.storylines[view.storyline - 1]]
        low: Sequence[Storyline] = []
    else:
        visible = visible_storylines(result.storylines, view.params, view.focus)
        stories, low = _split_low_signal(visible)
    if not stories and not low:
        console.print(" [dim]No storylines to show.[/]")
    for story in stories:
        console.print()
        console.print(_story_title(story, result.graphs))
        for line in _step_lines(story, view):
            console.print(line)
        for line in _scope_lines(story.scope) + _scope_details(story.scope):
            console.print(line)
    if low:
        console.print()
        console.print(
            f" [bold]Low-signal storylines[/] [dim]({len(low)}, collapsed; use --storyline N)[/]"
        )
        for story in low:
            console.print(f"   {_story_title(story, result.graphs)}")
    _result_line(console, result)


def render_inspect(
    console: Console, result: AnalysisResult, host: str, guid: str, view: View
) -> None:
    """Everything known about one process (§11.2 `inspect`); values are shown in full."""
    graph = result.graphs[host]
    node = graph.nodes[guid]
    console.print(_banner("inspect"))
    ghost = f"ghost ({node.ghost_reason})" if node.is_ghost else "created (event 1)"
    hashes = " · ".join(f"{safe(k)} {safe(v)}" for k, v in node.hashes.items()) or "-"
    start = format_rfc3339(node.start_us) if node.start_us is not None else "unknown"
    end = format_rfc3339(node.end_us) if node.end_us is not None else "-"
    for label, value in (
        ("Image", safe(node.image or node.image_name or "?")),
        ("Hashes", hashes),
        ("PID", str(node.pid) if node.pid is not None else "?"),
        ("GUID", safe(node.guid)),
        ("Host", safe(node.host)),
        ("User", safe(node.user or "?")),
        ("Integrity", safe(node.integrity_level or "?")),
        ("Start", start),
        ("End", end),
        ("State", ghost + (" · anchor" if view.is_anchor(node) else "")),
        ("Command", safe(node.command_line or "-")),
    ):
        console.print(_kv(label, value))
    if node.decoded_command:
        console.print(_kv("Decoded", safe(node.decoded_command)))
    if node.decode_note:
        console.print(_kv("Decode note", safe(node.decode_note)))

    chain = [guid, *ancestors(graph, guid)]
    console.print(" [bold]Ancestry[/] (nearest first)")
    for other in chain:
        item = graph.nodes[other]
        marks = " (anchor)" if view.is_anchor(item) else ""
        marks += " (ghost)" if item.is_ghost else ""
        console.print(f"   {safe(_display_name(item))} {safe(other)}{marks}")

    console.print(f" [bold]Children[/] ({len(node.children)})")
    for child in node.children:
        item = graph.nodes[child]
        start = format_rfc3339(item.start_us) if item.start_us is not None else "?"
        console.print(f"   {safe(_display_name(item))} {safe(child)} {start}")

    groups: dict[str, list[Activity]] = {}
    for activity in node.activity:
        groups.setdefault(activity.kind, []).append(activity)
    for kind, items in sorted(groups.items()):
        shown = items[:INSPECT_ITEMS_PER_KIND]
        console.print(f" [bold]Activity · {kind}[/] ({len(shown)} of {len(items)})")
        for activity in shown:
            role = " [dim](target)[/]" if activity.role == "target" else ""
            console.print(
                f"   {format_rfc3339(activity.ts_us)} {safe(activity.summary)}{role} "
                f"[dim]{safe(activity.source.file)}:{activity.source.index}[/]"
            )
    if node.image_load_count:
        shown_loads = node.image_loads[:INSPECT_ITEMS_PER_KIND]
        console.print(
            f" [bold]Activity · image_load[/] ({len(shown_loads)} of {node.image_load_count})"
        )
        for load in shown_loads:
            console.print(
                f"   {format_rfc3339(load.ts_us)} {safe(load.image_loaded or '?')} "
                f"signed {safe(load.signed or '?')} [dim]{safe(load.source.file)}:"
                f"{load.source.index}[/]"
            )

    findings = [f for f in result.findings if f.host == host and f.guid == guid]
    console.print(f" [bold]Findings[/] ({len(findings)})")
    for finding in findings:
        console.print(
            f"   {_severity_badge(finding.severity)} {finding.rule_id} {safe(finding.title)}"
        )
        console.print(f"     [dim]{safe(finding.why.strip())}[/]")
        refs = ", ".join(f"{safe(e.file)}:{e.index}" for e in finding.evidence)
        more = " (truncated)" if finding.evidence_truncated else ""
        console.print(f"     evidence {refs}{more}")
    member_of = [s.storyline_id for s in result.storylines if s.host == host and guid in s.nodes]
    console.print(_kv("Storylines", ", ".join(member_of) or "none"))
