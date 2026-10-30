"""Rich terminal views."""

from collections.abc import Sequence

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from lineage_ir import __version__
from lineage_ir.config import SYSMON_EVENT_NAMES, UNKNOWN_KEYS_SHOWN
from lineage_ir.ingest.timeparse import format_rfc3339
from lineage_ir.models import RuleInfo, ValidateResult
from lineage_ir.render.safe import safe

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
