"""Command-line interface; the only module that imports Typer."""

import io
import sys
from collections.abc import Callable, Sequence
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer

from lineage_ir import __version__
from lineage_ir.analyze.anchors import load_anchors
from lineage_ir.analyze.filters import AnalysisParams, make_params
from lineage_ir.analyze.focus import focus_set, resolve_focus, resolve_one
from lineage_ir.config import (
    COLLAPSE_MIN_RANGE,
    DEFAULT_COLLAPSE_MIN,
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_ERRORS,
    DEFAULT_MAX_FILE_SIZE_MB,
    DEFAULT_MAX_RECORDS,
    INSPECT_ITEMS_PER_KIND,
    MAX_DEPTH_RANGE,
    MAX_FILE_SIZE_MB_RANGE,
    MAX_RECORDS_RANGE,
)
from lineage_ir.engine import (
    AnalysisResult,
    list_rules,
    new_run_id,
    now_us,
    rule_set_sha256,
    run_analysis,
    run_validate,
)
from lineage_ir.errors import LineageError, UsageError
from lineage_ir.graph.traverse import ancestors
from lineage_ir.ingest.reader import IngestOptions
from lineage_ir.outputs import OutputKind, OutputRequest, check_outputs, write_outputs
from lineage_ir.render import artifacts, csv_timeline, report_json, terminal

EXIT_INTERNAL = 4
EXIT_INTERRUPTED = 130

app = typer.Typer(
    add_completion=False,
    invoke_without_command=True,
    pretty_exceptions_enable=False,
    help="Offline reconstruction of Windows process lineage from Sysmon telemetry.",
)

# Replaced in tests to freeze time and run IDs.
clock = now_us
run_id_factory = new_run_id


class OutputFormat(StrEnum):
    """Output format for commands that support JSON."""

    text = "text"
    json = "json"


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"lineage {__version__}")
        raise typer.Exit(0)


def _prepare_streams() -> None:
    """Keep non-ASCII output from failing on legacy code pages (Windows redirects)."""
    for stream in (sys.stdout, sys.stderr):
        try:
            if stream.isatty():
                stream.reconfigure(errors="replace")  # type: ignore[union-attr]
            else:
                stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
        except (AttributeError, ValueError, io.UnsupportedOperation):
            pass


@app.callback()
def main(
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            callback=_version_callback,
            is_eager=True,
            help="Print the version and exit.",
        ),
    ] = False,
) -> None:
    """Lineage: process lineage and attack storylines from Sysmon telemetry."""
    _prepare_streams()
    if ctx.invoked_subcommand is None:
        terminal.render_overview(terminal.make_console())
        raise typer.Exit(0)


InputsArg = Annotated[
    list[Path],
    typer.Argument(help="Sysmon EVTX, JSON or JSONL files (1-64).", show_default=False),
]
FormatOpt = Annotated[OutputFormat, typer.Option("--format", help="Output format.")]
MaxRecordsOpt = Annotated[
    int,
    typer.Option(
        "--max-records",
        min=MAX_RECORDS_RANGE[0],
        max=MAX_RECORDS_RANGE[1],
        help="Stop reading after this many records in total.",
    ),
]
MaxFileSizeOpt = Annotated[
    int,
    typer.Option(
        "--max-file-size",
        min=MAX_FILE_SIZE_MB_RANGE[0],
        max=MAX_FILE_SIZE_MB_RANGE[1],
        help="Largest accepted input file, in MB.",
    ),
]
NoColorOpt = Annotated[bool, typer.Option("--no-color", help="Disable colour output.")]
VerboseOpt = Annotated[
    bool, typer.Option("--verbose", help="Show a traceback on unexpected internal errors.")
]


def _fail_internal(verbose: bool, no_color: bool) -> NoReturn:
    err = terminal.make_console(no_color=no_color, stderr=True)
    terminal.print_error(err, "unexpected internal error (use --verbose for details)")
    if verbose:
        err.print_exception(show_locals=False)
    raise typer.Exit(EXIT_INTERNAL)


@app.command()
def validate(
    inputs: InputsArg,
    output_format: FormatOpt = OutputFormat.text,
    max_errors: Annotated[
        int, typer.Option("--max-errors", min=0, help="How many invalid records to list.")
    ] = DEFAULT_MAX_ERRORS,
    max_records: MaxRecordsOpt = DEFAULT_MAX_RECORDS,
    max_file_size: MaxFileSizeOpt = DEFAULT_MAX_FILE_SIZE_MB,
    no_color: NoColorOpt = False,
    verbose: VerboseOpt = False,
) -> None:
    """Check what an input holds and which rule families it can support."""
    options = IngestOptions(
        max_records=max_records,
        max_file_size_mb=max_file_size,
        max_error_samples=max_errors,
    )
    try:
        result = run_validate(inputs, options, clock=clock, run_id_factory=run_id_factory)
    except LineageError as exc:
        terminal.print_error(terminal.make_console(no_color=no_color, stderr=True), str(exc))
        raise typer.Exit(exc.exit_code) from None
    except KeyboardInterrupt:
        raise typer.Exit(EXIT_INTERRUPTED) from None
    except Exception:
        _fail_internal(verbose, no_color)

    if output_format is OutputFormat.json:
        # Bytes bypass newline translation, so the document keeps LF on every platform.
        document = report_json.dumps(report_json.validate_document(result))
        typer.echo(document.encode("ascii"), nl=False)
    else:
        terminal.render_validate(terminal.make_console(no_color=no_color), result, max_errors)
    raise typer.Exit(result.exit_code)


@app.command("rules")
def rules_command(
    output_format: FormatOpt = OutputFormat.text,
    no_color: NoColorOpt = False,
    verbose: VerboseOpt = False,
) -> None:
    """List the bundled rules and graph heuristics with the event IDs they need."""
    run_id = run_id_factory()
    started = clock()
    try:
        catalogue = list_rules()
    except LineageError as exc:
        terminal.print_error(terminal.make_console(no_color=no_color, stderr=True), str(exc))
        raise typer.Exit(exc.exit_code) from None
    except KeyboardInterrupt:
        raise typer.Exit(EXIT_INTERRUPTED) from None
    except Exception:
        _fail_internal(verbose, no_color)

    if output_format is OutputFormat.json:
        document = report_json.dumps(
            report_json.rules_document(catalogue, run_id, started, clock())
        )
        typer.echo(document.encode("ascii"), nl=False)
    else:
        terminal.render_rules(terminal.make_console(no_color=no_color), catalogue)
    raise typer.Exit(0)


# ---------------------------------------------------------------- analysis commands

HostOpt = Annotated[
    list[str] | None,
    typer.Option("--host", help="Only analyze this host (repeatable).", show_default=False),
]
RulesOpt = Annotated[
    str | None,
    typer.Option("--rules", help="Rule IDs or families, comma-separated (CMD, PER-001, GR)."),
]
MinSeverityOpt = Annotated[
    str, typer.Option("--min-severity", help="Drop findings below: high, medium, low, info.")
]
SinceOpt = Annotated[str | None, typer.Option("--since", help="Show from this RFC 3339 time.")]
UntilOpt = Annotated[str | None, typer.Option("--until", help="Show up to this RFC 3339 time.")]
AroundOpt = Annotated[
    str | None, typer.Option("--around", help="Show a window around this RFC 3339 time.")
]
WindowOpt = Annotated[
    str | None, typer.Option("--window", help="Half-width of --around (default 15m).")
]
FocusOpt = Annotated[
    str | None, typer.Option("--focus", help="GUID, pid:N or image:NAME to pivot on.")
]
HotOnlyOpt = Annotated[
    bool, typer.Option("--hot-only", help="Show only storyline nodes and their ancestors.")
]
TelemetryGapOpt = Annotated[
    str, typer.Option("--telemetry-gap", help="Report event pauses at least this long.")
]
GapOpt = Annotated[str, typer.Option("--gap", help="Mark storyline pauses at least this long.")]
MaxStepsOpt = Annotated[int, typer.Option("--max-steps", help="Steps shown per storyline.")]
WideOpt = Annotated[bool, typer.Option("--wide", help="Do not truncate command lines.")]
CollapseMinOpt = Annotated[
    int,
    typer.Option(
        "--collapse-min",
        min=COLLAPSE_MIN_RANGE[0],
        max=COLLAPSE_MIN_RANGE[1],
        help="Fold this many same-named benign siblings into one line.",
    ),
]


def _fail(exc: LineageError, no_color: bool) -> NoReturn:
    terminal.print_error(terminal.make_console(no_color=no_color, stderr=True), str(exc))
    raise typer.Exit(exc.exit_code) from None


def _params(hosts: list[str] | None, **options: Any) -> AnalysisParams:
    return make_params(hosts=tuple(hosts or ()), **options)


def _analyze(inputs: Sequence[Path], params: AnalysisParams) -> AnalysisResult:
    return run_analysis(inputs, params, clock=clock, run_id_factory=run_id_factory)


def _view(result: AnalysisResult, params: AnalysisParams, **options: Any) -> terminal.View:
    focus = None
    if params.focus is not None:
        focus = focus_set(result.graphs, resolve_focus(result.graphs, params.focus))
    return terminal.View(params=params, focus=focus, is_anchor=load_anchors(), **options)


def _echo_json(document: dict[str, Any]) -> None:
    # Bytes bypass newline translation, so the document keeps LF on every platform.
    typer.echo(report_json.dumps(document).encode("ascii"), nl=False)


def _run(body: Callable[[], int], verbose: bool, no_color: bool) -> NoReturn:
    """Run a command body and map its errors to exit codes (§10.5)."""
    try:
        code = body()
    except LineageError as exc:
        _fail(exc, no_color)
    except KeyboardInterrupt:
        raise typer.Exit(EXIT_INTERRUPTED) from None
    except Exception:
        _fail_internal(verbose, no_color)
    raise typer.Exit(code)


@app.command()
def analyze(
    inputs: InputsArg,
    host: HostOpt = None,
    rules: RulesOpt = None,
    min_severity: MinSeverityOpt = "info",
    since: SinceOpt = None,
    until: UntilOpt = None,
    around: AroundOpt = None,
    window: WindowOpt = None,
    focus: FocusOpt = None,
    hot_only: HotOnlyOpt = False,
    gap: GapOpt = "10m",
    max_steps: MaxStepsOpt = 60,
    telemetry_gap: TelemetryGapOpt = "30m",
    collapse_min: CollapseMinOpt = DEFAULT_COLLAPSE_MIN,
    wide: WideOpt = False,
    report: Annotated[
        Path | None, typer.Option("--report", help="Write the JSON report here.")
    ] = None,
    artifacts_path: Annotated[
        Path | None, typer.Option("--artifacts", help="Write artifacts JSONL for Lucent here.")
    ] = None,
    csv: Annotated[
        Path | None, typer.Option("--csv", help="Write the CSV storyline timeline here.")
    ] = None,
    force: Annotated[
        bool, typer.Option("--force", help="Replace an existing output Lineage wrote before.")
    ] = False,
    output_format: FormatOpt = OutputFormat.text,
    max_records: MaxRecordsOpt = DEFAULT_MAX_RECORDS,
    max_file_size: MaxFileSizeOpt = DEFAULT_MAX_FILE_SIZE_MB,
    no_color: NoColorOpt = False,
    verbose: VerboseOpt = False,
) -> None:
    """Full run: storylines, hot trees, scope, findings and coverage."""

    def body() -> int:
        params = _params(
            host,
            rules=rules,
            min_severity=min_severity,
            since=since,
            until=until,
            around=around,
            window=window,
            focus=focus,
            hot_only=hot_only,
            gap=gap,
            max_steps=max_steps,
            telemetry_gap=telemetry_gap,
            max_records=max_records,
            max_file_size_mb=max_file_size,
        )
        targets: list[tuple[Path, OutputKind]] = [
            (path, kind)
            for path, kind in ((report, "report"), (artifacts_path, "artifacts"), (csv, "csv"))
            if path is not None
        ]
        # Unsafe paths end the run before analysis (exit 2); files are written after it.
        check_outputs([OutputRequest(p, b"", k) for p, k in targets], inputs, force)
        result = _analyze(inputs, params)
        view = _view(result, params, wide=wide, collapse_min=collapse_min)
        document = report_json.report_document(result, rule_set_sha256())
        contents = {
            "report": lambda: report_json.dumps(document).encode("ascii"),
            "artifacts": lambda: artifacts.artifacts_text(result).encode("ascii"),
            "csv": lambda: csv_timeline.csv_bytes(result),
        }
        requests = [OutputRequest(p, contents[k](), k) for p, k in targets]
        write_outputs(requests, inputs, force)
        if output_format is OutputFormat.json:
            _echo_json(document)
        else:
            written = [(r.kind, r.path) for r in requests]
            terminal.render_analyze(terminal.make_console(no_color=no_color), result, view, written)
        return result.exit_code

    _run(body, verbose, no_color)


@app.command()
def tree(
    inputs: InputsArg,
    host: HostOpt = None,
    rules: RulesOpt = None,
    min_severity: MinSeverityOpt = "info",
    since: SinceOpt = None,
    until: UntilOpt = None,
    around: AroundOpt = None,
    window: WindowOpt = None,
    focus: FocusOpt = None,
    hot_only: HotOnlyOpt = False,
    max_depth: Annotated[
        int,
        typer.Option(
            "--max-depth",
            min=MAX_DEPTH_RANGE[0],
            max=MAX_DEPTH_RANGE[1],
            help="Deepest tree level shown (display only).",
        ),
    ] = DEFAULT_MAX_DEPTH,
    collapse_min: CollapseMinOpt = DEFAULT_COLLAPSE_MIN,
    wide: WideOpt = False,
    telemetry_gap: TelemetryGapOpt = "30m",
    output_format: FormatOpt = OutputFormat.text,
    max_records: MaxRecordsOpt = DEFAULT_MAX_RECORDS,
    max_file_size: MaxFileSizeOpt = DEFAULT_MAX_FILE_SIZE_MB,
    no_color: NoColorOpt = False,
    verbose: VerboseOpt = False,
) -> None:
    """Process trees per host, with findings marked."""

    def body() -> int:
        params = _params(
            host,
            rules=rules,
            min_severity=min_severity,
            since=since,
            until=until,
            around=around,
            window=window,
            focus=focus,
            hot_only=hot_only,
            telemetry_gap=telemetry_gap,
            max_records=max_records,
            max_file_size_mb=max_file_size,
        )
        result = _analyze(inputs, params)
        view = _view(result, params, wide=wide, max_depth=max_depth, collapse_min=collapse_min)
        if output_format is OutputFormat.json:
            _echo_json(report_json.report_document(result, rule_set_sha256()))
        else:
            terminal.render_tree(terminal.make_console(no_color=no_color), result, view)
        return result.exit_code

    _run(body, verbose, no_color)


@app.command()
def story(
    inputs: InputsArg,
    host: HostOpt = None,
    rules: RulesOpt = None,
    min_severity: MinSeverityOpt = "info",
    since: SinceOpt = None,
    until: UntilOpt = None,
    around: AroundOpt = None,
    window: WindowOpt = None,
    focus: FocusOpt = None,
    storyline: Annotated[
        int | None, typer.Option("--storyline", min=1, help="Show only storyline N.")
    ] = None,
    max_steps: MaxStepsOpt = 60,
    gap: GapOpt = "10m",
    wide: WideOpt = False,
    telemetry_gap: TelemetryGapOpt = "30m",
    output_format: FormatOpt = OutputFormat.text,
    max_records: MaxRecordsOpt = DEFAULT_MAX_RECORDS,
    max_file_size: MaxFileSizeOpt = DEFAULT_MAX_FILE_SIZE_MB,
    no_color: NoColorOpt = False,
    verbose: VerboseOpt = False,
) -> None:
    """Storylines as numbered narratives with tactic headings and gaps."""

    def body() -> int:
        params = _params(
            host,
            rules=rules,
            min_severity=min_severity,
            since=since,
            until=until,
            around=around,
            window=window,
            focus=focus,
            gap=gap,
            max_steps=max_steps,
            telemetry_gap=telemetry_gap,
            max_records=max_records,
            max_file_size_mb=max_file_size,
        )
        result = _analyze(inputs, params)
        if storyline is not None and storyline > len(result.storylines):
            raise UsageError(
                f"--storyline {storyline}: out of range "
                f"(this analysis has {len(result.storylines)} storylines)"
            )
        view = _view(result, params, wide=wide, storyline=storyline)
        if output_format is OutputFormat.json:
            _echo_json(report_json.report_document(result, rule_set_sha256(), storyline))
        else:
            terminal.render_story(terminal.make_console(no_color=no_color), result, view)
        return result.exit_code

    _run(body, verbose, no_color)


@app.command()
def inspect(
    inputs: InputsArg,
    target: Annotated[
        str, typer.Argument(help="GUID, pid:N or image:NAME of one process.", show_default=False)
    ],
    host: HostOpt = None,
    output_format: FormatOpt = OutputFormat.text,
    max_records: MaxRecordsOpt = DEFAULT_MAX_RECORDS,
    max_file_size: MaxFileSizeOpt = DEFAULT_MAX_FILE_SIZE_MB,
    no_color: NoColorOpt = False,
    verbose: VerboseOpt = False,
) -> None:
    """Everything known about one process: identity, ancestry, activity and findings."""

    def body() -> int:
        params = _params(host, max_records=max_records, max_file_size_mb=max_file_size)
        result = _analyze(inputs, params)
        node_host, guid = resolve_one(result.graphs, target, "TARGET")
        anchors = load_anchors()
        if output_format is OutputFormat.json:
            graph = result.graphs[node_host]
            ancestry = [(g, anchors(graph.nodes[g])) for g in ancestors(graph, guid)]
            _echo_json(
                report_json.inspect_document(
                    result, node_host, guid, ancestry, INSPECT_ITEMS_PER_KIND
                )
            )
        else:
            view = terminal.View(params=params, is_anchor=anchors)
            console = terminal.make_console(no_color=no_color)
            terminal.render_inspect(console, result, node_host, guid, view)
        return 0

    _run(body, verbose, no_color)
