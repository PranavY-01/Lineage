"""Command-line interface; the only module that imports Typer."""

from enum import StrEnum
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from lineage_ir import __version__
from lineage_ir.config import (
    DEFAULT_MAX_ERRORS,
    DEFAULT_MAX_FILE_SIZE_MB,
    DEFAULT_MAX_RECORDS,
    MAX_FILE_SIZE_MB_RANGE,
    MAX_RECORDS_RANGE,
)
from lineage_ir.engine import list_rules, new_run_id, now_us, run_validate
from lineage_ir.errors import LineageError
from lineage_ir.ingest.reader import IngestOptions
from lineage_ir.render import report_json, terminal

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
