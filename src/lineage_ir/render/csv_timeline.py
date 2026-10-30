"""CSV storyline timeline (§12.6, stretch S3).

One row per step of every storyline, whatever the display filters (amendment 16). Values are
raw, as in every machine output (§12); the only change is a leading ``'`` on any cell that a
spreadsheet would read as a formula. UTF-8 with a BOM, every field quoted, CRLF line endings.
"""

import csv
import io

from lineage_ir.config import CSV_COLUMNS
from lineage_ir.engine import AnalysisResult
from lineage_ir.ingest.timeparse import format_rfc3339

BOM = chr(0xFEFF)
REPLACEMENT = chr(0xFFFD)
# Characters that start a formula, with their full-width forms (＝ ＋ － ＠).
FORMULA_TRIGGERS = frozenset("=+-@\t\r") | frozenset(
    chr(c) for c in (0xFF1D, 0xFF0B, 0xFF0D, 0xFF20)
)


def neutralize(cell: str) -> str:
    """Prefix ``'`` when the first character after leading whitespace starts a formula."""
    for char in cell:
        if char in FORMULA_TRIGGERS:
            return "'" + cell
        if not char.isspace():
            return cell
    return cell


def _clean(cell: str) -> str:
    # Lone surrogates cannot be written as UTF-8 (amendment 22).
    if any(0xD800 <= ord(c) <= 0xDFFF for c in cell):
        cell = "".join(REPLACEMENT if 0xD800 <= ord(c) <= 0xDFFF else c for c in cell)
    return neutralize(cell)


def csv_bytes(result: AnalysisResult) -> bytes:
    """The CSV file: BOM, quoted header, one quoted row per step, CRLF after every line."""
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS)
    for story in result.storylines:
        for step in story.steps:
            row = (
                story.storyline_id,
                str(step.n),
                format_rfc3339(step.ts_us),
                step.tactic or "",
                step.technique or "",
                step.severity or "",
                story.host,
                step.guid,
                step.image_name or "",
                step.action,
                step.text,
                "" if step.source.record_id is None else str(step.source.record_id),
                step.source.file,
            )
            writer.writerow([_clean(cell) for cell in row])
    return (BOM + buffer.getvalue()).encode("utf-8")
