"""Frozen-clock analysis runs, report builders and schema validators for P5 tests."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from lineage_ir.analyze.filters import make_params
from lineage_ir.engine import AnalysisResult, rule_set_sha256, run_analysis
from lineage_ir.ingest.timeparse import to_us
from lineage_ir.render import artifacts, report_json

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures"
SCHEMAS = ROOT / "schema"
RUN_ID = "00000000-0000-4000-8000-000000000001"
FROZEN_US = to_us(datetime(2026, 10, 14, 17, 46, 40, tzinfo=UTC))


def frozen_analysis(*paths: Path, **options: Any) -> AnalysisResult:
    """run_analysis with a fixed clock and run ID, so outputs are byte-comparable."""
    return run_analysis(
        list(paths),
        make_params(**options),
        clock=lambda: FROZEN_US,
        run_id_factory=lambda: RUN_ID,
    )


def report_text(result: AnalysisResult, storyline: int | None = None) -> str:
    return report_json.dumps(report_json.report_document(result, rule_set_sha256(), storyline))


def report(result: AnalysisResult) -> dict[str, Any]:
    return json.loads(report_text(result))


def artifact_lines(result: AnalysisResult) -> list[dict[str, Any]]:
    return [json.loads(line) for line in artifacts.artifacts_text(result).splitlines()]


def validator(name: str, definition: str | None = None) -> Draft202012Validator:
    """A validator for ``schema/<name>``, or for one of its ``$defs`` entries."""
    schema = json.loads((SCHEMAS / name).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    if definition is not None:
        schema = {**schema, "$ref": f"#/$defs/{definition}"}
        for key in ("oneOf", "required", "properties", "additionalProperties", "type"):
            schema.pop(key, None)
    return Draft202012Validator(schema)
