"""Builders for the 7d7b-report envelope and the JSON documents printed by the CLI (§12.3)."""

import json
from typing import Any

from lineage_ir import __version__
from lineage_ir.ingest.timeparse import format_rfc3339
from lineage_ir.models import ValidateResult

ENVELOPE_SCHEMA = "7d7b-report"
ENVELOPE_SCHEMA_VERSION = "1.0"
TOOL = "lineage"


def envelope(run_id: str, started_us: int, completed_us: int) -> dict[str, Any]:
    """The shared series envelope, keys in contract order."""
    return {
        "schema": ENVELOPE_SCHEMA,
        "schema_version": ENVELOPE_SCHEMA_VERSION,
        "tool": TOOL,
        "tool_version": __version__,
        "run_id": run_id,
        "started_at": format_rfc3339(started_us),
        "completed_at": format_rfc3339(completed_us),
    }


def dumps(document: dict[str, Any]) -> str:
    """Serialize as ASCII JSON with 2-space indent and a trailing LF."""
    return json.dumps(document, ensure_ascii=True, indent=2) + "\n"


def validate_document(result: ValidateResult) -> dict[str, Any]:
    """The `validate --format json` document."""
    ingest = result.ingest
    counters = ingest.counters
    span = ingest.span
    return {
        "envelope": envelope(result.run_id, result.started_us, result.completed_us),
        "kind": "validate",
        "status": "valid" if result.valid else "invalid",
        "exit_code": result.exit_code,
        "input": [i.model_dump(mode="json") for i in ingest.inputs],
        "hosts": list(ingest.hosts),
        "span": None
        if span is None
        else {"from": format_rfc3339(span.start_us), "to": format_rfc3339(span.end_us)},
        "counters": {
            "records_total": counters.records_total,
            "sysmon": counters.sysmon,
            "irrelevant": counters.irrelevant,
            "irrelevant_by_channel": counters.irrelevant_by_channel,
            "invalid": counters.invalid,
            "invalid_by_reason": counters.invalid_by_reason,
            "duplicates_dropped": counters.duplicates_dropped,
            "duplicate_conflicts": counters.duplicate_conflicts,
            "bad_guid": counters.bad_guid,
            "out_of_order": counters.out_of_order,
        },
        "events": ingest.event_count,
        "event_ids_seen": ingest.event_ids_seen,
        "event_ids_missing": list(result.event_ids_missing),
        "readiness": [
            {
                "family": r.family,
                "needs": list(r.needs),
                "mode": r.mode,
                "state": r.state,
                "missing": list(r.missing),
            }
            for r in result.readiness
        ],
        "unknown_keys": ingest.unknown_keys,
        "invalid_records": [r.model_dump(mode="json") for r in ingest.invalid_samples],
        "invalid_records_truncated": len(ingest.invalid_samples) < counters.invalid,
        "record_cap_reached": ingest.record_cap_reached,
        "reasons": list(ingest.reasons),
        "warnings": list(ingest.warnings),
        "errors": [e.model_dump(mode="json") for e in ingest.errors],
    }
