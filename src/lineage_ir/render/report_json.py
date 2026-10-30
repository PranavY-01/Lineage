"""Builders for the 7d7b-report envelope and the JSON documents printed by the CLI (§12.3).

JSON outputs keep raw values (no defanging); ``ensure_ascii`` escapes everything else.
"""

import json
from collections.abc import Mapping, Sequence
from typing import Any

from lineage_ir import __version__
from lineage_ir.analyze.filters import SEVERITY_RANK, AnalysisParams
from lineage_ir.config import ATTACK_VERSION, REPORT_ERRORS_CAP, TIMESTAMP_SOURCE
from lineage_ir.detect.engine import HOST_NODE_PREFIX
from lineage_ir.engine import AnalysisResult
from lineage_ir.graph.model import ProcessGraph
from lineage_ir.ingest.timeparse import format_rfc3339
from lineage_ir.models import (
    Activity,
    Coverage,
    Finding,
    ImageLoad,
    ProcessNode,
    RuleInfo,
    SourceRef,
    Storyline,
    ValidateResult,
)

ENVELOPE_SCHEMA = "7d7b-report"
# Same key names and schema_version as the AuthWatch sample report.
ENVELOPE_SCHEMA_VERSION = 1
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


def _time(ts_us: int | None) -> str | None:
    return None if ts_us is None else format_rfc3339(ts_us)


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


def rules_document(
    rules: Sequence[RuleInfo], run_id: str, started_us: int, completed_us: int
) -> dict[str, Any]:
    """The `rules --format json` document: the envelope plus one entry per rule, sorted by ID."""
    return {
        "envelope": envelope(run_id, started_us, completed_us),
        "kind": "rules",
        "rules": [
            {
                "id": r.id,
                "kind": r.kind,
                "title": r.title,
                "severity": r.severity,
                "event_ids": list(r.event_ids),
                "attack": list(r.attack),
                "tactics": list(r.tactics),
            }
            for r in sorted(rules, key=lambda r: r.id)
        ],
    }


def source_ref(source: SourceRef) -> dict[str, Any]:
    """An evidence reference as reports print it: file, index and record ID."""
    return {"file": source.file, "index": source.index, "record_id": source.record_id}


def parameters(
    params: AnalysisParams, rule_set_sha256: str, storyline: int | None = None
) -> dict[str, Any]:
    """Resolved options, display filters included (amendment 16)."""
    since, until = params.window_us
    return {
        "hosts": list(params.hosts),
        "rules": params.rules if params.rules is not None else "all",
        "min_severity": params.min_severity,
        "since": _time(since),
        "until": _time(until),
        "focus": params.focus,
        "gap_seconds": params.gap_seconds,
        "telemetry_gap_seconds": params.telemetry_gap_seconds,
        "max_records": params.max_records,
        "timestamp_source": TIMESTAMP_SOURCE,
        "rule_set_sha256": rule_set_sha256,
        "attack_version": ATTACK_VERSION,
        "around": params.around,
        "window": params.window if params.around is not None else None,
        "hot_only": params.hot_only,
        "storyline": storyline,
        "max_steps": params.max_steps,
        "max_file_size_mb": params.max_file_size_mb,
    }


def coverage_document(coverage: Coverage) -> dict[str, Any]:
    """Section 10.1 with times as RFC 3339."""
    timeline = coverage.timeline
    span = timeline.span
    return {
        "complete": coverage.complete,
        "reasons": list(coverage.reasons),
        "counters": coverage.counters.model_dump(mode="json"),
        "event_ids_seen": coverage.event_ids_seen,
        "event_ids_missing": list(coverage.event_ids_missing),
        "rules": {
            rule_id: state.model_dump(mode="json") for rule_id, state in coverage.rules.items()
        },
        "hosts": list(coverage.hosts),
        "timeline": {
            "span": None
            if span is None
            else {"from": format_rfc3339(span.start_us), "to": format_rfc3339(span.end_us)},
            "gaps": [
                {
                    "host": g.host,
                    "from": format_rfc3339(g.from_us),
                    "to": format_rfc3339(g.to_us),
                    "seconds": g.seconds,
                }
                for g in timeline.gaps
            ],
            "out_of_order": timeline.out_of_order,
        },
    }


def _summary(result: AnalysisResult) -> dict[str, Any]:
    by_severity = dict.fromkeys(SEVERITY_RANK, 0)
    for finding in result.findings:
        by_severity[finding.severity] += 1
    states = [r.state for r in result.coverage.rules.values()]
    return {
        "hosts": len(result.hosts),
        "events": sum(result.coverage.event_ids_seen.values()),
        "nodes": sum(len(g.nodes) for g in result.graphs.values()),
        "ghosts": sum(result.coverage.counters.ghosts.values()),
        "findings_total": len(result.findings),
        "findings_by_severity": by_severity,
        "storylines": len(result.storylines),
        "rules_evaluable": states.count("evaluable"),
        "rules_not_evaluable": states.count("not_evaluable"),
    }


def storyline_of(storylines: Sequence[Storyline]) -> dict[str, str]:
    """Finding ID → the ID of the storyline holding it."""
    return {fid: s.storyline_id for s in storylines for fid in s.finding_ids}


def _subject(finding: Finding) -> str:
    if finding.guid.startswith(HOST_NODE_PREFIX):
        return finding.guid
    return f"process:{finding.host}/{finding.guid}"


def finding_document(finding: Finding, storyline: str | None) -> dict[str, Any]:
    """One finding in the series shape: event, category, subject and details."""
    details: dict[str, Any] = {
        "finding_id": finding.finding_id,
        "title": finding.title,
        "severity": finding.severity,
        "attack": list(finding.attack),
        "tactics": list(finding.tactics),
        "why": finding.why,
        "image_name": finding.image_name,
        "first_seen": format_rfc3339(finding.first_us),
        "last_seen": format_rfc3339(finding.last_us),
        "count": finding.count,
        "storyline": storyline,
        "evidence": [source_ref(e) for e in finding.evidence],
        "evidence_truncated": finding.evidence_truncated,
    }
    for key, value in finding.details.items():
        details.setdefault(key, value)
    return {
        "event": finding.rule_id,
        "category": "detection",
        "subject": _subject(finding),
        "details": details,
    }


def storyline_document(story: Storyline) -> dict[str, Any]:
    """Section 5.6 with steps and scope, times as RFC 3339."""
    return {
        "storyline_id": story.storyline_id,
        "host": story.host,
        "root_guid": story.root_guid,
        "root_image_name": story.root_image_name,
        "anchor_image_name": story.anchor_image_name,
        "flagged": list(story.flagged),
        "path_nodes": list(story.path_nodes),
        "descendant_nodes": list(story.descendant_nodes),
        "nodes": list(story.nodes),
        "finding_ids": list(story.finding_ids),
        "max_severity": story.max_severity,
        "tactics": list(story.tactics),
        "users": list(story.users),
        "start": format_rfc3339(story.start_us),
        "end": format_rfc3339(story.end_us),
        "steps": [
            {
                "n": s.n,
                "time": format_rfc3339(s.ts_us),
                "tactic": s.tactic,
                "technique": s.technique,
                "guid": s.guid,
                "image_name": s.image_name,
                "action": s.action,
                "text": s.text,
                "severity": s.severity,
                "source": source_ref(s.source),
            }
            for s in story.steps
        ],
        "gaps": [g.model_dump(mode="json") for g in story.gaps],
        "scope": story.scope.model_dump(mode="json"),
        "links": [
            {
                "from_storyline": link.from_storyline,
                "to_storyline": link.to_storyline,
                "kind": link.kind,
                "match": link.match,
                "path": link.path,
                "evidence": [source_ref(e) for e in link.evidence],
            }
            for link in story.links
        ],
    }


def report_document(
    result: AnalysisResult, rule_set_sha256: str, storyline: int | None = None
) -> dict[str, Any]:
    """The full 7d7b report for `analyze --report` and `--format json` (§12.3).

    The report always holds the whole analysis; display filters only appear under
    ``parameters`` (amendment 16).
    """
    owners = storyline_of(result.storylines)
    errors = result.errors[:REPORT_ERRORS_CAP]
    return {
        "envelope": envelope(result.run_id, result.started_us, result.completed_us),
        "status": result.status,
        "result": result.result,
        "input": [i.model_dump(mode="json") for i in result.inputs],
        "parameters": parameters(result.parameters, rule_set_sha256, storyline),
        "coverage": coverage_document(result.coverage),
        "summary": _summary(result),
        "findings": [finding_document(f, owners.get(f.finding_id)) for f in result.findings],
        "storylines": [storyline_document(s) for s in result.storylines],
        "errors": [e.model_dump(mode="json") for e in errors],
        "errors_truncated": len(errors) < len(result.errors),
    }


def _activity(activity: Activity) -> dict[str, Any]:
    return {
        "kind": activity.kind,
        "event_id": activity.event_id,
        "time": format_rfc3339(activity.ts_us),
        "role": activity.role,
        "summary": activity.summary,
        "fields": activity.fields,
        "source": source_ref(activity.source),
    }


def _image_load(load: ImageLoad) -> dict[str, Any]:
    return {
        "time": format_rfc3339(load.ts_us),
        "image_loaded": load.image_loaded,
        "signed": load.signed,
        "source": source_ref(load.source),
    }


def _activity_by_kind(node: ProcessNode, cap: int) -> dict[str, Any]:
    groups: dict[str, list[Activity]] = {}
    for activity in node.activity:
        groups.setdefault(activity.kind, []).append(activity)
    result: dict[str, Any] = {
        kind: {"total": len(items), "items": [_activity(a) for a in items[:cap]]}
        for kind, items in sorted(groups.items())
    }
    if node.image_load_count:
        result["image_load"] = {
            "total": node.image_load_count,
            "items": [_image_load(load) for load in node.image_loads[:cap]],
        }
    return result


def node_document(node: ProcessNode) -> dict[str, Any]:
    """Identity, command line and ghost state of one process node."""
    return {
        "host": node.host,
        "guid": node.guid,
        "pid": node.pid,
        "image": node.image,
        "image_name": node.image_name,
        "command_line": node.command_line,
        "decoded_command": node.decoded_command,
        "decode_note": node.decode_note,
        "user": node.user,
        "integrity_level": node.integrity_level,
        "hashes": node.hashes,
        "current_directory": node.current_directory,
        "logon_id": node.logon_id,
        "start": _time(node.start_us),
        "end": _time(node.end_us),
        "parent_guid": node.parent_guid,
        "is_ghost": node.is_ghost,
        "ghost_reason": node.ghost_reason,
        "create_record": None if node.create_record is None else source_ref(node.create_record),
    }


def inspect_document(
    result: AnalysisResult,
    host: str,
    guid: str,
    ancestry: Sequence[tuple[str, bool]],
    items_per_kind: int,
) -> dict[str, Any]:
    """The `inspect --format json` document; ``ancestry`` is (guid, is_anchor) nearest-first."""
    graph: ProcessGraph = result.graphs[host]
    node = graph.nodes[guid]
    owners = storyline_of(result.storylines)
    findings = [f for f in result.findings if f.host == host and f.guid == guid]
    member_of = [s.storyline_id for s in result.storylines if s.host == host and guid in s.nodes]

    def brief(other: str, anchor: bool | None = None) -> Mapping[str, Any]:
        item = graph.nodes[other]
        entry: dict[str, Any] = {
            "guid": other,
            "image_name": item.image_name,
            "pid": item.pid,
            "start": _time(item.start_us),
            "is_ghost": item.is_ghost,
        }
        if anchor is not None:
            entry["anchor"] = anchor
        return entry

    return {
        "envelope": envelope(result.run_id, result.started_us, result.completed_us),
        "kind": "inspect",
        "node": node_document(node),
        "ancestry": [brief(g, anchor) for g, anchor in ancestry],
        "children": [brief(c) for c in node.children],
        "activity": _activity_by_kind(node, items_per_kind),
        "findings": [finding_document(f, owners.get(f.finding_id)) for f in findings],
        "storylines": member_of,
    }
