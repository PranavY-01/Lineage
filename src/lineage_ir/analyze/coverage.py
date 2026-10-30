"""Coverage, reason codes, rule evaluability and status (§10).

Any reason makes the run incomplete (exit 4), so silence is never mistaken for a clean host.
Informational signals (ghosts, gaps, out-of-order records, anchor_unverified, unattached
events, several hosts, irrelevant records) never become reasons.
"""

from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Literal

from lineage_ir.analyze.anchors import AnchorSet, count_unverified
from lineage_ir.analyze.gaps import telemetry_gaps
from lineage_ir.config import STANDARD_EVENT_IDS
from lineage_ir.detect.engine import HOST_NODE_PREFIX, DetectionResult
from lineage_ir.detect.graph_rules import GraphRule
from lineage_ir.detect.schema import Rule
from lineage_ir.graph.model import ProcessGraph
from lineage_ir.models import (
    Coverage,
    CoverageCounters,
    Finding,
    IngestResult,
    RuleCoverage,
    Timeline,
)

Result = Literal["no_findings", "findings_detected"]
Status = Literal["no_findings", "findings_detected", "incomplete"]


def _event_rule_state(rule: Rule, seen: set[int]) -> tuple[str, tuple[int, ...]]:
    missing: set[int] = set()
    evaluable = 0
    for group in rule.groups:
        if any(i in seen for i in group.event_ids):
            evaluable += 1
        else:
            missing.update(group.event_ids)
    if evaluable == len(rule.groups):
        return "evaluable", ()
    state = "partially_evaluable" if evaluable else "not_evaluable"
    return state, tuple(sorted(missing))


def _graph_rule_state(rule: GraphRule, seen: set[int]) -> tuple[str, tuple[int, ...]]:
    # A graph heuristic is evaluable only when every required event ID is present (§10.3).
    missing = tuple(i for i in rule.info.event_ids if i not in seen)
    return ("not_evaluable" if missing else "evaluable"), missing


def build_coverage(
    ingest: IngestResult,
    graphs: Mapping[str, ProcessGraph],
    detection: DetectionResult,
    findings: Sequence[Finding],
    rules: Sequence[Rule],
    graph_rules: Sequence[GraphRule],
    anchors: AnchorSet,
    telemetry_gap_seconds: int,
) -> Coverage:
    """Merge counters from every stage and derive the reason codes for the enabled rules."""
    seen = {int(k) for k, count in ingest.event_ids_seen.items() if count > 0}
    per_rule = Counter(f.rule_id for f in findings)
    states = {r.id: _event_rule_state(r, seen) for r in rules if r.enabled}
    states |= {g.info.id: _graph_rule_state(g, seen) for g in graph_rules}
    rules_coverage = {
        rule_id: RuleCoverage(
            state=state,  # type: ignore[arg-type]
            missing_event_ids=missing,
            events_examined=detection.events_examined.get(rule_id, 0),
            findings=per_rule[rule_id],
        )
        for rule_id, (state, missing) in sorted(states.items())
    }

    counters = ingest.counters
    ghosts: Counter[str] = Counter()
    for graph in graphs.values():
        ghosts.update(graph.counters.ghosts)
    conflicts = counters.duplicate_conflicts + sum(
        g.counters.creation_conflicts for g in graphs.values()
    )
    cycles = sum(g.counters.cycles_broken for g in graphs.values())

    reasons = set()
    if ingest.event_count == 0:
        reasons.add("no_events")
    if counters.invalid:
        reasons.add("invalid_records")
    if conflicts:
        reasons.add("duplicate_conflicts")
    if cycles:
        reasons.add("cycles_broken")
    if ingest.record_cap_reached:
        reasons.add("record_cap_reached")
    for rule_id, coverage in rules_coverage.items():
        if coverage.state != "evaluable":
            reasons.add(f"{coverage.state}:{rule_id}")

    return Coverage(
        complete=not reasons,
        reasons=tuple(sorted(reasons)),
        counters=CoverageCounters(
            records_total=counters.records_total,
            sysmon=counters.sysmon,
            irrelevant=counters.irrelevant,
            invalid=counters.invalid,
            invalid_by_reason=counters.invalid_by_reason,
            duplicates_dropped=counters.duplicates_dropped,
            duplicate_conflicts=conflicts,
            bad_guid=counters.bad_guid,
            ghosts=dict(sorted(ghosts.items())),
            cycles_broken=cycles,
            unattached_events=sum(g.counters.unattached_events for g in graphs.values()),
            unattached_findings=sum(1 for f in findings if f.guid.startswith(HOST_NODE_PREFIX)),
            anchor_unverified=count_unverified(graphs, anchors),
        ),
        event_ids_seen=ingest.event_ids_seen,
        event_ids_missing=tuple(i for i in STANDARD_EVENT_IDS if i not in seen),
        rules=rules_coverage,
        hosts=ingest.hosts,
        timeline=Timeline(
            span=ingest.span,
            gaps=telemetry_gaps(ingest, telemetry_gap_seconds),
            out_of_order=counters.out_of_order,
        ),
    )


def outcome(findings: Sequence[Finding], coverage: Coverage) -> tuple[Result, Status, int]:
    """(result, status, exit code) by the §10.4 table."""
    result: Result = "findings_detected" if findings else "no_findings"
    if not coverage.complete:
        return result, "incomplete", 4
    return result, result, 1 if findings else 0
