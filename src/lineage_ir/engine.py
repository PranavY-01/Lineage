"""Library entry points; the CLI calls these and hands the results to a renderer."""

import time
import uuid
from collections.abc import Callable, Sequence
from pathlib import Path

from lineage_ir.analyze.anchors import load_anchors
from lineage_ir.analyze.coverage import Result, Status, build_coverage, outcome
from lineage_ir.analyze.decode import decode_command
from lineage_ir.analyze.filters import AnalysisParams, keep_by_severity, select_rules
from lineage_ir.analyze.focus import resolve_focus
from lineage_ir.analyze.persistence_links import attach_links
from lineage_ir.analyze.storyline import build_storylines
from lineage_ir.config import READINESS_FAMILIES, STANDARD_EVENT_IDS
from lineage_ir.detect.engine import run_detection
from lineage_ir.detect.graph_rules import GRAPH_RULES
from lineage_ir.detect.loader import load_rules, rule_set_digest
from lineage_ir.graph.builder import build_graphs
from lineage_ir.graph.model import ProcessGraph
from lineage_ir.ingest.reader import IngestOptions, read_inputs
from lineage_ir.models import (
    Coverage,
    ErrorEntry,
    Finding,
    FrozenModel,
    IngestResult,
    InputFile,
    Readiness,
    RuleInfo,
    Storyline,
    ValidateResult,
)

__all__ = ["AnalysisParams", "AnalysisResult", "run_analysis", "run_validate"]

Clock = Callable[[], int]
RunIdFactory = Callable[[], str]


def now_us() -> int:
    """Current wall-clock time in microseconds since the Unix epoch."""
    return time.time_ns() // 1000


def new_run_id() -> str:
    """A fresh UUID4 run identifier."""
    return str(uuid.uuid4())


def readiness(event_ids_seen: dict[str, int]) -> tuple[Readiness, ...]:
    """Readiness of each rule family given the event IDs present (§11.2)."""
    present = {int(k) for k, count in event_ids_seen.items() if count > 0}
    result = []
    for family, needs, mode in READINESS_FAMILIES:
        missing = tuple(i for i in needs if i not in present)
        have = len(needs) - len(missing)
        if not missing or (mode == "any" and have):
            state = "ready"
        elif have:
            state = "partial"
        else:
            state = "missing"
        result.append(
            Readiness(family=family, needs=needs, mode=mode, state=state, missing=missing)
        )
    return tuple(result)


def validate_exit_code(ingest: IngestResult) -> int:
    """0 when every record was read and valid and Sysmon events exist, else 4 (§10.5)."""
    clean = (
        ingest.counters.invalid == 0 and ingest.event_count > 0 and not ingest.record_cap_reached
    )
    return 0 if clean else 4


def run_validate(
    inputs: Sequence[Path],
    options: IngestOptions | None = None,
    *,
    clock: Clock = now_us,
    run_id_factory: RunIdFactory = new_run_id,
) -> ValidateResult:
    """Read and normalize inputs without building a graph or running rules."""
    run_id = run_id_factory()
    started = clock()
    ingest = read_inputs(inputs, options)
    seen = {int(k) for k in ingest.event_ids_seen}
    exit_code = validate_exit_code(ingest)
    return ValidateResult(
        ingest=ingest,
        event_ids_missing=tuple(i for i in STANDARD_EVENT_IDS if i not in seen),
        readiness=readiness(ingest.event_ids_seen),
        valid=exit_code == 0,
        exit_code=exit_code,
        started_us=started,
        completed_us=clock(),
        run_id=run_id,
    )


def build_host_graphs(ingest: IngestResult) -> dict[str, ProcessGraph]:
    """Per-host graphs with PowerShell decoding applied as nodes are frozen (§4.3 step 6).

    The decoder lives in ``analyze``; passing it in keeps graph code from importing upward.
    """
    return build_graphs(ingest.events, ingest.image_loads, decode=decode_command)


def rule_set_sha256() -> str:
    """Digest of the bundled rule files, recorded in report parameters (§12.3)."""
    return rule_set_digest()


def list_rules() -> tuple[RuleInfo, ...]:
    """Every bundled event rule and graph heuristic, sorted by ID (§11.2 `rules`)."""
    infos = [rule.info for rule in load_rules()] + [rule.info for rule in GRAPH_RULES]
    return tuple(sorted(infos, key=lambda info: info.id))


class AnalysisResult(FrozenModel):
    """Everything one analysis produced (§5.8); renderers only format it.

    It lives here rather than in models.py because it holds per-host ProcessGraphs, and
    models.py sits below the graph layer. ``result``, ``status`` and ``exit_code`` are
    derived from findings and coverage by the §10.4 table.
    """

    inputs: tuple[InputFile, ...]
    parameters: AnalysisParams
    hosts: tuple[str, ...]
    graphs: dict[str, ProcessGraph]
    findings: tuple[Finding, ...]
    storylines: tuple[Storyline, ...]
    coverage: Coverage
    errors: tuple[ErrorEntry, ...]
    started_us: int
    completed_us: int
    run_id: str

    @property
    def result(self) -> Result:
        return outcome(self.findings, self.coverage)[0]

    @property
    def status(self) -> Status:
        return outcome(self.findings, self.coverage)[1]

    @property
    def exit_code(self) -> int:
        return outcome(self.findings, self.coverage)[2]


def run_analysis(
    inputs: Sequence[Path],
    params: AnalysisParams | None = None,
    *,
    clock: Clock = now_us,
    run_id_factory: RunIdFactory = new_run_id,
) -> AnalysisResult:
    """The full run: ingest, graphs, detection, storylines and coverage (§4.3).

    ``--rules`` and ``--min-severity`` decide what counts as flagged. The display filters in
    ``params`` (time window, focus) are validated here but never change the result.
    """
    params = params or AnalysisParams()
    run_id = run_id_factory()
    started = clock()
    rules, graph_rules = select_rules(load_rules(), GRAPH_RULES, params.rules)
    anchors = load_anchors()
    options = IngestOptions(
        max_records=params.max_records,
        max_file_size_mb=params.max_file_size_mb,
        hosts=frozenset(params.hosts),
    )
    ingest = read_inputs(inputs, options)
    graphs = build_host_graphs(ingest)
    if params.focus is not None:
        resolve_focus(graphs, params.focus)
    detection = run_detection(ingest, graphs, rules, is_anchor=anchors, graph_rules=graph_rules)
    findings = keep_by_severity(detection.findings, params.min_severity)
    storylines = build_storylines(ingest, graphs, findings, anchors, params.gap_seconds)
    storylines = attach_links(storylines, graphs, findings, ingest.events)
    coverage = build_coverage(
        ingest,
        graphs,
        detection,
        findings,
        rules,
        graph_rules,
        anchors,
        params.telemetry_gap_seconds,
    )
    return AnalysisResult(
        inputs=ingest.inputs,
        parameters=params,
        hosts=ingest.hosts,
        graphs=graphs,
        findings=findings,
        storylines=storylines,
        coverage=coverage,
        errors=ingest.errors,
        started_us=started,
        completed_us=clock(),
        run_id=run_id,
    )
