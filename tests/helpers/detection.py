"""Run ingest, graph and detection on a file the way the engine does, with the stub anchors."""

from dataclasses import dataclass
from pathlib import Path

from helpers.anchors import stub_is_anchor
from lineage_ir.detect.engine import DetectionResult, run_detection
from lineage_ir.detect.loader import load_rules
from lineage_ir.detect.schema import Rule
from lineage_ir.engine import build_host_graphs
from lineage_ir.graph.model import ProcessGraph
from lineage_ir.ingest.reader import read_inputs
from lineage_ir.models import Finding, IngestResult


@dataclass(frozen=True)
class Run:
    ingest: IngestResult
    graphs: dict[str, ProcessGraph]
    detection: DetectionResult

    def by_rule(self, rule_id: str) -> list[Finding]:
        return [f for f in self.detection.findings if f.rule_id == rule_id]


def detect_file(path: Path, rules: tuple[Rule, ...] | None = None) -> Run:
    ingest = read_inputs([path])
    graphs = build_host_graphs(ingest)
    selected = load_rules() if rules is None else rules
    detection = run_detection(ingest, graphs, selected, is_anchor=stub_is_anchor)
    return Run(ingest, graphs, detection)
