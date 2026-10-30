"""Anchors (§9.1): name AND directory, ghosts by name alone, and anchor_unverified."""

from pathlib import Path

import pytest

from lineage_ir.analyze.anchors import AnchorSet, count_unverified, load_anchors
from lineage_ir.engine import build_host_graphs
from lineage_ir.errors import UsageError
from lineage_ir.ingest.normalize import image_name
from lineage_ir.ingest.reader import read_inputs
from lineage_ir.models import ProcessNode

SECTION_9_1 = {
    "system": ("",),
    "registry": ("",),
    "smss.exe": ("c:\\windows\\system32\\",),
    "csrss.exe": ("c:\\windows\\system32\\",),
    "wininit.exe": ("c:\\windows\\system32\\",),
    "winlogon.exe": ("c:\\windows\\system32\\",),
    "services.exe": ("c:\\windows\\system32\\",),
    "lsass.exe": ("c:\\windows\\system32\\",),
    "svchost.exe": ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\"),
    "userinit.exe": ("c:\\windows\\system32\\",),
    "explorer.exe": ("c:\\windows\\",),
    "wmiprvse.exe": ("c:\\windows\\system32\\wbem\\", "c:\\windows\\syswow64\\wbem\\"),
    "taskhostw.exe": ("c:\\windows\\system32\\",),
    "taskeng.exe": ("c:\\windows\\system32\\",),
    "sihost.exe": ("c:\\windows\\system32\\",),
}


def node(image: str | None, ghost: bool = False) -> ProcessNode:
    return ProcessNode.model_construct(image=image, image_name=image_name(image), is_ghost=ghost)


@pytest.fixture(scope="module")
def anchors() -> AnchorSet:
    return load_anchors()


def test_bundled_table_is_section_9_1(anchors: AnchorSet) -> None:
    assert {a.name: a.paths for a in anchors.anchors} == SECTION_9_1


@pytest.mark.parametrize(
    ("image", "verdict"),
    [
        ("C:\\Windows\\explorer.exe", "verified"),
        ("C:\\WINDOWS\\EXPLORER.EXE", "verified"),
        ("\\\\?\\C:\\Windows\\explorer.exe", "verified"),
        ("C:/Windows/explorer.exe", "verified"),
        ("C:\\Windows\\System32\\svchost.exe", "verified"),
        ("C:\\Windows\\SysWOW64\\svchost.exe", "verified"),
        ("C:\\Windows\\System32\\wbem\\WmiPrvSE.exe", "verified"),
        ("System", "verified"),
        ("C:\\Users\\Public\\svchost.exe", None),
        ("C:\\Windows\\System32\\explorer.exe", None),
        ("C:\\Windows\\System32\\wbem\\x\\wmiprvse.exe", None),
        ("C:\\Windows\\System32\\cmd.exe", None),
        ("explorer.exe", None),
        (None, None),
    ],
)
def test_created_nodes_need_name_and_directory(
    anchors: AnchorSet, image: str | None, verdict: str | None
) -> None:
    assert anchors.verdict(node(image)) == verdict
    assert anchors(node(image)) is (verdict is not None)


def test_ghosts_with_a_bare_name_match_by_name_alone(anchors: AnchorSet) -> None:
    assert anchors.verdict(node("explorer.exe", ghost=True)) == "name_only"
    assert anchors.verdict(node("C:\\Windows\\explorer.exe", ghost=True)) == "verified"
    assert anchors.verdict(node("C:\\Temp\\explorer.exe", ghost=True)) is None
    assert anchors.verdict(node(None, ghost=True)) is None
    assert anchors.verdict(node("evil.exe", ghost=True)) is None


def test_count_unverified(tmp_path: Path) -> None:
    from helpers.chain import Chain

    chain = Chain()
    chain.create(1, "C:\\Tools\\a.exe", parent=90, parent_image="explorer.exe")
    chain.create(2, "C:\\Tools\\b.exe", parent=91, parent_image="services.exe", second=1)
    chain.create(3, "C:\\Tools\\c.exe", parent=92, parent_image="C:\\Windows\\explorer.exe")
    chain.create(4, "C:\\Tools\\d.exe", parent=93, parent_image="tool.exe", second=2)
    graphs = build_host_graphs(read_inputs([chain.write(tmp_path / "in.jsonl")]))
    assert count_unverified(graphs, load_anchors()) == 2


def test_anchor_file_is_validated(tmp_path: Path) -> None:
    good = tmp_path / "good.yaml"
    good.write_text("anchors:\n  - {name: explorer.exe, paths: ['c:\\windows\\']}\n", "utf-8")
    assert [a.name for a in load_anchors(good).anchors] == ["explorer.exe"]
    for text in (
        "anchors:\n  - {name: explorer.exe}\n",
        "anchors:\n  - {name: explorer.exe, paths: ['c:\\windows']}\n",
        "anchors:\n  - {name: Explorer.EXE, paths: ['c:\\windows\\']}\n",
        "anchors:\n  - {name: a.exe, paths: ['']}\n  - {name: a.exe, paths: ['']}\n",
        "anchors: []\nextra: 1\n",
        "anchors:\n  - {name: a.exe, paths: [''], name: b.exe}\n",
    ):
        bad = tmp_path / "bad.yaml"
        bad.write_text(text, "utf-8")
        with pytest.raises(UsageError):
            load_anchors(bad)
