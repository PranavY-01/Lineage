"""Graph heuristics GR-001 to GR-004 (§8.7) with the stub anchor test."""

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from helpers.anchors import stub_is_anchor
from helpers.detection import detect_file
from lineage_ir.detect.graph_rules import GRAPH_RULES, AnchorTest
from lineage_ir.models import ProcessNode

HOST = "ws-14.corp.example"
OFFICE = "C:\\Program Files\\Microsoft Office\\root\\Office16\\"
SYS32 = "C:\\Windows\\System32\\"


def g(tag: int) -> str:
    return f"{{6c1e0a2b-7d3f-4e5a-9b8c-0000000c{tag:04x}}}"


def bare(tag: int) -> str:
    return g(tag).strip("{}")


class Log:
    """Builds a small JSONL log with increasing record IDs."""

    def __init__(self, make_record: Callable[..., dict[str, Any]]) -> None:
        self.make = make_record
        self.rows: list[dict[str, Any]] = []

    def at(self, second: int) -> str:
        return f"2026-10-12 10:{second // 60:02d}:{second % 60:02d}.000"

    def create(
        self, tag: int, image: str, parent: int | None, second: int, parent_image: str = ""
    ) -> None:
        fields: dict[str, Any] = {"ProcessGuid": g(tag), "ProcessId": str(tag), "Image": image}
        if parent is not None:
            fields["ParentProcessGuid"] = g(parent)
            if parent_image:
                fields["ParentImage"] = parent_image
        self.rows.append(self.make(1, len(self.rows) + 1, self.at(second), **fields))

    def event(self, event_id: int, tag: int, second: int, **fields: Any) -> None:
        record = {"ProcessGuid": g(tag), "Image": fields.pop("Image", SYS32 + "x.exe"), **fields}
        self.rows.append(self.make(event_id, len(self.rows) + 1, self.at(second), **record))

    def connect(self, tag: int, second: int, initiated: str = "true") -> None:
        self.event(
            3,
            tag,
            second,
            Protocol="tcp",
            Initiated=initiated,
            DestinationIp="203.0.113.7",
            DestinationPort="443",
        )


def findings(write_jsonl: Callable[..., Path], log: Log, rule_id: str) -> list[Any]:
    return detect_file(write_jsonl(log.rows), ()).by_rule(rule_id)


@pytest.fixture
def log(make_record: Callable[..., dict[str, Any]]) -> Log:
    return Log(make_record)


def test_catalogue() -> None:
    infos = {r.info.id: r.info for r in GRAPH_RULES}
    assert sorted(infos) == ["GR-001", "GR-002", "GR-003", "GR-004"]
    assert infos["GR-001"].event_ids == (1, 3)
    assert infos["GR-002"].event_ids == (1,)
    assert infos["GR-003"].event_ids == (1, 11)
    assert infos["GR-004"].event_ids == (1,)
    assert all(i.kind == "graph" for i in infos.values())
    assert infos["GR-004"].severity == "info" and infos["GR-004"].attack == ()


def test_anchor_alias_accepts_the_stub() -> None:
    anchor: AnchorTest = stub_is_anchor
    assert callable(anchor)


def test_stub_anchor_needs_name_and_directory() -> None:
    def node(image: str | None, ghost: bool = False) -> ProcessNode:
        name = image.replace("/", "\\").rsplit("\\", 1)[-1].lower() if image else None
        return ProcessNode.model_construct(image=image, image_name=name, is_ghost=ghost)

    assert stub_is_anchor(node("C:\\Windows\\explorer.exe"))
    assert stub_is_anchor(node("C:\\Windows\\SysWOW64\\svchost.exe"))
    assert not stub_is_anchor(node("C:\\Users\\Public\\explorer.exe"))
    assert not stub_is_anchor(node("C:\\Windows\\System32\\explorer.exe"))
    assert stub_is_anchor(node("explorer.exe", ghost=True))
    assert not stub_is_anchor(node("explorer.exe", ghost=False))
    assert not stub_is_anchor(node(None, ghost=True))


# GR-001


def test_gr001_office_descendant_connecting_out(write_jsonl: Callable[..., Path], log: Log) -> None:
    log.create(1, "C:\\Windows\\explorer.exe", None, 0)
    log.create(2, OFFICE + "WINWORD.EXE", 1, 1)
    log.create(3, SYS32 + "cmd.exe", 2, 2)
    log.create(4, SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe", 3, 3)
    log.connect(4, 4)
    log.connect(4, 5)
    (finding,) = findings(write_jsonl, log, "GR-001")
    assert finding.guid == bare(4)
    assert finding.count == 2
    assert finding.details["office_ancestor"] == "winword.exe"
    assert finding.details["destination"] == "203.0.113.7:443/tcp"


def test_gr001_stops_at_the_first_anchor(write_jsonl: Callable[..., Path], log: Log) -> None:
    log.create(1, OFFICE + "WINWORD.EXE", None, 0)
    log.create(2, "C:\\Windows\\explorer.exe", 1, 1)
    log.create(3, SYS32 + "cmd.exe", 2, 2)
    log.connect(3, 3)
    assert findings(write_jsonl, log, "GR-001") == []


def test_gr001_walks_through_a_same_named_binary_elsewhere(
    write_jsonl: Callable[..., Path], log: Log
) -> None:
    log.create(1, OFFICE + "EXCEL.EXE", None, 0)
    log.create(2, "C:\\Users\\Public\\explorer.exe", 1, 1)
    log.create(3, SYS32 + "cmd.exe", 2, 2)
    log.connect(3, 3)
    (finding,) = findings(write_jsonl, log, "GR-001")
    assert finding.guid == bare(3)
    assert finding.details["office_ancestor"] == "excel.exe"


def test_gr001_ghost_ancestors(write_jsonl: Callable[..., Path], log: Log) -> None:
    # Parent 10 is never created: a ghost seeded with the Office image from the child record.
    log.create(11, SYS32 + "cmd.exe", 10, 0, parent_image=OFFICE + "OUTLOOK.EXE")
    log.connect(11, 1)
    # Parent 20 is a ghost with no image at all: the walk ends there without a hit.
    log.create(21, SYS32 + "cmd.exe", 20, 2)
    log.connect(21, 3)
    run_findings = findings(write_jsonl, log, "GR-001")
    assert [f.guid for f in run_findings] == [bare(11)]


def test_gr001_needs_initiated_connection_and_a_real_ancestor(
    write_jsonl: Callable[..., Path], log: Log
) -> None:
    log.create(1, OFFICE + "WINWORD.EXE", None, 0)
    log.create(2, SYS32 + "cmd.exe", 1, 1)
    log.connect(2, 2, initiated="false")
    # The Office process itself connecting out has no Office ancestor.
    log.connect(1, 3)
    assert findings(write_jsonl, log, "GR-001") == []


# GR-002


@pytest.mark.parametrize(("last_second", "fires"), [(120, True), (121, False)])
def test_gr002_window(
    write_jsonl: Callable[..., Path], log: Log, last_second: int, fires: bool
) -> None:
    log.create(1, SYS32 + "cmd.exe", None, 0)
    log.create(2, SYS32 + "whoami.exe", 1, 0)
    log.create(3, SYS32 + "systeminfo.exe", 1, 60)
    log.create(4, SYS32 + "ipconfig.exe", 1, last_second)
    found = findings(write_jsonl, log, "GR-002")
    if not fires:
        assert found == []
        return
    (finding,) = found
    assert finding.guid == bare(1)
    assert finding.details["binaries"] == "ipconfig.exe, systeminfo.exe, whoami.exe"
    assert finding.count == 3


def test_gr002_attaches_to_a_ghost_parent(write_jsonl: Callable[..., Path], log: Log) -> None:
    for tag, name in ((2, "whoami.exe"), (3, "nltest.exe"), (4, "net.exe")):
        log.create(tag, SYS32 + name, 1, tag)
    (finding,) = findings(write_jsonl, log, "GR-002")
    assert finding.guid == bare(1)
    assert detect_file(write_jsonl(log.rows), ()).graphs[HOST].nodes[bare(1)].is_ghost


def test_gr002_needs_three_distinct_binaries(write_jsonl: Callable[..., Path], log: Log) -> None:
    log.create(1, SYS32 + "cmd.exe", None, 0)
    for tag in (2, 3, 4):
        log.create(tag, SYS32 + "whoami.exe", 1, tag)
    log.create(5, SYS32 + "notepad.exe", 1, 6)
    log.create(6, SYS32 + "ipconfig.exe", 1, 7)
    assert findings(write_jsonl, log, "GR-002") == []


# GR-003


def test_gr003_dropped_file_later_executed(write_jsonl: Callable[..., Path], log: Log) -> None:
    log.create(1, SYS32 + "cmd.exe", None, 0)
    log.event(11, 1, 1, Image=SYS32 + "cmd.exe", TargetFilename="C:\\Users\\Public\\Drop.exe")
    log.create(2, "c:/users/public/DROP.EXE", 1, 2)
    (finding,) = findings(write_jsonl, log, "GR-003")
    assert finding.guid == bare(2)
    assert finding.details["creator_guid"] == bare(1)
    assert finding.details["creator_image"] == SYS32 + "cmd.exe"
    assert len(finding.evidence) == 2


def test_gr003_ignores_earlier_runs_streams_and_other_hosts(
    write_jsonl: Callable[..., Path], log: Log
) -> None:
    log.create(2, "C:\\Users\\Public\\early.exe", None, 0)
    log.event(11, 2, 1, TargetFilename="C:\\Users\\Public\\early.exe")
    log.event(15, 2, 2, TargetFilename="C:\\Users\\Public\\stream.exe")
    log.create(3, "C:\\Users\\Public\\stream.exe", None, 3)
    log.event(11, 2, 4, TargetFilename="C:\\Users\\Public\\remote.exe")
    other = log.make(
        1,
        99,
        log.at(5),
        host="ws-15.corp.example",
        ProcessGuid=g(4),
        Image="C:\\Users\\Public\\remote.exe",
    )
    log.rows.append(other)
    assert findings(write_jsonl, log, "GR-003") == []


# GR-004


def test_gr004_active_ghost(write_jsonl: Callable[..., Path], log: Log) -> None:
    log.connect(1, 0)
    log.event(11, 2, 1, TargetFilename="C:\\Temp\\a.txt")
    found = findings(write_jsonl, log, "GR-004")
    assert sorted(f.guid for f in found) == [bare(1), bare(2)]
    assert all(f.severity == "info" for f in found)


def test_gr004_ignores_file_stream_other_and_parent_ghosts(
    write_jsonl: Callable[..., Path], log: Log
) -> None:
    log.event(15, 1, 0, TargetFilename="C:\\Temp\\a.txt:Zone.Identifier")
    log.event(255, 2, 1)
    # Ghost 3 is first seen as a parent, so its reason stays parent_reference.
    log.create(4, SYS32 + "cmd.exe", 3, 2)
    log.connect(3, 3)
    run = detect_file(write_jsonl(log.rows), ())
    kinds = {a.kind for n in run.graphs[HOST].nodes.values() for a in n.activity}
    assert {"file_stream", "other", "network"} <= kinds
    assert run.by_rule("GR-004") == []
