"""Persistence and drop links between storylines (§9.8, stretch S1)."""

from pathlib import Path

import pytest

from helpers.chain import EXPLORER, HOST, SYS32, Chain, guid
from helpers.reports import FIXTURES, frozen_analysis
from lineage_ir.analyze.persistence_links import (
    LinkTarget,
    extract_target,
    sc_binpath_target,
    schtasks_target,
)
from lineage_ir.engine import AnalysisResult
from lineage_ir.ingest.timeparse import format_rfc3339
from lineage_ir.models import Storyline

PUBLIC = "C:\\Users\\Public\\"
RUN_KEY = "HKU\\S-1-5-21-1-2-3-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"
OTHER_HOST = "ws-15.corp.example"


# Path extraction (§9.8 "Path extraction").


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("C:\\Users\\Public\\upd.exe", LinkTarget("c:\\users\\public\\upd.exe", "exact")),
        (
            '"C:\\Program Files\\App\\app.exe" --silent',
            LinkTarget("c:\\program files\\app\\app.exe", "exact"),
        ),
        (
            "C:\\Users\\Public\\upd.exe -k netsvcs",
            LinkTarget("c:\\users\\public\\upd.exe", "exact"),
        ),
        ("C:/Users/Public/UPD.EXE", LinkTarget("c:\\users\\public\\upd.exe", "exact")),
        ("C:\\Tools\\run.bat now", LinkTarget("c:\\tools\\run.bat", "exact")),
        ("C:\\Tools\\a.ps1", LinkTarget("c:\\tools\\a.ps1", "exact")),
        ("C:\\Tools\\b.vbs", LinkTarget("c:\\tools\\b.vbs", "exact")),
        ("C:\\Tools\\c.hta", LinkTarget("c:\\tools\\c.hta", "exact")),
        ("C:\\Tools\\d.cmd", LinkTarget("c:\\tools\\d.cmd", "exact")),
        ("C:\\Tools\\e.js", LinkTarget("c:\\tools\\e.js", "exact")),
        (
            "C:\\Tools\\config.json C:\\Tools\\real.exe",
            LinkTarget("c:\\tools\\config.json c:\\tools\\real.exe", "exact"),
        ),
        ("%SystemRoot%\\Temp\\svc.exe", LinkTarget("c:\\windows\\temp\\svc.exe", "exact")),
        ("%windir%\\x.exe", LinkTarget("c:\\windows\\x.exe", "exact")),
        ("%ProgramData%\\svc\\svc.exe", LinkTarget("c:\\programdata\\svc\\svc.exe", "exact")),
        ("%PUBLIC%\\upd.exe", LinkTarget("c:\\users\\public\\upd.exe", "exact")),
        ("%APPDATA%\\Microsoft\\upd.exe", LinkTarget("\\microsoft\\upd.exe", "suffix")),
        ("%LocalAppData%\\Temp\\x.exe", LinkTarget("\\temp\\x.exe", "suffix")),
        ("%TEMP%\\x.exe", LinkTarget("\\x.exe", "suffix")),
        ('"%USERPROFILE%\\Downloads\\y.exe" /q', LinkTarget("\\downloads\\y.exe", "suffix")),
        (
            "rundll32.exe C:\\Users\\Public\\a.dll,Start",
            LinkTarget("c:\\users\\public\\a.dll", "exact"),
        ),
        (
            '"C:\\Windows\\System32\\rundll32.exe" "C:\\Users\\Public\\b.dll",Run',
            LinkTarget("c:\\users\\public\\b.dll", "exact"),
        ),
        (
            "powershell.exe -nop -w hidden -File C:\\Users\\Public\\s.ps1",
            LinkTarget("c:\\users\\public\\s.ps1", "exact"),
        ),
        ("cmd.exe /c C:\\Users\\Public\\go.bat", LinkTarget("c:\\users\\public\\go.bat", "exact")),
        # The DLL argument has no extension, so only the ",Entry" cut ends the path.
        (
            "rundll32.exe C:\\Users\\Public\\payload,Start",
            LinkTarget("c:\\users\\public\\payload", "exact"),
        ),
        # No separator after the variable: the suffix is kept exactly as written.
        ("%TEMP%x.exe", LinkTarget("x.exe", "suffix")),
        ("wscript.exe //B %APPDATA%\\x.vbs", LinkTarget("\\x.vbs", "suffix")),
        ("mshta.exe C:\\Users\\Public\\p.hta", LinkTarget("c:\\users\\public\\p.hta", "exact")),
        (
            "regsvr32.exe /s C:\\Users\\Public\\r.dll",
            LinkTarget("c:\\users\\public\\r.dll", "exact"),
        ),
    ],
)
def test_extract_target(value: str, expected: LinkTarget) -> None:
    assert extract_target(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "%HOMEDRIVE%\\x.exe",  # not one of the listed variables
        "C:\\Tools\\no-extension",
        "upd.exe",  # relative: nothing to anchor an exact match to
        "rundll32.exe",  # a host program with no path argument
        "cmd.exe /c echo hi",
    ],
)
def test_no_target(value: str) -> None:
    assert extract_target(value) is None


def test_extension_needs_a_boundary() -> None:
    # ".js" inside ".json" is not an extension; the later ".exe" is.
    assert extract_target("C:\\a.json") is None


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        (
            'schtasks /create /tn Updater /tr "C:\\Users\\Public\\upd.exe --run" /sc onlogon',
            LinkTarget("c:\\users\\public\\upd.exe", "exact"),
        ),
        (
            "schtasks.exe -create -tn x -TR C:\\Users\\Public\\upd.exe -sc daily",
            LinkTarget("c:\\users\\public\\upd.exe", "exact"),
        ),
        ("schtasks /create /tn x /sc onlogon", None),
        ("schtasks /create /tn x /tr", None),
    ],
)
def test_schtasks_target(command: str, expected: LinkTarget | None) -> None:
    assert schtasks_target(command) == expected


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        (
            'sc.exe create svc binPath= "C:\\ProgramData\\svc\\svc.exe -k" start= auto',
            LinkTarget("c:\\programdata\\svc\\svc.exe", "exact"),
        ),
        (
            "sc create svc binpath=C:\\ProgramData\\x.exe",
            LinkTarget("c:\\programdata\\x.exe", "exact"),
        ),
        (
            "sc create svc BINPATH= %SystemRoot%\\Temp\\x.exe",
            LinkTarget("c:\\windows\\temp\\x.exe", "exact"),
        ),
        ("sc create svc start= auto", None),
    ],
)
def test_sc_binpath_target(command: str, expected: LinkTarget | None) -> None:
    assert sc_binpath_target(command) == expected


# Links built during analysis.


def _setter(chain: Chain, details: str, *, second: float = 5, explorer: bool = True) -> Chain:
    """explorer → tool.exe (LOC-001) which sets a Run key (PER-001) to ``details``."""
    if explorer:
        chain.create(1, EXPLORER)
    chain.create(2, PUBLIC + "tool.exe", 1, 1, parent_image=EXPLORER)
    chain.event(
        13,
        2,
        second,
        Image=PUBLIC + "tool.exe",
        EventType="SetValue",
        TargetObject=RUN_KEY,
        Details=details,
    )
    return chain


def _story(result: AnalysisResult, root_image: str) -> Storyline:
    return next(s for s in result.storylines if s.root_image_name == root_image)


def test_exact_persistence_link(tmp_path: Path) -> None:
    chain = _setter(Chain(), PUBLIC + "upd.exe")
    chain.create(3, PUBLIC + "upd.exe", 1, 100, parent_image=EXPLORER)
    result = frozen_analysis(chain.write(tmp_path / "in.jsonl"))
    setter, later = _story(result, "tool.exe"), _story(result, "upd.exe")
    (link,) = setter.links
    assert (link.from_storyline, link.to_storyline) == (setter.storyline_id, later.storyline_id)
    assert (link.kind, link.match, link.path) == (
        "persistence",
        "exact",
        "c:\\users\\public\\upd.exe",
    )
    assert [e.index for e in link.evidence] == [2, 3]
    assert later.links == ()
    assert setter.scope.unlinked_targets == ()


def test_appdata_suffix_link(tmp_path: Path) -> None:
    chain = _setter(Chain(), "%APPDATA%\\Microsoft\\svchost.exe")
    image = "C:\\Users\\jdoe\\AppData\\Roaming\\Microsoft\\svchost.exe"  # LOC-002
    chain.create(3, image, 1, 100, parent_image=EXPLORER)
    result = frozen_analysis(chain.write(tmp_path / "in.jsonl"))
    (link,) = _story(result, "tool.exe").links
    assert (link.match, link.path) == ("suffix", "\\microsoft\\svchost.exe")
    assert link.to_storyline == _story(result, "svchost.exe").storyline_id


def test_no_link_to_another_host(tmp_path: Path) -> None:
    chain = _setter(Chain(), PUBLIC + "upd.exe")
    chain.create(31, EXPLORER, host=OTHER_HOST)
    chain.create(32, PUBLIC + "upd.exe", 31, 100, parent_image=EXPLORER, host=OTHER_HOST)
    result = frozen_analysis(chain.write(tmp_path / "in.jsonl"))
    setter = _story(result, "tool.exe")
    assert setter.links == ()
    (note,) = setter.scope.unlinked_targets
    assert (note.reason, note.path, note.guid, note.start_us) == (
        "not_seen_running",
        "c:\\users\\public\\upd.exe",
        None,
        None,
    )
    assert any(s.host == OTHER_HOST and s.root_image_name == "upd.exe" for s in result.storylines)


def test_a_process_started_before_the_finding_does_not_link(tmp_path: Path) -> None:
    chain = Chain().create(1, EXPLORER)
    chain.create(3, PUBLIC + "upd.exe", 1, 1, parent_image=EXPLORER)
    _setter(chain, PUBLIC + "upd.exe", second=50, explorer=False)
    result = frozen_analysis(chain.write(tmp_path / "in.jsonl"))
    setter = _story(result, "tool.exe")
    assert setter.links == ()
    assert [n.reason for n in setter.scope.unlinked_targets] == ["not_seen_running"]


def test_target_ran_but_is_in_no_storyline(tmp_path: Path) -> None:
    app = "C:\\Program Files\\App\\app.exe"  # no rule fires on it
    chain = _setter(Chain(), f'"{app}" --tray')
    chain.create(3, app, 1, 100, parent_image=EXPLORER)
    result = frozen_analysis(chain.write(tmp_path / "in.jsonl"))
    setter = _story(result, "tool.exe")
    assert setter.links == ()
    (note,) = setter.scope.unlinked_targets
    assert note.reason == "target_not_in_storyline"
    assert note.guid == guid(3)
    assert format_rfc3339(note.start_us or 0) == "2026-10-12T10:01:40Z"
    assert (note.rule_id, note.match, note.path) == (
        "PER-001",
        "exact",
        "c:\\program files\\app\\app.exe",
    )
    assert note.source.index == 2


def test_both_unlinked_cases_are_reported_separately(tmp_path: Path) -> None:
    app = "C:\\Program Files\\App\\app.exe"
    chain = _setter(Chain(), app)
    chain.event(
        13,
        2,
        6,
        Image=PUBLIC + "tool.exe",
        EventType="SetValue",
        TargetObject=RUN_KEY + "2",
        Details=PUBLIC + "never.exe",
    )
    chain.create(3, app, 1, 100, parent_image=EXPLORER)
    result = frozen_analysis(chain.write(tmp_path / "in.jsonl"))
    notes = _story(result, "tool.exe").scope.unlinked_targets
    assert [(n.reason, n.path) for n in notes] == [
        ("target_not_in_storyline", "c:\\program files\\app\\app.exe"),
        ("not_seen_running", "c:\\users\\public\\never.exe"),
    ]


def test_no_self_link_for_persistence(tmp_path: Path) -> None:
    chain = _setter(Chain(), PUBLIC + "upd.exe")
    chain.create(3, PUBLIC + "upd.exe", 2, 100, parent_image=PUBLIC + "tool.exe")
    result = frozen_analysis(chain.write(tmp_path / "in.jsonl"))
    (story,) = result.storylines
    assert story.links == () and story.scope.unlinked_targets == ()


def test_self_link_for_a_dropped_file(tmp_path: Path) -> None:
    chain = Chain().create(1, EXPLORER)
    chain.create(2, PUBLIC + "tool.exe", 1, 1, parent_image=EXPLORER)
    chain.event(11, 2, 2, Image=PUBLIC + "tool.exe", TargetFilename=PUBLIC + "x.exe")
    chain.create(3, PUBLIC + "x.exe", 2, 3, parent_image=PUBLIC + "tool.exe")
    result = frozen_analysis(chain.write(tmp_path / "in.jsonl"))
    (story,) = result.storylines
    (link,) = story.links
    assert (link.from_storyline, link.to_storyline) == (story.storyline_id, story.storyline_id)
    assert (link.kind, link.match, link.path) == (
        "dropped_executed",
        "exact",
        "c:\\users\\public\\x.exe",
    )
    assert [e.index for e in link.evidence] == [2, 3]


def test_a_process_in_two_storylines_links_to_the_one_it_roots(tmp_path: Path) -> None:
    # A flagged payload starts a new explorer.exe (a verified anchor), whose child has its own
    # finding: the child is a descendant in the payload's storyline and roots its own.
    chain = Chain().create(1, EXPLORER)
    chain.create(2, PUBLIC + "payload.exe", 1, 1, parent_image=EXPLORER)
    chain.create(3, EXPLORER, 2, 2, parent_image=PUBLIC + "payload.exe")
    chain.create(10, PUBLIC + "setter.exe", 1, 3, parent_image=EXPLORER)
    chain.event(
        13,
        10,
        4,
        Image=PUBLIC + "setter.exe",
        EventType="SetValue",
        TargetObject=RUN_KEY,
        Details=PUBLIC + "child.exe",
    )
    chain.create(4, PUBLIC + "child.exe", 3, 100, parent_image=EXPLORER)
    result = frozen_analysis(chain.write(tmp_path / "in.jsonl"))
    payload, child = _story(result, "payload.exe"), _story(result, "child.exe")
    assert guid(4) in payload.nodes and child.root_guid == guid(4)
    (link,) = _story(result, "setter.exe").links
    assert link.to_storyline == child.storyline_id


def test_schtasks_and_service_targets(tmp_path: Path) -> None:
    chain = Chain().create(1, EXPLORER)
    chain.create(2, PUBLIC + "tool.exe", 1, 1, parent_image=EXPLORER)
    chain.create(
        3,
        SYS32 + "schtasks.exe",
        2,
        2,
        f'schtasks /create /tn U /tr "{PUBLIC}upd.exe --run" /sc onlogon',
        PUBLIC + "tool.exe",
    )
    chain.create(
        4,
        SYS32 + "sc.exe",
        2,
        3,
        'sc.exe create svc binPath= "C:\\ProgramData\\svchost.exe" start= auto',
        PUBLIC + "tool.exe",
    )
    chain.event(
        13,
        2,
        4,
        Image=PUBLIC + "tool.exe",
        EventType="SetValue",
        TargetObject="HKLM\\System\\CurrentControlSet\\Services\\svc2\\ImagePath",
        Details="%SystemRoot%\\Temp\\svc2.exe",
    )
    chain.create(5, PUBLIC + "upd.exe", 1, 100, parent_image=EXPLORER)
    chain.create(6, "C:\\ProgramData\\svchost.exe", 1, 101, parent_image=EXPLORER)
    chain.create(7, "C:\\Windows\\Temp\\svc2.exe", 1, 102, parent_image=EXPLORER)
    result = frozen_analysis(chain.write(tmp_path / "in.jsonl"))
    setter = _story(result, "tool.exe")
    linked = {(link.path, link.to_storyline) for link in setter.links}
    assert linked == {
        ("c:\\users\\public\\upd.exe", _story(result, "upd.exe").storyline_id),
        ("c:\\programdata\\svchost.exe", _story(result, "svchost.exe").storyline_id),
        ("c:\\windows\\temp\\svc2.exe", _story(result, "svc2.exe").storyline_id),
    }


def test_startup_folder_target(tmp_path: Path) -> None:
    startup = (
        "C:\\Users\\jdoe\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"
    )
    chain = Chain().create(1, EXPLORER)
    chain.create(2, PUBLIC + "tool.exe", 1, 1, parent_image=EXPLORER)
    chain.event(11, 2, 2, Image=PUBLIC + "tool.exe", TargetFilename=startup + "svchost.exe")
    chain.create(3, startup + "svchost.exe", 1, 100, parent_image=EXPLORER)
    result = frozen_analysis(chain.write(tmp_path / "in.jsonl"))
    kinds = {(link.kind, link.path) for link in _story(result, "tool.exe").links}
    assert ("persistence", (startup + "svchost.exe").lower()) in kinds


def test_links_are_sorted_and_deterministic(tmp_path: Path) -> None:
    chain = _setter(Chain(), PUBLIC + "b.exe")
    chain.event(
        13,
        2,
        6,
        Image=PUBLIC + "tool.exe",
        EventType="SetValue",
        TargetObject=RUN_KEY + "2",
        Details=PUBLIC + "a.exe",
    )
    chain.create(3, PUBLIC + "b.exe", 1, 100, parent_image=EXPLORER)
    chain.create(4, PUBLIC + "a.exe", 1, 101, parent_image=EXPLORER)
    path = chain.write(tmp_path / "in.jsonl")
    first = frozen_analysis(path)
    links = _story(first, "tool.exe").links
    keys = [(link.from_storyline, link.to_storyline, link.kind, link.path) for link in links]
    assert keys == sorted(keys) and len(keys) == 2
    assert frozen_analysis(path).storylines == first.storylines


# The phish fixture (S1 gate).


@pytest.fixture(scope="module")
def phish() -> AnalysisResult:
    return frozen_analysis(FIXTURES / "phish_chain.jsonl")


def test_phish_run_key_links_s1_to_s2(phish: AnalysisResult) -> None:
    s1, s2 = phish.storylines
    links = {(link.kind, link.match, link.path, link.to_storyline) for link in s1.links}
    assert links == {
        ("persistence", "exact", "c:\\users\\public\\upd.exe", "S2"),
        ("dropped_executed", "exact", "c:\\users\\public\\upd.exe", "S2"),
    }
    assert all(link.from_storyline == "S1" for link in s1.links)
    assert s2.links == ()
    assert s1.scope.unlinked_targets == () and s2.scope.unlinked_targets == ()
    assert HOST == s1.host
