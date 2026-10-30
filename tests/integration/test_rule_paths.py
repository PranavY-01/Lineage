"""Path and registry values are directory fragments with a boundary on both sides (amendment 13)."""

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from helpers.detection import detect_file
from lineage_ir.detect.loader import load_rules

RUN_KEY = "HKU\\S-1-5-21-1111\\Software\\Microsoft\\Windows\\CurrentVersion\\"


def _fires(
    write_jsonl: Callable[..., Path],
    make_record: Callable[..., dict[str, Any]],
    rule_id: str,
    event_id: int,
    **fields: str,
) -> bool:
    record = make_record(
        event_id, 1, ProcessGuid="{6c1e0a2b-7d3f-4e5a-9b8c-00000000d001}", **fields
    )
    rules = tuple(r for r in load_rules() if r.id == rule_id)
    return bool(detect_file(write_jsonl([record]), rules).by_rule(rule_id))


@pytest.mark.parametrize(
    ("image", "fires"),
    [
        ("c:\\users\\public\\x.exe", True),
        ("c:\\$recycle.bin\\s-1-5-21\\x.exe", True),
        ("C:\\Users\\jdoe\\AppData\\Local\\Temp\\x.exe", True),
        ("C:\\Windows\\Temp\\x.exe", True),
        ("C:\\Users\\jdoe\\Downloads\\x.exe", True),
        ("C:\\PerfLogs\\x.exe", True),
        ("c:\\users\\publicity\\x.exe", False),
        ("c:\\downloads_old\\x.exe", False),
        ("C:\\Users\\jdoe\\AppData\\Local\\Temporary\\x.exe", False),
        ("C:\\Windows\\Temporal\\x.exe", False),
        ("C:\\PerfLogs2\\x.exe", False),
        ("C:\\x$recycle.bin\\x.exe", False),
    ],
)
def test_loc001_staging_paths(
    write_jsonl: Callable[..., Path],
    make_record: Callable[..., dict[str, Any]],
    image: str,
    fires: bool,
) -> None:
    assert _fires(write_jsonl, make_record, "LOC-001", 1, Image=image) is fires


@pytest.mark.parametrize(
    ("image", "fires"),
    [
        ("c:\\windows\\system32x\\svchost.exe", True),
        ("c:\\windows\\syswow64x\\svchost.exe", True),
        ("c:\\windows\\winsxsx\\svchost.exe", True),
        ("c:\\windows\\system32\\svchost.exe", False),
        ("C:\\Windows\\SysWOW64\\svchost.exe", False),
        ("C:\\Windows\\WinSxS\\amd64_x\\svchost.exe", False),
    ],
)
def test_loc002_system_directories(
    write_jsonl: Callable[..., Path],
    make_record: Callable[..., dict[str, Any]],
    image: str,
    fires: bool,
) -> None:
    assert _fires(write_jsonl, make_record, "LOC-002", 1, Image=image) is fires


@pytest.mark.parametrize(
    ("key", "fires"),
    [
        ("Run\\Updater", True),
        ("RunOnce\\x", True),
        ("Policies\\Explorer\\Run\\x", True),
        ("RunServices\\x", False),
        ("RunOnceEx\\x", False),
        ("Policies\\Explorer\\RunX\\x", False),
    ],
)
def test_per001_run_keys(
    write_jsonl: Callable[..., Path],
    make_record: Callable[..., dict[str, Any]],
    key: str,
    fires: bool,
) -> None:
    assert _fires(write_jsonl, make_record, "PER-001", 13, TargetObject=RUN_KEY + key) is fires
