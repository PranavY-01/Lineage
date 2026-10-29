import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from lineage_ir.config import MIB
from lineage_ir.errors import InputError, UsageError
from lineage_ir.ingest.reader import (
    IngestOptions,
    check_paths,
    hash_file,
    read_inputs,
    sniff_format,
)


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"ElfFile\x00rest", "evtx"),
        (b'[{"a": 1}]', "json"),
        (b'  \n [\n{"a": 1}\n]', "json"),
        (b'{"a": 1}\n{"a": 2}\n', "jsonl"),
        (b'\xef\xbb\xbf{"a": 1}\n', "jsonl"),
        (b'{\n  "a": 1\n}\n', "json"),
        (b'{"a": \n{"a": 2}\n', "jsonl"),
        (b"\n\n", "jsonl"),
        (b"", "jsonl"),
    ],
)
def test_sniff_by_content(tmp_path: Path, data: bytes, expected: str) -> None:
    assert sniff_format(_write(tmp_path, "input.log", data)) == expected


@pytest.mark.parametrize(
    "bom", [b"\xff\xfe", b"\xfe\xff", b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff"]
)
def test_wide_encodings_are_rejected(tmp_path: Path, bom: bytes) -> None:
    with pytest.raises(InputError) as err:
        sniff_format(_write(tmp_path, "x.json", bom + "{}".encode("utf-16-le")))
    assert err.value.exit_code == 3
    assert "Out-File -Encoding utf8" in str(err.value)


@pytest.mark.parametrize("data", [b"hello world", b"<Events/>", b"\x00\x01\x02"])
def test_unknown_format_is_rejected(tmp_path: Path, data: bytes) -> None:
    with pytest.raises(InputError):
        sniff_format(_write(tmp_path, "x.txt", data))


def test_hash_file_streams(tmp_path: Path) -> None:
    data = b"x" * (3 * MIB + 7)
    assert hash_file(_write(tmp_path, "big.bin", data)) == hashlib.sha256(data).hexdigest()


def test_directory_is_usage_error(tmp_path: Path) -> None:
    with pytest.raises(UsageError) as err:
        check_paths([tmp_path], 2048)
    assert err.value.exit_code == 2
    assert "directory" in str(err.value)


def test_missing_file_is_usage_error(tmp_path: Path) -> None:
    with pytest.raises(UsageError):
        check_paths([tmp_path / "missing.jsonl"], 2048)


def test_too_many_inputs(tmp_path: Path) -> None:
    path = _write(tmp_path, "a.jsonl", b"")
    with pytest.raises(UsageError):
        check_paths([path] * 65, 2048)


def test_file_size_cap(tmp_path: Path) -> None:
    path = _write(tmp_path, "big.jsonl", b"\n" * (MIB + 1))
    with pytest.raises(UsageError):
        check_paths([path], 1)
    check_paths([_write(tmp_path, "ok.jsonl", b"\n" * MIB)], 1)


def _sysmon_lines(make_record: Any, count: int, start: int = 1) -> bytes:
    rows = [
        json.dumps(make_record(1, start + i, f"2026-10-12 10:00:{i % 60:02d}.000"))
        for i in range(count)
    ]
    return ("\n".join(rows) + "\n").encode()


def test_same_file_twice_is_skipped(tmp_path: Path, make_record: Any) -> None:
    data = _sysmon_lines(make_record, 2)
    first = _write(tmp_path, "a.jsonl", data)
    second = _write(tmp_path, "b.jsonl", data)
    result = read_inputs([first, second])
    assert [i.label for i in result.inputs] == ["a.jsonl"]
    assert result.counters.records_total == 2
    assert result.warnings == ("b.jsonl: skipped, same content as a.jsonl",)


def test_record_cap_reached(tmp_path: Path, make_record: Any) -> None:
    first = _write(tmp_path, "a.jsonl", _sysmon_lines(make_record, 3))
    second = _write(tmp_path, "b.jsonl", _sysmon_lines(make_record, 3, start=100))
    result = read_inputs([first, second], IngestOptions(max_records=4))
    assert result.record_cap_reached
    assert result.counters.records_total == 4
    assert "record_cap_reached" in result.reasons


def test_record_cap_exactly_met_is_not_reached(tmp_path: Path, make_record: Any) -> None:
    path = _write(tmp_path, "a.jsonl", _sysmon_lines(make_record, 3))
    result = read_inputs([path], IngestOptions(max_records=3))
    assert not result.record_cap_reached
    assert result.reasons == ()


def test_host_filter(tmp_path: Path, make_record: Any) -> None:
    rows = [
        make_record(1, 1, host="ws-14.corp.example"),
        make_record(1, 2, host="ws-15.corp.example"),
    ]
    path = _write(tmp_path, "a.jsonl", "\n".join(json.dumps(r) for r in rows).encode())
    result = read_inputs(
        [path], IngestOptions(hosts=frozenset({"WS-15.corp.example", "ws-99.corp.example"}))
    )
    assert result.hosts == ("ws-15.corp.example",)
    assert result.warnings == ("--host ws-99.corp.example: no events for this host",)


def test_invalid_samples_capped(tmp_path: Path) -> None:
    path = _write(tmp_path, "a.jsonl", b"{bad\n" * 5)
    result = read_inputs([path], IngestOptions(max_error_samples=2))
    assert result.counters.invalid == 5
    assert len(result.invalid_samples) == 2
    assert set(result.reasons) == {"invalid_records", "no_events"}
