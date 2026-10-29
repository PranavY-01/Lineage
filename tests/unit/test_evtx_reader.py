import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from lineage_ir.errors import InputError
from lineage_ir.ingest.windows import evtx_reader


def _record(record_id: int) -> dict[str, Any]:
    data = {
        "Event": {
            "System": {"EventID": 1, "EventRecordID": record_id},
            "EventData": {"UtcTime": "2026-10-12 10:41:58.123"},
        }
    }
    return {"event_record_id": record_id, "timestamp": "t", "data": json.dumps(data)}


class _FlakyIterator:
    """Yields records but raises in place of some of them, then continues."""

    def __init__(self, plan: list[Any]) -> None:
        self._plan = list(plan)

    def __iter__(self) -> Iterator[Any]:
        return self

    def __next__(self) -> Any:
        if not self._plan:
            raise StopIteration
        item = self._plan.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class _FakeParser:
    def __init__(self, plan: list[Any]) -> None:
        self._plan = plan

    def records_json(self) -> _FlakyIterator:
        return _FlakyIterator(self._plan)


def test_record_errors_are_isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    plan = [
        _record(1),
        RuntimeError("bad chunk"),
        _record(3),
        {"event_record_id": 4, "data": "{not json"},
        {"unexpected": True},
        _record(6),
    ]
    monkeypatch.setattr(evtx_reader, "_open_parser", lambda _path: _FakeParser(plan))
    items = list(evtx_reader.read_evtx(tmp_path / "x.evtx"))
    assert [(i.index, i.reason) for i in items] == [
        (0, None),
        (1, "evtx_record_error"),
        (2, None),
        (3, "bad_json"),
        (4, "evtx_record_error"),
        (5, None),
    ]
    assert items[2].record["event_record_id"] == 3
    assert items[2].record["Event"]["System"]["EventRecordID"] == 3


def test_unopenable_file_raises_input_error(tmp_path: Path) -> None:
    path = tmp_path / "broken.evtx"
    path.write_bytes(b"ElfFile\x00" + b"\x00" * 16)
    with pytest.raises(InputError):
        list(evtx_reader.read_evtx(path))


def test_missing_evtx_module_is_input_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import builtins

    real_import = builtins.__import__

    def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "evtx":
            raise ImportError("no wheel")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(InputError):
        list(evtx_reader.read_evtx(tmp_path / "x.evtx"))
