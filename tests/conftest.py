"""Shared fixtures: network blocking for every test and synthetic record builders."""

import json
import socket
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
HOST = "ws-14.corp.example"


def _network_attempt(*_args: object, **_kwargs: object) -> None:
    raise AssertionError("network access attempted during a test")


@pytest.fixture(autouse=True)
def _block_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket.socket, "connect", _network_attempt)
    monkeypatch.setattr(socket.socket, "connect_ex", _network_attempt)
    monkeypatch.setattr(socket, "create_connection", _network_attempt)
    monkeypatch.setattr(socket, "getaddrinfo", _network_attempt)


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


def flat_record(
    event_id: int,
    record_id: int | None = None,
    utc_time: str = "2026-10-12 10:41:58.123",
    host: str = HOST,
    channel: str = SYSMON_CHANNEL,
    **fields: Any,
) -> dict[str, Any]:
    """A shape B (flat) record with the given EventData fields."""
    record: dict[str, Any] = {"EventID": event_id, "Hostname": host, "Channel": channel}
    if record_id is not None:
        record["RecordNumber"] = record_id
    if utc_time:
        record["UtcTime"] = utc_time
    record.update(fields)
    return record


@pytest.fixture
def make_record() -> Callable[..., dict[str, Any]]:
    return flat_record


@pytest.fixture
def write_jsonl(tmp_path: Path) -> Callable[..., Path]:
    """Write records (dicts or raw strings) as a JSONL file under tmp_path."""

    def write(records: list[Any], name: str = "input.jsonl") -> Path:
        path = tmp_path / name
        lines = [r if isinstance(r, str) else json.dumps(r) for r in records]
        path.write_text("".join(line + "\n" for line in lines), encoding="utf-8", newline="\n")
        return path

    return write
