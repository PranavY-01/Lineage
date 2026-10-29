"""EVTX reader with per-record error isolation (§6.1, §6.2 shape A)."""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

from lineage_ir.errors import InputError
from lineage_ir.ingest.windows.json_reader import RawItem, parse_record_text


def _open_parser(path: Path) -> Any:
    try:
        from evtx import PyEvtxParser
    except ImportError as exc:
        raise InputError(f"{path.name}: EVTX support is unavailable on this platform") from exc
    try:
        return PyEvtxParser(str(path))
    except Exception as exc:
        raise InputError(f"{path.name}: EVTX file cannot be opened") from exc


def read_evtx(path: Path) -> Iterator[RawItem]:
    """Yield one item per EVTX record; a record that raises is reported, not fatal."""
    parser = _open_parser(path)
    try:
        records = iter(parser.records_json())
    except Exception as exc:
        raise InputError(f"{path.name}: EVTX file cannot be opened") from exc

    index = 0
    while True:
        try:
            raw = next(records)
        except StopIteration:
            return
        except Exception:
            yield RawItem(index, reason="evtx_record_error")
            index += 1
            continue

        data = raw.get("data") if isinstance(raw, dict) else None
        if not isinstance(data, str):
            yield RawItem(index, reason="evtx_record_error")
            index += 1
            continue
        record, reason = parse_record_text(data)
        if isinstance(record, dict):
            # Keep the parser's own record ID and timestamp as shape A fallbacks.
            record.setdefault("event_record_id", raw.get("event_record_id"))
            record.setdefault("timestamp", raw.get("timestamp"))
        yield RawItem(index, record, reason)
        index += 1
