"""JSON and JSONL readers with per-record safety checks (§6.1)."""

import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from lineage_ir.config import JSON_LINE_CAP_BYTES, JSON_MAX_DEPTH
from lineage_ir.errors import InputError

UTF8_BOM = b"\xef\xbb\xbf"


@dataclass(frozen=True, slots=True)
class RawItem:
    """One record as read: the parsed value, or the reason it could not be parsed."""

    index: int
    record: Any = None
    reason: str | None = None


class _DupDict(dict):
    """Marks an object that contained a duplicate key."""


class _NonFinite:
    """Placeholder for NaN or Infinity in the source text."""


_NON_FINITE = _NonFinite()


def _pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    duplicate = False
    for key, value in pairs:
        if key in result:
            duplicate = True
            continue
        result[key] = value
    return _DupDict(result) if duplicate else result


def _constant_hook(_name: str) -> _NonFinite:
    return _NON_FINITE


def _loads(text: str) -> Any:
    return json.loads(text, object_pairs_hook=_pairs_hook, parse_constant=_constant_hook)


def check_value(value: Any) -> str | None:
    """Return an invalid reason for a parsed record, or None when it is acceptable."""
    duplicate = too_deep = False
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if item is _NON_FINITE:
            return "bad_json"
        if isinstance(item, dict | list):
            if depth > JSON_MAX_DEPTH:
                too_deep = True
                continue
            if isinstance(item, _DupDict):
                duplicate = True
            children = item.values() if isinstance(item, dict) else item
            stack.extend((child, depth + 1) for child in children)
    if duplicate:
        return "duplicate_key"
    if too_deep:
        return "too_deep"
    return None


def parse_record_text(text: str) -> tuple[Any, str | None]:
    """Parse one record's JSON text; return (record, None) or (None, reason)."""
    try:
        value = _loads(text)
    except RecursionError:
        return None, "too_deep"
    except ValueError:
        return None, "bad_json"
    reason = check_value(value)
    return (None, reason) if reason else (value, None)


def is_jsonl(first_line: bytes) -> bool:
    """A ``{`` file is one pretty-printed JSON document only when its first line is a bare ``{``."""
    return first_line.strip() != b"{"


def read_jsonl(path: Path) -> Iterator[RawItem]:
    """Yield one item per non-blank line; over-long lines are drained, never loaded."""
    with path.open("rb") as handle:
        index = 0
        first = True
        while True:
            line = handle.readline(JSON_LINE_CAP_BYTES + 1)
            if not line:
                return
            if first and line.startswith(UTF8_BOM):
                line = line[len(UTF8_BOM) :]
            first = False
            if len(line) > JSON_LINE_CAP_BYTES and not line.endswith(b"\n"):
                while line and not line.endswith(b"\n"):
                    line = handle.readline(JSON_LINE_CAP_BYTES)
                yield RawItem(index, reason="line_too_long")
                index += 1
                continue
            if not line.strip():
                continue
            try:
                text = line.decode("utf-8")
            except UnicodeDecodeError:
                yield RawItem(index, reason="bad_json")
            else:
                record, reason = parse_record_text(text)
                yield RawItem(index, record, reason)
            index += 1


def read_json_document(path: Path) -> Iterator[RawItem]:
    """Yield the elements of a JSON array, or the single object of a JSON document."""
    data = path.read_bytes()
    if data.startswith(UTF8_BOM):
        data = data[len(UTF8_BOM) :]
    try:
        value = _loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise InputError(f"{path.name}: not valid JSON") from exc
    items = value if isinstance(value, list) else [value]
    for index, item in enumerate(items):
        reason = check_value(item)
        yield RawItem(index, None if reason else item, reason)
