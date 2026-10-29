import json
from pathlib import Path

import pytest

from lineage_ir.config import JSON_LINE_CAP_BYTES, JSON_MAX_DEPTH
from lineage_ir.errors import InputError
from lineage_ir.ingest.windows.json_reader import (
    check_value,
    parse_record_text,
    read_json_document,
    read_jsonl,
)


def _nested(depth: int) -> object:
    value: object = "x"
    for _ in range(depth - 1):
        value = [value]
    return {"k": value} if depth else value


def test_parse_valid_record() -> None:
    assert parse_record_text('{"a": 1}') == ({"a": 1}, None)


@pytest.mark.parametrize(
    "text", ['{"a": ', '{"a": NaN}', '{"a": Infinity}', '{"a": -Infinity}', "nope"]
)
def test_parse_bad_json(text: str) -> None:
    assert parse_record_text(text) == (None, "bad_json")


def test_parse_duplicate_key_nested() -> None:
    assert parse_record_text('{"a": {"b": 1, "b": 2}}') == (None, "duplicate_key")


def test_depth_limit_is_inclusive() -> None:
    ok = json.dumps(_nested(JSON_MAX_DEPTH))
    too_deep = json.dumps(_nested(JSON_MAX_DEPTH + 1))
    assert check_value(json.loads(ok)) is None
    assert parse_record_text(too_deep) == (None, "too_deep")


def test_extreme_nesting_does_not_crash() -> None:
    text = "[" * 200_000 + "]" * 200_000
    assert parse_record_text(text) == (None, "too_deep")


def test_jsonl_lines_blank_lines_and_bom(tmp_path: Path) -> None:
    path = tmp_path / "in.jsonl"
    path.write_bytes(b'\xef\xbb\xbf{"a": 1}\n\n   \n{"b": 2}\r\n{"c": \n')
    items = list(read_jsonl(path))
    assert [(i.index, i.record, i.reason) for i in items] == [
        (0, {"a": 1}, None),
        (1, {"b": 2}, None),
        (2, None, "bad_json"),
    ]


def test_jsonl_bad_utf8(tmp_path: Path) -> None:
    path = tmp_path / "in.jsonl"
    path.write_bytes(b'{"a": "\xff\xfe"}\n{"b": 1}\n')
    items = list(read_jsonl(path))
    assert [(i.index, i.reason) for i in items] == [(0, "bad_json"), (1, None)]


def test_jsonl_line_too_long_is_drained(tmp_path: Path) -> None:
    path = tmp_path / "in.jsonl"
    long_line = b'{"a": "' + b"x" * (2 * JSON_LINE_CAP_BYTES) + b'"}\n'
    path.write_bytes(b'{"first": 1}\n' + long_line + b'{"last": 2}\n')
    items = list(read_jsonl(path))
    assert [(i.index, i.record, i.reason) for i in items] == [
        (0, {"first": 1}, None),
        (1, None, "line_too_long"),
        (2, {"last": 2}, None),
    ]


def test_jsonl_line_at_cap_is_accepted(tmp_path: Path) -> None:
    body = b'{"a": "' + b"x" * (JSON_LINE_CAP_BYTES - 10) + b'"}'
    assert len(body) <= JSON_LINE_CAP_BYTES
    path = tmp_path / "in.jsonl"
    path.write_bytes(body + b"\n")
    items = list(read_jsonl(path))
    assert items[0].reason is None


def test_jsonl_long_final_line_without_newline(tmp_path: Path) -> None:
    path = tmp_path / "in.jsonl"
    path.write_bytes(b'{"a": "' + b"x" * (JSON_LINE_CAP_BYTES + 5) + b'"}')
    assert [i.reason for i in read_jsonl(path)] == ["line_too_long"]


def test_json_array_document(tmp_path: Path) -> None:
    path = tmp_path / "in.json"
    path.write_text(
        '[\n {"a": 1},\n {"a": NaN},\n {"b": 1, "b": 2},\n 5\n]\n', encoding="utf-8", newline="\n"
    )
    items = list(read_json_document(path))
    assert [(i.index, i.record, i.reason) for i in items] == [
        (0, {"a": 1}, None),
        (1, None, "bad_json"),
        (2, None, "duplicate_key"),
        (3, 5, None),
    ]


def test_json_single_object_document(tmp_path: Path) -> None:
    path = tmp_path / "in.json"
    path.write_bytes(b'\xef\xbb\xbf{\n  "a": 1\n}\n')
    assert [(i.index, i.record) for i in read_json_document(path)] == [(0, {"a": 1})]


def test_json_document_syntax_error_is_unusable(tmp_path: Path) -> None:
    path = tmp_path / "in.json"
    path.write_text('[{"a": 1}, {"a": ]', encoding="utf-8", newline="\n")
    with pytest.raises(InputError):
        list(read_json_document(path))
