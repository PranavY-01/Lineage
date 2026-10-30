"""Compact Event storage: equal to full validation, and never mutated downstream."""

import copy
import functools
import json
import random
from pathlib import Path
from typing import Any

import pytest

from lineage_ir.graph.builder import build_graphs
from lineage_ir.graph.traverse import ancestors, collapse_children, descendants, hot_set
from lineage_ir.ingest import reader
from lineage_ir.ingest.normalize import (
    Normalized,
    NormalizedImageLoad,
    StringPools,
    content_digest,
    normalize_record,
)
from lineage_ir.ingest.reader import read_inputs
from lineage_ir.ingest.windows.json_reader import read_jsonl
from lineage_ir.models import Event, IngestResult

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
JSONL_FIXTURES = sorted(FIXTURES.rglob("*.jsonl"))


def _event_mix(directory: Path) -> Path:
    """Every activity kind, odd GUIDs and PIDs, unknown keys, non-string values, no IDs."""
    rng = random.Random(11)
    rows: list[dict[str, Any]] = []
    guids = [f"{{6C1E0A2B-7D3F-4E5A-9B8C-{n:012X}}}" for n in range(1, 25)] + [
        "{bad}",
        "-",
        "",
        "{00000000-0000-0000-0000-000000000000}",
    ]
    images = [f"C:\\Tools\\p{n}.exe" for n in range(6)] + ["\\\\?\\C:\\Long\\path.exe", ""]
    for n in range(800):
        event_id = rng.choice([1, 3, 5, 7, 8, 10, 11, 12, 13, 15, 17, 19, 22, 23, 26, 255])
        record: dict[str, Any] = {
            "EventID": event_id,
            "Hostname": rng.choice(["WS-14.corp.example", "ws-15.corp.example", " Ws-16 "]),
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "UtcTime": f"2026-10-12 11:{n % 60:02d}:{n * 7 % 60:02d}.{n % 1000:03d}",
            "RuleName": "-",
            "ProcessGuid": rng.choice(guids),
            "ProcessId": rng.choice([str(n), hex(n), "x", n]),
            "Image": rng.choice(images),
            "User": rng.choice(["CORP\\jdoe", "NT AUTHORITY\\SYSTEM", "CORP\\\u202ereversed"]),
        }
        if n % 4:
            record["RecordNumber"] = 10_000 + n
        if event_id == 1:
            record.update(
                ParentProcessGuid=rng.choice(guids),
                ParentProcessId=str(n // 2),
                ParentImage=rng.choice(images),
                CommandLine=f"p.exe --n {n}",
                Hashes=f"SHA256={n % 9:064X},MD5={n % 9:032x}",
            )
        elif event_id in (8, 10):
            record.update(
                SourceProcessGuid=rng.choice(guids),
                TargetProcessGuid=rng.choice(guids),
                SourceImage=rng.choice(images),
                TargetImage=rng.choice(images),
                GrantedAccess=rng.choice(["0x1FFFFF", "0x1010", "bogus"]),
            )
        elif event_id == 7:
            record.update(ImageLoaded=f"C:\\Windows\\m{n % 7}.dll", Signed="true")
        if n % 9 == 0:
            record[f"Custom{n % 5}Field"] = rng.choice([1, 2.5, True, None, {"a": [1]}, "x"])
        rows.append(record)
    out = directory / "event_mix.jsonl"
    out.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8", newline="\n")
    return out


def _source(name: str, tmp_path: Path) -> Path:
    return _event_mix(tmp_path) if name == "event_mix" else FIXTURES / name


def _dump(event: Event) -> str:
    # JSON text also tells 1 from True, which a plain dict comparison would not.
    return json.dumps(event.model_dump(), sort_keys=True)


CASES = [*(p.relative_to(FIXTURES).as_posix() for p in JSONL_FIXTURES), "event_mix"]


@pytest.mark.parametrize("name", CASES)
def test_compact_events_equal_fully_validated_events(tmp_path: Path, name: str) -> None:
    pools = StringPools()
    compared = 0
    for raw in read_jsonl(_source(name, tmp_path)):
        if raw.reason is not None:
            continue
        args = (raw.record, "in.jsonl", "0" * 64, raw.index)
        compact = normalize_record(*args, pools=pools, slim_image_loads=False)
        full = normalize_record(*args, slim_image_loads=False, compact=False)
        assert type(compact) is type(full)
        if isinstance(full, Normalized):
            assert isinstance(compact, Normalized)
            assert _dump(compact.event) == _dump(full.event)
            assert type(compact.event.source) is type(full.event.source)
            assert (compact.unknown_keys, compact.bad_guids) == (full.unknown_keys, full.bad_guids)
            compared += 1
    assert compared > 0


def _full_validation_ingest(monkeypatch: pytest.MonkeyPatch, path: Path) -> IngestResult:
    with monkeypatch.context() as patch:
        patch.setattr(
            reader, "normalize_record", functools.partial(normalize_record, compact=False)
        )
        return read_inputs([path])


@pytest.mark.parametrize("name", CASES)
def test_compact_pipeline_equals_full_validation_pipeline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    path = _source(name, tmp_path)
    compact = read_inputs([path])
    full = _full_validation_ingest(monkeypatch, path)
    assert [_dump(e) for e in compact.events] == [_dump(e) for e in full.events]
    assert [(i.content(), i.source) for i in compact.image_loads] == [
        (i.content(), i.source) for i in full.image_loads
    ]
    assert compact.model_dump(exclude={"events", "image_loads"}) == full.model_dump(
        exclude={"events", "image_loads"}
    )


def _snapshot(result: IngestResult) -> tuple[list[Event], list[Any]]:
    loads = [(i.content(), i.file, i.file_sha256, i.index) for i in result.image_loads]
    return copy.deepcopy(list(result.events)), copy.deepcopy(loads)


@pytest.mark.parametrize("name", CASES)
def test_shared_maps_and_strings_survive_the_pipeline(tmp_path: Path, name: str) -> None:
    result = read_inputs([_source(name, tmp_path)])
    before_events, before_loads = _snapshot(result)

    # Everything downstream of ingest that exists so far; later phases add their stages here.
    graphs = build_graphs(result.events, result.image_loads)
    for graph in graphs.values():
        graph.model_dump()
        hot = hot_set(graph, list(graph.nodes)[:3])
        for guid, node in graph.nodes.items():
            ancestors(graph, guid)
            descendants(graph, guid)
            collapse_children(graph, node.children, hot, 2)
    for item in (*result.events, *result.image_loads):
        content_digest(item)

    after_events, after_loads = _snapshot(result)
    assert [_dump(e) for e in after_events] == [_dump(e) for e in before_events]
    assert all(a == b for a, b in zip(result.events, before_events, strict=True))
    assert after_loads == before_loads


def test_activities_share_the_event_field_map() -> None:
    """The sharing the immutability test protects: one field map per record, not a copy."""
    result = read_inputs([FIXTURES / "ghosts.jsonl"])
    by_source = {(e.source.file, e.source.index): e for e in result.events}
    graph = next(iter(build_graphs(result.events).values()))
    activity = [a for n in graph.nodes.values() for a in n.activity]
    assert activity
    for item in activity:
        assert item.fields is by_source[(item.source.file, item.source.index)].fields


def test_slim_path_is_unchanged_by_compaction(tmp_path: Path) -> None:
    pools = StringPools()
    for raw in read_jsonl(_event_mix(tmp_path)):
        outcome = normalize_record(raw.record, "in.jsonl", "0" * 64, raw.index, pools=pools)
        if isinstance(outcome, NormalizedImageLoad):
            reference = normalize_record(raw.record, "in.jsonl", "0" * 64, raw.index)
            assert isinstance(reference, NormalizedImageLoad)
            assert outcome.event.content() == reference.event.content()
