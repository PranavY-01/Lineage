import json
import random
from pathlib import Path
from typing import Any

from lineage_ir.ingest.normalize import content_digest
from lineage_ir.ingest.reader import read_inputs

SHAPES = ("shape_a.jsonl", "shape_b.jsonl", "shape_c.jsonl")


def _without_source(result: Any) -> list[dict[str, Any]]:
    return [e.model_dump(exclude={"source"}) for e in result.events]


def test_shapes_normalize_identically(fixtures_dir: Path) -> None:
    results = [read_inputs([fixtures_dir / "shapes" / name]) for name in SHAPES]
    baseline = _without_source(results[0])
    assert len(baseline) == 3
    for result in results[1:]:
        assert _without_source(result) == baseline
    for result in results:
        assert result.reasons == ()
        assert result.counters.invalid == 0


def test_shape_fixture_values(fixtures_dir: Path) -> None:
    result = read_inputs([fixtures_dir / "shapes" / "shape_a.jsonl"])
    create, net, reg = result.events
    assert [e.event_id for e in result.events] == [1, 3, 13]
    assert create.host == "ws-14.corp.example"
    assert create.process_guid == "8d9a1c2e-1111-4a2b-9c3d-0000000000a1"
    assert create.fields["parent_process_guid"] == "8d9a1c2e-1111-4a2b-9c3d-0000000000a0"
    assert create.fields["parent_pid"] == "3100"
    assert create.pid == 4242
    assert create.record_id == 101
    assert net.fields["initiated"] == "true"
    assert net.fields["destination_port"] == "80"
    assert reg.fields["event_type"] == "SetValue"
    assert result.event_ids_seen == {"1": 1, "3": 1, "13": 1}
    # FileVersion, SourceIsIpv6 and DestinationIsIpv6 are mapped since amendment 25.
    assert set(result.unknown_keys) == set()


def test_all_shapes_together_dedupe_to_one_copy(fixtures_dir: Path) -> None:
    result = read_inputs([fixtures_dir / "shapes" / name for name in SHAPES])
    assert len(result.events) == 3
    assert result.counters.duplicates_dropped == 6
    assert result.counters.duplicate_conflicts == 0
    assert {e.source.file for e in result.events} == {"shape_a.jsonl"}


def test_duplicates_fixture(fixtures_dir: Path, tmp_path: Path) -> None:
    result = read_inputs([fixtures_dir / "duplicates.jsonl"])
    counters = result.counters
    assert counters.records_total == 7
    assert counters.duplicates_dropped == 2
    assert counters.duplicate_conflicts == 1
    assert len(result.events) == 4
    assert result.reasons == ("duplicate_conflicts",)

    # Records 2 and 3 share a record ID with different content and the same time: the
    # copy with the smaller content hash is kept, and both locations are reported.
    lines = (fixtures_dir / "duplicates.jsonl").read_text(encoding="utf-8").splitlines()
    copies = []
    for index in (2, 3):
        single = tmp_path / f"line{index}.jsonl"
        single.write_text(lines[index] + "\n", encoding="utf-8", newline="\n")
        event = read_inputs([single]).events[0]
        copies.append((content_digest(event), index, event))
    kept_digest, kept_index, kept = min(copies)
    dropped_index = ({2, 3} - {kept_index}).pop()
    network = [e for e in result.events if e.event_id == 3]
    assert network[0].fields["destination_port"] == kept.fields["destination_port"]
    assert network[0].source.index == kept_index
    assert [e.model_dump() for e in result.errors] == [
        {
            "kind": "duplicate_conflict",
            "subject": f"duplicates.jsonl:{dropped_index}",
            "message": (
                f"dropped; conflicts with kept record duplicates.jsonl:{kept_index} "
                "(same host, channel and record ID or content key, different content)"
            ),
        }
    ]
    assert kept_digest == content_digest(network[0])


def test_broken_fixture_counts_every_reason(fixtures_dir: Path) -> None:
    result = read_inputs([fixtures_dir / "broken" / "invalid_mix.jsonl"])
    counters = result.counters
    assert counters.records_total == 11
    assert counters.sysmon == 1
    assert counters.irrelevant == 1
    assert counters.irrelevant_by_channel == {"Security": 1}
    assert counters.invalid == 9
    assert counters.invalid_by_reason == {
        "bad_json": 2,
        "duplicate_key": 1,
        "implausible_timestamp": 1,
        "naive_timestamp": 1,
        "no_event_id": 1,
        "no_timestamp": 1,
        "too_deep": 1,
        "unknown_shape": 1,
    }
    assert [(s.index, s.reason) for s in result.invalid_samples][:3] == [
        (1, "bad_json"),
        (2, "bad_json"),
        (3, "duplicate_key"),
    ]
    assert result.reasons == ("invalid_records",)


def test_global_sort_order(write_jsonl: Any, make_record: Any) -> None:
    rows = [
        make_record(1, 5, "2026-10-12 10:00:02.000", host="b.corp.example"),
        make_record(1, 9, "2026-10-12 10:00:01.000", host="a.corp.example"),
        make_record(1, 3, "2026-10-12 10:00:01.000", host="a.corp.example"),
        make_record(1, None, "2026-10-12 10:00:01.000", host="a.corp.example", Image="x"),
        make_record(1, 1, "2026-10-12 10:00:00.000", host="b.corp.example"),
    ]
    result = read_inputs([write_jsonl(rows)])
    order = [(e.host, e.ts_us, e.record_id) for e in result.events]
    assert order == sorted(order, key=lambda o: (o[0], o[1], o[2] or 0))
    assert [e.record_id for e in result.events] == [None, 3, 9, 1, 5]
    assert result.hosts == ("a.corp.example", "b.corp.example")


def test_shuffled_input_gives_same_events(write_jsonl: Any, make_record: Any) -> None:
    rows = [
        make_record(eid, rid, f"2026-10-12 10:00:{rid:02d}.000", Image=f"img{rid}.exe")
        for rid, eid in enumerate([1, 3, 11, 13, 22, 1, 3, 5], start=1)
    ]
    baseline = _without_source(read_inputs([write_jsonl(rows, "base.jsonl")]))
    for seed in range(5):
        shuffled = rows[:]
        random.Random(seed).shuffle(shuffled)
        result = read_inputs([write_jsonl(shuffled, f"s{seed}.jsonl")])
        assert _without_source(result) == baseline


def test_out_of_order_counter(write_jsonl: Any, make_record: Any) -> None:
    rows = [
        make_record(1, 1, "2026-10-12 10:00:05.000"),
        make_record(1, 2, "2026-10-12 10:00:01.000"),
        make_record(1, 3, "2026-10-12 10:00:09.000"),
    ]
    result = read_inputs([write_jsonl(rows)])
    assert result.counters.out_of_order == 1
    assert result.reasons == ()


def test_bad_guid_counter(write_jsonl: Any, make_record: Any) -> None:
    rows = [make_record(1, 1, ProcessGuid="nope", ParentProcessGuid="{also-bad}")]
    result = read_inputs([write_jsonl(rows)])
    assert result.counters.bad_guid == 2
    assert result.events[0].process_guid is None


def test_only_irrelevant_records_means_no_events(write_jsonl: Any, make_record: Any) -> None:
    result = read_inputs([write_jsonl([make_record(4624, 1, channel="Security")])])
    assert result.events == ()
    assert result.reasons == ("no_events",)
    assert result.span is None


def test_evidence_index_points_at_record(write_jsonl: Any, make_record: Any) -> None:
    rows = ["", json.dumps(make_record(1, 1)), "{bad", "", json.dumps(make_record(3, 2))]
    path = write_jsonl(rows)
    result = read_inputs([path])
    records = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    for event in result.events:
        source = json.loads(records[event.source.index])
        assert source["RecordNumber"] == event.record_id
