from lineage_ir.ingest.shapes import detect_shape

CH = "Microsoft-Windows-Sysmon/Operational"


def test_shape_a() -> None:
    record = {
        "Event": {"System": {"EventID": 1, "Channel": CH}, "EventData": {"Image": "x"}},
        "event_record_id": 9,
    }
    shaped = detect_shape(record)
    assert shaped is not None and shaped.shape == "A"
    assert shaped.event_data == {"Image": "x"}
    assert shaped.system["EventID"] == 1
    assert shaped.system["event_record_id"] == 9


def test_shape_a_system_value_beats_outer_key() -> None:
    record = {"Event": {"System": {"timestamp": "inner"}, "EventData": {}}, "timestamp": "outer"}
    shaped = detect_shape(record)
    assert shaped is not None and shaped.system["timestamp"] == "inner"


def test_shape_a_null_event_data() -> None:
    shaped = detect_shape({"Event": {"System": {"EventID": 1}, "EventData": None}})
    assert shaped is not None and shaped.shape == "A" and shaped.event_data == {}


def test_shape_c() -> None:
    record = {"winlog": {"event_id": "1", "event_data": {"Image": "x"}}}
    shaped = detect_shape(record)
    assert shaped is not None and shaped.shape == "C"
    assert shaped.event_data == {"Image": "x"}


def test_shape_b_excludes_system_keys_from_event_data() -> None:
    record = {"EventID": 1, "Channel": CH, "Hostname": "h", "RecordNumber": 3, "Image": "x"}
    shaped = detect_shape(record)
    assert shaped is not None and shaped.shape == "B"
    assert shaped.event_data == {"Image": "x"}


def test_shape_b_non_sysmon_record_with_system_keys() -> None:
    shaped = detect_shape({"EventID": 4624, "Channel": "Security", "TargetUserName": "jdoe"})
    assert shaped is not None and shaped.shape == "B"


def test_unknown_shapes() -> None:
    assert detect_shape({"alpha": 1}) is None
    assert detect_shape({"Image": "x"}) is None
    assert detect_shape({"EventID": 1}) is None
    assert detect_shape([1, 2]) is None
    assert detect_shape("text") is None
    assert detect_shape({"winlog": {"event_data": "not a mapping"}}) is None
