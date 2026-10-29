import pytest

from lineage_ir.ingest.field_aliases import lookup, normalize_key, resolve_system, to_snake


def test_lookup_literal_key_wins_over_nested_path() -> None:
    record = {"host.name": "literal", "host": {"name": "nested"}}
    assert lookup(record, "host.name") == "literal"


def test_lookup_nested_path() -> None:
    record = {"Provider": {"#attributes": {"Name": "Microsoft-Windows-Sysmon"}}}
    assert lookup(record, "Provider.#attributes.Name") == "Microsoft-Windows-Sysmon"


def test_lookup_missing() -> None:
    assert lookup({"a": {"b": 1}}, "a.c") is None
    assert lookup({"a": "text"}, "a.b") is None


def test_host_priority_order() -> None:
    record = {"Hostname": "second", "Computer": "first", "winlog": {"computer_name": "last"}}
    assert resolve_system(record, "host") == ("first", "Computer")


def test_empty_value_falls_through() -> None:
    record = {"Computer": "", "Hostname": "ws-14.corp.example"}
    assert resolve_system(record, "host") == ("ws-14.corp.example", "Hostname")


def test_shape_a_extras_only_for_shape_a() -> None:
    record = {"event_record_id": 7, "timestamp": "2026-10-12T10:41:58Z"}
    assert resolve_system(record, "record_id") == (None, None)
    assert resolve_system(record, "record_id", shape_a=True) == (7, "event_record_id")
    assert resolve_system(record, "time_created", shape_a=True)[1] == "timestamp"


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        ("ProcessGuid", "process_guid"),
        ("processguid", "process_guid"),
        ("SourceProcessGUID", "source_process_guid"),
        ("TargetProcessGUID", "target_process_guid"),
        ("ProcessId", "pid"),
        ("ParentProcessId", "parent_pid"),
        ("SourceProcessId", "source_pid"),
        ("TargetProcessId", "target_pid"),
        ("UtcTime", "utc_time"),
        ("IsExecutable", "is_executable"),
    ],
)
def test_known_keys_map_case_insensitively(key: str, expected: str) -> None:
    assert normalize_key(key) == (expected, True)


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        ("RuleName", "rule_name"),
        ("FileVersion", "file_version"),
        ("SourceIsIpv6", "source_is_ipv6"),
        ("NewThreadId", "new_thread_id"),
        ("HTTPHeader", "http_header"),
        ("@version", "version"),
        ("---", "_"),
    ],
)
def test_unknown_keys_become_snake_case(key: str, expected: str) -> None:
    assert to_snake(key) == expected
    assert normalize_key(key) == (expected, False)
