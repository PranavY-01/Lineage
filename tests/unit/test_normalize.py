from typing import Any

import pytest

from lineage_ir.ingest.normalize import (
    Invalid,
    Irrelevant,
    Normalized,
    canonical_guid,
    image_name,
    normalize_granted_access,
    normalize_path,
    normalize_record,
    parse_hashes,
    parse_pid,
)
from lineage_ir.ingest.timeparse import parse_iso, parse_utc_time

GUID = "8d9a1c2e-1111-4a2b-9c3d-0000000000a1"


def _norm(record: Any) -> Normalized | Irrelevant | Invalid:
    return normalize_record(record, "in.jsonl", "0" * 64, 0)


def _event(record: Any) -> Normalized:
    outcome = _norm(record)
    assert isinstance(outcome, Normalized), outcome
    return outcome


@pytest.mark.parametrize(
    "value",
    [
        GUID,
        GUID.upper(),
        "{" + GUID.upper() + "}",
        "  {" + GUID + "}  ",
    ],
)
def test_guid_canonical_forms(value: str) -> None:
    assert canonical_guid(value) == (GUID, False)


@pytest.mark.parametrize("value", ["{00000000-0000-0000-0000-000000000000}", "", "-", None])
def test_guid_null_forms_are_not_bad(value: str | None) -> None:
    assert canonical_guid(value) == (None, False)


@pytest.mark.parametrize("value", ["not-a-guid", "8d9a1c2e-1111-4a2b-9c3d", GUID + "ff"])
def test_guid_malformed(value: str) -> None:
    assert canonical_guid(value) == (None, True)


@pytest.mark.parametrize(
    ("value", "expected"),
    [("4242", 4242), ("0x1092", 4242), ("0X1092", 4242), (" 12 ", 12), ("-1", None), ("x", None)],
)
def test_parse_pid(value: str, expected: int | None) -> None:
    assert parse_pid(value) == expected


def test_parse_pid_bad_hex() -> None:
    assert parse_pid("0xZZ") is None


def test_parse_hashes() -> None:
    value = "SHA1=AA11,MD5=BB22, SHA256=CC33 ,IMPHASH=DD44,broken,=x"
    assert parse_hashes(value) == {
        "sha1": "aa11",
        "md5": "bb22",
        "sha256": "cc33",
        "imphash": "dd44",
    }
    assert parse_hashes(None) == {}


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("C:/Users/Public/a.exe", "c:\\users\\public\\a.exe"),
        ("\\\\?\\C:\\Windows\\System32\\cmd.exe", "c:\\windows\\system32\\cmd.exe"),
        ("\\??\\C:\\Windows\\Temp\\x.exe", "c:\\windows\\temp\\x.exe"),
        ("C:\\Windows\\explorer.exe", "c:\\windows\\explorer.exe"),
    ],
)
def test_normalize_path(value: str, expected: str) -> None:
    assert normalize_path(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.EXE", "powershell.exe"),
        ("/usr/bin/pwsh", "pwsh"),
        ("cmd.exe", "cmd.exe"),
        ("", None),
        (None, None),
    ],
)
def test_image_name(value: str | None, expected: str | None) -> None:
    assert image_name(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"), [("0x1FFFFF", "0x1fffff"), ("0x01410", "0x1410"), ("0xZZ", "0xzz")]
)
def test_granted_access(value: str, expected: str) -> None:
    assert normalize_granted_access(value) == expected


def test_snake_case_map_and_values_as_strings(make_record: Any) -> None:
    record = make_record(
        3,
        77,
        ProcessGuid="{" + GUID.upper() + "}",
        ProcessId=4242,
        Initiated=True,
        DestinationPort=80,
        RuleName="-",
        SourceIsIpv6=False,
    )
    result = _event(record)
    fields = result.event.fields
    assert fields["process_guid"] == GUID
    assert fields["pid"] == "4242"
    assert fields["initiated"] == "true"
    assert fields["destination_port"] == "80"
    assert fields["rule_name"] == "-"
    assert fields["source_is_ipv6"] == "false"
    assert result.unknown_keys == ("SourceIsIpv6",)
    assert result.event.process_guid == GUID
    assert result.event.pid == 4242
    assert result.event.record_id == 77
    assert result.event.source.record_id == 77


def test_nested_values_are_serialized(make_record: Any) -> None:
    result = _event(make_record(1, Extra={"b": 1, "a": [1, 2]}))
    assert result.event.fields["extra"] == '{"a":[1,2],"b":1}'


def test_null_values_are_dropped(make_record: Any) -> None:
    result = _event(make_record(1, Image=None))
    assert "image" not in result.event.fields
    assert result.event.image is None


def test_pid_fields_normalized_to_decimal(make_record: Any) -> None:
    result = _event(make_record(1, ProcessId="0x1092", ParentProcessId="0xC1C"))
    assert result.event.fields["pid"] == "4242"
    assert result.event.fields["parent_pid"] == "3100"


def test_event10_acting_process_is_source_and_guid_key_is_case_insensitive(
    make_record: Any,
) -> None:
    record = make_record(
        10,
        SourceProcessGUID="{" + GUID + "}",
        SourceProcessId="4242",
        SourceImage="C:\\Users\\Public\\a.exe",
        TargetProcessGUID="{8D9A1C2E-1111-4A2B-9C3D-0000000000B2}",
        TargetImage="C:\\Windows\\System32\\lsass.exe",
        GrantedAccess="0x1FFFFF",
    )
    event = _event(record).event
    assert event.process_guid == GUID
    assert event.pid == 4242
    assert event.image == "C:\\Users\\Public\\a.exe"
    assert event.fields["target_process_guid"] == "8d9a1c2e-1111-4a2b-9c3d-0000000000b2"
    assert event.fields["granted_access"] == "0x1fffff"


def test_bad_and_zero_guids(make_record: Any) -> None:
    record = make_record(
        1,
        ProcessGuid="not-a-guid",
        ParentProcessGuid="{00000000-0000-0000-0000-000000000000}",
    )
    result = _event(record)
    assert result.bad_guids == 1
    assert result.event.process_guid is None
    assert result.event.fields["process_guid"] == "not-a-guid"


def test_host_lowercased_and_missing_host(make_record: Any) -> None:
    assert _event(make_record(1, host="WS-14.Corp.Example")).event.host == "ws-14.corp.example"
    record = make_record(1)
    del record["Hostname"]
    assert _event(record).event.host == "unknown"


@pytest.mark.parametrize(
    "channel", ["Microsoft-Windows-Sysmon/Operational", "microsoft-windows-sysmon/operational"]
)
def test_sysmon_by_channel(make_record: Any, channel: str) -> None:
    assert isinstance(_norm(make_record(1, channel=channel)), Normalized)


def test_sysmon_by_provider_only() -> None:
    record = {
        "EventID": 1,
        "SourceName": "microsoft-windows-sysmon",
        "UtcTime": "2026-10-12 10:00:00",
    }
    event = _event(record).event
    assert event.channel == "Microsoft-Windows-Sysmon/Operational"


def test_non_sysmon_is_irrelevant(make_record: Any) -> None:
    outcome = _norm(make_record(4688, channel="Security"))
    assert outcome == Irrelevant("Security")
    outcome = _norm({"EventID": 7045, "SourceName": "Service Control Manager", "Hostname": "h"})
    assert outcome == Irrelevant("(no channel)")


def test_irrelevant_checked_before_validity() -> None:
    record = {"EventID": "x", "Channel": "Security"}
    assert isinstance(_norm(record), Irrelevant)


def test_unknown_shape_and_no_event_id(make_record: Any) -> None:
    assert _norm({"a": 1}) == Invalid("unknown_shape")
    assert _norm(make_record("abc")) == Invalid("no_event_id")
    assert _norm(make_record(True)) == Invalid("no_event_id")


def test_timestamp_prefers_utc_time(make_record: Any) -> None:
    record = make_record(1, TimeCreated="2026-10-12T09:00:00Z")
    event = _event(record).event
    assert event.ts_us == parse_utc_time("2026-10-12 10:41:58.123")
    assert event.ts_source == "utc_time"


def test_timestamp_falls_back_to_time_created(make_record: Any) -> None:
    record = make_record(1, utc_time="", TimeCreated="2026-10-12T09:00:00.1234567Z")
    event = _event(record).event
    assert event.ts_us == parse_iso("2026-10-12T09:00:00.123456Z")
    assert event.ts_source == "time_created"


def test_unparseable_utc_time_falls_back(make_record: Any) -> None:
    record = make_record(1, utc_time="yesterday", **{"@timestamp": "2026-10-12T09:00:00Z"})
    event = _event(record).event
    assert event.ts_source == "other"


@pytest.mark.parametrize(
    ("extra", "reason"),
    [
        ({}, "no_timestamp"),
        ({"EventTime": "2026-10-12 10:43:04"}, "naive_timestamp"),
        ({"TimeCreated": "garbage"}, "no_timestamp"),
        ({"TimeCreated": "1980-01-01T00:00:00Z"}, "implausible_timestamp"),
        ({"UtcTime": "1601-01-01 00:00:00.000"}, "implausible_timestamp"),
    ],
)
def test_timestamp_invalid_reasons(make_record: Any, extra: dict[str, str], reason: str) -> None:
    record = make_record(1, utc_time="", **extra)
    assert _norm(record) == Invalid(reason)


def test_shape_a_event_id_object_and_system_time() -> None:
    record = {
        "Event": {
            "System": {
                "Provider": {"#attributes": {"Name": "Microsoft-Windows-Sysmon"}},
                "EventID": {"#attributes": {"Qualifiers": ""}, "#text": 3},
                "EventRecordID": 12,
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "Computer": "WS-14.corp.example",
                "TimeCreated": {"#attributes": {"SystemTime": "2026-10-12T10:41:58.1239876Z"}},
            },
            "EventData": {"ProcessId": 4242},
        }
    }
    event = _event(record).event
    assert event.event_id == 3
    assert event.record_id == 12
    assert event.ts_source == "time_created"
    assert event.ts_us == parse_iso("2026-10-12T10:41:58.123987Z")


def test_shape_a_outer_record_id_fallback() -> None:
    record = {
        "Event": {
            "System": {"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational"},
            "EventData": {"UtcTime": "2026-10-12 10:41:58.123"},
        },
        "event_record_id": 55,
        "timestamp": "2026-10-12 10:41:58.123000 UTC",
    }
    assert _event(record).event.record_id == 55
