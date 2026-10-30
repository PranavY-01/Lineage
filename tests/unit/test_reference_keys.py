"""EventData keys mapped for reference only (amendment 25): normalized, never rule fields."""

from pathlib import Path
from typing import Any

import pytest

from lineage_ir.detect.schema import ALLOWED_FIELDS, Rule
from lineage_ir.engine import run_validate
from lineage_ir.ingest.field_aliases import NORMALIZED_KEYS, normalize_key

REFERENCE_KEYS = {
    "FileVersion": "file_version",
    "PreviousCreationUtcTime": "previous_creation_utc_time",
    "SignatureStatus": "signature_status",
    "TerminalSessionId": "terminal_session_id",
    "DestinationIsIpv6": "destination_is_ipv6",
    "DestinationPortName": "destination_port_name",
    "SourceIsIpv6": "source_is_ipv6",
    "SourcePortName": "source_port_name",
    "SourceThreadId": "source_thread_id",
}


@pytest.mark.parametrize(("raw", "normalized"), sorted(REFERENCE_KEYS.items()))
def test_keys_are_mapped(raw: str, normalized: str) -> None:
    # (key, True): the key comes from the explicit map, so validate does not list it as unknown.
    assert normalize_key(raw) == (normalized, True)
    assert normalize_key(raw.lower()) == (normalized, True)
    assert normalized in NORMALIZED_KEYS


@pytest.mark.parametrize("field", sorted(REFERENCE_KEYS.values()))
def test_no_rule_may_use_them(field: str) -> None:
    assert field not in ALLOWED_FIELDS
    with pytest.raises(ValueError, match=field):
        Rule.model_validate(
            {
                "id": "TST-001",
                "title": "Test",
                "severity": "low",
                "attack": [],
                "tactics": ["execution"],
                "why": "Test.",
                "match": {"event_id": 1, field: "x"},
            }
        )


def test_validate_lists_no_unknown_keys(write_jsonl: Any, make_record: Any, tmp_path: Path) -> None:
    extra = {raw: "1" for raw in REFERENCE_KEYS}
    records = [
        make_record(
            1,
            1,
            ProcessGuid="{6c1e0a2b-7d3f-4e5a-9b8c-000000000001}",
            Image="C:\\Windows\\System32\\cmd.exe",
            **extra,
        ),
        make_record(
            3,
            2,
            ProcessGuid="{6c1e0a2b-7d3f-4e5a-9b8c-000000000001}",
            DestinationIp="203.0.113.5",
            DestinationPort="443",
            **extra,
        ),
    ]
    result = run_validate([write_jsonl(records)])
    assert result.ingest.unknown_keys == {}
    assert result.exit_code == 0
