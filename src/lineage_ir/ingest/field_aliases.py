"""System-level alias candidates (§6.3) and the EventData key map (§6.4)."""

import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

# Candidates in priority order. A dotted candidate is tried first as a literal key,
# then as a nested path.
SYSTEM_ALIASES: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "host": ("Computer", "Hostname", "host.name", "computer_name", "winlog.computer_name"),
        "channel": ("Channel", "channel", "winlog.channel", "log_name"),
        "provider": (
            "Provider.#attributes.Name",
            "SourceName",
            "ProviderName",
            "winlog.provider_name",
        ),
        "event_id": ("EventID", "EventId", "event_id", "winlog.event_id"),
        "record_id": ("EventRecordID", "RecordNumber", "record_id", "winlog.record_id"),
        "time_created": (
            "TimeCreated.#attributes.SystemTime",
            "TimeCreated",
            "@timestamp",
            "EventTime",
        ),
    }
)

# Extra candidates that apply to shape A only, appended after the shared list.
SHAPE_A_EXTRA: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {"record_id": ("event_record_id",), "time_created": ("timestamp",)}
)

# Candidates whose value counts as a "TimeCreated" source; others report ts_source "other".
TIME_CREATED_CANDIDATES = frozenset({"TimeCreated.#attributes.SystemTime", "TimeCreated"})

# Top-level keys that hold system values in flat (shape B) records, so they are not
# treated as EventData.
FLAT_SYSTEM_KEYS = frozenset(
    head
    for candidates in SYSTEM_ALIASES.values()
    for head in (c.split(".", 1)[0] for c in candidates)
    if head != "winlog"
)

EVENT_ID_KEYS = ("EventID", "EventId", "event_id")

_EVENTDATA_MAP = {
    "UtcTime": "utc_time",
    "ProcessGuid": "process_guid",
    "ProcessId": "pid",
    "Image": "image",
    "CommandLine": "command_line",
    "CurrentDirectory": "current_directory",
    "User": "user",
    "IntegrityLevel": "integrity_level",
    "Hashes": "hashes",
    "LogonId": "logon_id",
    "LogonGuid": "logon_guid",
    "OriginalFileName": "original_file_name",
    "Company": "company",
    "Description": "description",
    "Product": "product",
    "ParentProcessGuid": "parent_process_guid",
    "ParentProcessId": "parent_pid",
    "ParentImage": "parent_image",
    "ParentCommandLine": "parent_command_line",
    "ParentUser": "parent_user",
    "Protocol": "protocol",
    "Initiated": "initiated",
    "SourceIp": "source_ip",
    "SourcePort": "source_port",
    "SourceHostname": "source_hostname",
    "DestinationIp": "destination_ip",
    "DestinationPort": "destination_port",
    "DestinationHostname": "destination_hostname",
    "TargetFilename": "target_filename",
    "CreationUtcTime": "creation_utc_time",
    "EventType": "event_type",
    "TargetObject": "target_object",
    "Details": "details",
    "NewName": "new_name",
    "QueryName": "query_name",
    "QueryStatus": "query_status",
    "QueryResults": "query_results",
    "SourceProcessGuid": "source_process_guid",
    "SourceProcessId": "source_pid",
    "SourceImage": "source_image",
    "TargetProcessGuid": "target_process_guid",
    "TargetProcessId": "target_pid",
    "TargetImage": "target_image",
    "GrantedAccess": "granted_access",
    "CallTrace": "call_trace",
    "StartAddress": "start_address",
    "StartModule": "start_module",
    "PipeName": "pipe_name",
    "ImageLoaded": "image_loaded",
    "Signed": "signed",
    "Signature": "signature",
    "Operation": "operation",
    "EventNamespace": "event_namespace",
    "Name": "name",
    "Query": "query",
    "Type": "type",
    "Destination": "destination",
    "Consumer": "consumer",
    "Filter": "filter",
    "IsExecutable": "is_executable",
    "Archived": "archived",
}

# Case-insensitive lookup: casefolded Sysmon key -> normalized key.
EVENTDATA_KEYS: Mapping[str, str] = MappingProxyType(
    {k.casefold(): v for k, v in _EVENTDATA_MAP.items()}
)

# Every normalized EventData key (the field names rules may use).
NORMALIZED_KEYS = frozenset(_EVENTDATA_MAP.values())

_CAMEL_LOWER = re.compile(r"([a-z0-9])([A-Z])")
_CAMEL_ACRONYM = re.compile(r"([A-Z]+)([A-Z][a-z])")
_NON_WORD = re.compile(r"[^0-9A-Za-z]+")


def to_snake(key: str) -> str:
    """Convert an unknown EventData key to lowercase snake_case."""
    s = _CAMEL_ACRONYM.sub(r"\1_\2", key)
    s = _CAMEL_LOWER.sub(r"\1_\2", s)
    s = _NON_WORD.sub("_", s).strip("_").lower()
    return s or "_"


def normalize_key(key: str) -> tuple[str, bool]:
    """Return the normalized key and whether it came from the explicit map."""
    known = EVENTDATA_KEYS.get(key.casefold())
    if known is not None:
        return known, True
    return to_snake(key), False


def lookup(container: Mapping[str, Any], path: str) -> Any:
    """Resolve ``path`` as a literal key, else as a dotted nested path; None when absent."""
    if path in container:
        return container[path]
    if "." not in path:
        return None
    current: Any = container
    for part in path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return None
        current = current[part]
    return current


def resolve_system(
    container: Mapping[str, Any], name: str, *, shape_a: bool = False
) -> tuple[Any, str | None]:
    """Return the first non-empty value for system field ``name`` and the candidate used."""
    candidates = SYSTEM_ALIASES[name]
    if shape_a:
        candidates = candidates + SHAPE_A_EXTRA.get(name, ())
    for candidate in candidates:
        value = lookup(container, candidate)
        if value is not None and value != "":
            return value, candidate
    return None, None
