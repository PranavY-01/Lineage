"""Raw record -> Event normalization (§6.3-6.7), deduplication and ordering (§6.8)."""

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Literal

from lineage_ir.config import SYSMON_CHANNEL, SYSMON_PROVIDER
from lineage_ir.ingest.field_aliases import TIME_CREATED_CANDIDATES, normalize_key, resolve_system
from lineage_ir.ingest.shapes import detect_shape
from lineage_ir.ingest.timeparse import NaiveTimestamp, parse_iso, parse_utc_time
from lineage_ir.models import Event, SourceRef

_GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_ZERO_GUID = "00000000-0000-0000-0000-000000000000"
_MISSING = frozenset({"", "-"})

GUID_FIELDS = ("process_guid", "parent_process_guid", "source_process_guid", "target_process_guid")
PID_FIELDS = ("pid", "parent_pid", "source_pid", "target_pid")
PATH_FIELDS = (
    "image",
    "parent_image",
    "target_filename",
    "source_image",
    "target_image",
    "current_directory",
)

# Events whose acting process is the source of an access (§6.5).
_SOURCE_ACTING = frozenset({8, 10})


@dataclass(frozen=True, slots=True)
class Normalized:
    """A Sysmon record turned into an Event."""

    event: Event
    unknown_keys: tuple[str, ...]
    bad_guids: int


@dataclass(frozen=True, slots=True)
class Irrelevant:
    """A record from a channel other than Sysmon."""

    channel: str


@dataclass(frozen=True, slots=True)
class Invalid:
    """A record that could not be normalized, with its reason code."""

    reason: str


Outcome = Normalized | Irrelevant | Invalid


def canonical_guid(value: str | None) -> tuple[str | None, bool]:
    """Return the canonical GUID (or None) and whether the input was a malformed GUID."""
    if value is None:
        return None, False
    text = value.strip()
    if text in _MISSING:
        return None, False
    text = text.strip("{}").strip().lower()
    if not _GUID.match(text):
        return None, True
    if text == _ZERO_GUID:
        return None, False
    return text, False


def parse_pid(value: str | None) -> int | None:
    """Parse a decimal or ``0x`` hex PID; None when absent or malformed."""
    if value is None:
        return None
    text = value.strip()
    try:
        if text.lower().startswith("0x"):
            return int(text[2:], 16)
        if text.isdigit():
            return int(text)
    except ValueError:
        return None
    return None


def parse_hashes(value: str | None) -> dict[str, str]:
    """Parse ``ALGO=VALUE`` pairs separated by commas into lowercase keys and values."""
    result: dict[str, str] = {}
    if not value:
        return result
    for part in value.split(","):
        algo, sep, digest = part.partition("=")
        algo, digest = algo.strip().lower(), digest.strip().lower()
        if sep and algo and digest and algo not in result:
            result[algo] = digest
    return result


def normalize_path(value: str) -> str:
    """Matching form of a path: backslashes, no long-path prefix, lowercase."""
    text = value.replace("/", "\\")
    for prefix in ("\\\\?\\", "\\??\\"):
        if text.startswith(prefix):
            text = text[len(prefix) :]
            break
    return text.lower()


def image_name(path: str | None) -> str | None:
    """Lowercase basename after splitting on ``\\`` and ``/``."""
    if not path:
        return None
    name = path.replace("/", "\\").rsplit("\\", 1)[-1].strip().lower()
    return name or None


def normalize_granted_access(value: str) -> str:
    """Lowercase ``0x`` hex form of a GrantedAccess mask."""
    text = value.strip().lower()
    if text.startswith("0x"):
        try:
            return f"0x{int(text[2:], 16):x}"
        except ValueError:
            return text
    return text


def _to_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return value
    if isinstance(value, int | float):
        return str(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _event_id(value: Any) -> int | None:
    if isinstance(value, Mapping):
        value = value.get("#text")
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _record_id(value: Any) -> int | None:
    if isinstance(value, Mapping):
        value = value.get("#text")
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _is_sysmon(channel: str | None, provider: str | None) -> bool:
    return (channel is not None and channel.casefold() == SYSMON_CHANNEL.casefold()) or (
        provider is not None and provider.casefold() == SYSMON_PROVIDER.casefold()
    )


def _timestamp(
    fields: Mapping[str, str], time_value: Any, time_candidate: str | None
) -> tuple[int, Literal["utc_time", "time_created", "other"]] | str:
    """Return (ts_us, ts_source) or an invalid reason code."""
    utc_time = fields.get("utc_time")
    if utc_time:
        try:
            return parse_utc_time(utc_time), "utc_time"
        except OverflowError:
            return "implausible_timestamp"
        except ValueError:
            pass
    if isinstance(time_value, str):
        try:
            ts = parse_iso(time_value)
        except NaiveTimestamp:
            return "naive_timestamp"
        except OverflowError:
            return "implausible_timestamp"
        except ValueError:
            return "no_timestamp"
        source = "time_created" if time_candidate in TIME_CREATED_CANDIDATES else "other"
        return ts, source
    return "no_timestamp"


def _event_data(raw: Mapping[str, Any]) -> tuple[dict[str, str], list[str]]:
    fields: dict[str, str] = {}
    unknown: list[str] = []
    for key, value in raw.items():
        if not isinstance(key, str):
            continue
        name, known = normalize_key(key)
        text = _to_text(value)
        if text is None or name in fields:
            continue
        fields[name] = text
        if not known:
            unknown.append(key)
    return fields, unknown


def normalize_record(record: object, file: str, file_sha256: str, index: int) -> Outcome:
    """Classify one raw record and, for Sysmon records, build its Event."""
    shaped = detect_shape(record)
    if shaped is None:
        return Invalid("unknown_shape")
    shape_a = shaped.shape == "A"

    channel_value, _ = resolve_system(shaped.system, "channel", shape_a=shape_a)
    provider_value, _ = resolve_system(shaped.system, "provider", shape_a=shape_a)
    channel = _to_text(channel_value)
    provider = _to_text(provider_value)
    if not _is_sysmon(channel, provider):
        return Irrelevant(channel or "(no channel)")

    event_id = _event_id(resolve_system(shaped.system, "event_id", shape_a=shape_a)[0])
    if event_id is None:
        return Invalid("no_event_id")

    fields, unknown = _event_data(shaped.event_data)

    time_value, time_candidate = resolve_system(shaped.system, "time_created", shape_a=shape_a)
    stamp = _timestamp(fields, time_value, time_candidate)
    if isinstance(stamp, str):
        return Invalid(stamp)
    ts_us, ts_source = stamp

    bad_guids = 0
    for key in GUID_FIELDS:
        if key in fields:
            guid, bad = canonical_guid(fields[key])
            bad_guids += bad
            if guid is not None:
                fields[key] = guid
    for key in PID_FIELDS:
        if key in fields:
            pid = parse_pid(fields[key])
            if pid is not None:
                fields[key] = str(pid)
    if "granted_access" in fields:
        fields["granted_access"] = normalize_granted_access(fields["granted_access"])

    if event_id in _SOURCE_ACTING:
        guid_key, pid_key, image_key = "source_process_guid", "source_pid", "source_image"
    else:
        guid_key, pid_key, image_key = "process_guid", "pid", "image"

    host_value = _to_text(resolve_system(shaped.system, "host", shape_a=shape_a)[0])
    record_id = _record_id(resolve_system(shaped.system, "record_id", shape_a=shape_a)[0])

    event = Event(
        host=(host_value or "unknown").strip().lower(),
        channel=channel or SYSMON_CHANNEL,
        event_id=event_id,
        ts_us=ts_us,
        ts_source=ts_source,
        record_id=record_id,
        process_guid=canonical_guid(fields.get(guid_key))[0],
        pid=parse_pid(fields.get(pid_key)),
        image=fields.get(image_key) or None,
        fields=fields,
        source=SourceRef(file=file, file_sha256=file_sha256, index=index, record_id=record_id),
    )
    return Normalized(event, tuple(unknown), bad_guids)


def content_digest(event: Event) -> str:
    """SHA-256 of the canonical JSON of an event without its provenance."""
    payload = event.model_dump(mode="json", exclude={"source"})
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(blob.encode("ascii")).hexdigest()


@dataclass(frozen=True, slots=True)
class Deduped:
    """Events in global order plus dedupe counters."""

    events: tuple[Event, ...]
    duplicates_dropped: int
    duplicate_conflicts: int


def dedupe_and_sort(events_in_input_order: Iterable[tuple[int, Event]]) -> Deduped:
    """Drop duplicates (first by input order wins) and sort globally (§6.8).

    Each item is ``(input_file_order, event)``; items must arrive in input order.
    """
    seen: dict[tuple[str, ...], str] = {}
    kept: list[tuple[tuple[str, int, int, int, int], Event]] = []
    dropped = conflicts = 0
    for file_order, event in events_in_input_order:
        digest = content_digest(event)
        if event.record_id is not None:
            key: tuple[str, ...] = (event.host, event.channel, str(event.record_id))
        else:
            key = ("digest", digest)
        previous = seen.get(key)
        if previous is not None:
            if previous == digest:
                dropped += 1
            else:
                conflicts += 1
            continue
        seen[key] = digest
        sort_key = (
            event.host,
            event.ts_us,
            event.record_id or 0,
            file_order,
            event.source.index,
        )
        kept.append((sort_key, event))
    kept.sort(key=lambda item: item[0])
    return Deduped(tuple(e for _, e in kept), dropped, conflicts)
