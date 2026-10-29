"""Raw record -> Event normalization (§6.3-6.7), deduplication and ordering (§6.8)."""

import hashlib
import json
import re
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Literal

from lineage_ir.config import SYSMON_CHANNEL, SYSMON_PROVIDER
from lineage_ir.ingest.field_aliases import TIME_CREATED_CANDIDATES, normalize_key, resolve_system
from lineage_ir.ingest.shapes import detect_shape
from lineage_ir.ingest.timeparse import NaiveTimestamp, parse_iso, parse_utc_time
from lineage_ir.models import (
    IMAGE_LOAD_EVENT_ID,
    ActivityKind,
    Event,
    ImageLoadRecord,
    SourceRef,
)

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
class NormalizedImageLoad:
    """A Sysmon event 7 in its slim form."""

    event: ImageLoadRecord
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


Outcome = Normalized | NormalizedImageLoad | Irrelevant | Invalid


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


def _interned(value: str | None) -> str | None:
    return None if value is None else sys.intern(value)


def normalize_record(
    record: object,
    file: str,
    file_sha256: str,
    index: int,
    *,
    slim_image_loads: bool = True,
) -> Outcome:
    """Classify one raw record and, for Sysmon records, build its Event.

    Event 7 becomes a slim ImageLoadRecord unless ``slim_image_loads`` is false, which
    exists so tests can compare the slim path with a full-Event build.
    """
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
    host = (host_value or "unknown").strip().lower()

    if event_id == IMAGE_LOAD_EVENT_ID and slim_image_loads:
        load = ImageLoadRecord(
            host=sys.intern(host),
            channel=sys.intern(channel or SYSMON_CHANNEL),
            record_id=record_id,
            ts_us=ts_us,
            process_guid=_interned(canonical_guid(fields.get("process_guid"))[0]),
            pid=parse_pid(fields.get("pid")),
            image=_interned(fields.get("image") or None),
            user=_interned(fields.get("user")),
            image_loaded=_interned(fields.get("image_loaded")),
            signed=_interned(fields.get("signed")),
            file=file,
            file_sha256=file_sha256,
            index=index,
        )
        return NormalizedImageLoad(load, tuple(unknown), bad_guids)

    event = Event(
        host=host,
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


WMI_EVENT_IDS = frozenset({19, 20, 21})

_ACTIVITY_KINDS: dict[int, ActivityKind] = {
    3: "network",
    5: "terminate",
    8: "remote_thread",
    10: "process_access",
    11: "file_create",
    12: "registry",
    13: "registry",
    14: "registry",
    15: "file_stream",
    17: "pipe",
    18: "pipe",
    19: "wmi",
    20: "wmi",
    21: "wmi",
    22: "dns",
    23: "file_delete",
    26: "file_delete",
}


def activity_kind(event_id: int) -> ActivityKind:
    """Activity category for a non-creation event ID; unlisted IDs are ``other``."""
    return _ACTIVITY_KINDS.get(event_id, "other")


def _endpoint(ip: str, port: str, protocol: str) -> str:
    host = f"[{ip}]" if ":" in ip else ip
    return f"{host}:{port}/{protocol}" if protocol else f"{host}:{port}"


def activity_summary(event: Event, role: Literal["actor", "target"] = "actor") -> str:
    """Short, unescaped one-line description of a non-creation event (§5.4)."""
    f = event.fields
    kind = activity_kind(event.event_id)
    if kind == "network":
        protocol = f.get("protocol", "")
        if f.get("initiated", "").lower() == "false":
            peer = _endpoint(f.get("source_ip", "?"), f.get("source_port", "?"), protocol)
            return f"← {peer}"
        text = "→ " + _endpoint(
            f.get("destination_ip", "?"), f.get("destination_port", "?"), protocol
        )
        hostname = f.get("destination_hostname", "")
        return f"{text} ({hostname})" if hostname and hostname != "-" else text
    if kind == "dns":
        return f"resolved {f.get('query_name', '?')}"
    if kind == "file_create":
        return f"wrote {f.get('target_filename', '?')}"
    if kind == "file_delete":
        return f"deleted {f.get('target_filename', '?')}"
    if kind == "file_stream":
        return f"stream {f.get('target_filename', '?')}"
    if kind == "registry":
        target = f.get("target_object", "?")
        if event.event_id == 14:
            return f"renamed {target} → {f.get('new_name', '?')}"
        if event.event_id == 13:
            return f"set {target} = {f.get('details', '')}"
        return f"{f.get('event_type', 'registry')} {target}"
    if kind in ("process_access", "remote_thread"):
        verb = "accessed" if kind == "process_access" else "remote thread into"
        access = f" ({f['granted_access']})" if "granted_access" in f else ""
        if role == "target":
            passive = "accessed by" if kind == "process_access" else "remote thread from"
            return f"{passive} {f.get('source_image', '?')}{access}"
        return f"{verb} {f.get('target_image', '?')}{access}"
    if kind == "pipe":
        verb = "created pipe" if event.event_id == 17 else "connected pipe"
        return f"{verb} {f.get('pipe_name', '?')}"
    if kind == "terminate":
        return "terminated"
    if kind == "wmi":
        name = f.get("name") or f.get("consumer") or f.get("filter") or "?"
        return f"wmi {f.get('event_type', 'event')} {name}"
    return f"event {event.event_id}"


def _sha256_json(payload: object) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(blob.encode("ascii")).hexdigest()


def image_load_record(event: Event) -> ImageLoadRecord:
    """The slim form of a full event 7 (used when a full Event reaches the graph)."""
    return ImageLoadRecord(
        host=event.host,
        channel=event.channel,
        record_id=event.record_id,
        ts_us=event.ts_us,
        process_guid=event.process_guid,
        pid=event.pid,
        image=event.image,
        user=event.fields.get("user"),
        image_loaded=event.fields.get("image_loaded"),
        signed=event.fields.get("signed"),
        file=event.source.file,
        file_sha256=event.source.file_sha256,
        index=event.source.index,
    )


Item = Event | ImageLoadRecord


def content_digest(item: Item) -> str:
    """SHA-256 of a record's canonical content without its provenance.

    Event 7 is hashed in its slim form whether it arrives as an Event or an ImageLoadRecord,
    so both paths deduplicate and order image loads identically.
    """
    if isinstance(item, Event) and item.event_id == IMAGE_LOAD_EVENT_ID:
        item = image_load_record(item)
    if isinstance(item, ImageLoadRecord):
        return _sha256_json(["image_load", *item.content()])
    return _sha256_json(item.model_dump(mode="json", exclude={"source"}))


def _location(item: Item) -> tuple[str, int]:
    if isinstance(item, ImageLoadRecord):
        return item.file, item.index
    return item.source.file, item.source.index


class DigestCache:
    """Content hashes computed on demand and remembered per record object."""

    def __init__(self) -> None:
        self._cache: dict[int, str] = {}
        self._keep: list[Item] = []

    def __call__(self, item: Item) -> str:
        key = id(item)
        digest = self._cache.get(key)
        if digest is None:
            digest = self._cache[key] = content_digest(item)
            self._keep.append(item)  # keeps id() unique while the cache is alive
        return digest


def global_order(items: list[tuple[int, Item]], digest: DigestCache) -> list[Item]:
    """Sort by (host, ts_us, record_id or 0, content hash, input file order, index) (§6.8).

    The content hash is computed only for records whose first three keys tie.
    """
    items.sort(key=lambda p: (p[1].host, p[1].ts_us, p[1].record_id or 0, p[0], _location(p[1])[1]))
    ordered: list[Item] = []
    start = 0
    while start < len(items):
        head = items[start][1]
        key = (head.host, head.ts_us, head.record_id or 0)
        end = start + 1
        while end < len(items):
            other = items[end][1]
            if (other.host, other.ts_us, other.record_id or 0) != key:
                break
            end += 1
        run = items[start:end]
        if len(run) > 1:
            run.sort(key=lambda p: (digest(p[1]), p[0], _location(p[1])[1]))
        ordered.extend(item for _, item in run)
        start = end
    return ordered


@dataclass(frozen=True, slots=True)
class Deduped:
    """Events and image loads in global order, dedupe counters and conflict locations."""

    events: tuple[Event, ...]
    image_loads: tuple[ImageLoadRecord, ...]
    duplicates_dropped: int
    duplicate_conflicts: int
    conflicts: tuple[tuple[tuple[str, int], tuple[str, int]], ...]


def dedupe_and_sort(items_in_input_order: Iterable[tuple[int, Item]]) -> Deduped:
    """Drop duplicates and sort globally (§6.8, as amended).

    Each item is ``(input_file_order, record)`` and items arrive in input order. Records with
    a record ID are keyed by (host, channel, record ID) and hashed only on a key collision;
    records without one are keyed by their content hash. Identical copies keep the first
    seen; conflicting copies keep the earliest ``ts_us``, then the smallest content hash.
    Each conflict is reported as ((kept file, index), (dropped file, index)).
    """
    digest = DigestCache()
    kept: dict[tuple[object, ...], tuple[int, Item]] = {}
    dropped = 0
    conflicts: list[tuple[tuple[str, int], tuple[str, int]]] = []
    for file_order, item in items_in_input_order:
        if item.record_id is not None:
            key: tuple[object, ...] = (item.host, item.channel, item.record_id)
        else:
            key = ("digest", digest(item))
        previous = kept.get(key)
        if previous is None:
            kept[key] = (file_order, item)
            continue
        old = previous[1]
        if digest(old) == digest(item):
            dropped += 1
            continue
        if (item.ts_us, digest(item)) < (old.ts_us, digest(old)):
            kept[key] = (file_order, item)
            conflicts.append((_location(item), _location(old)))
        else:
            conflicts.append((_location(old), _location(item)))

    survivors = list(kept.values())
    events = [p for p in survivors if isinstance(p[1], Event)]
    loads = [p for p in survivors if isinstance(p[1], ImageLoadRecord)]
    return Deduped(
        events=tuple(global_order(events, digest)),  # type: ignore[arg-type]
        image_loads=tuple(global_order(loads, digest)),  # type: ignore[arg-type]
        duplicates_dropped=dropped,
        duplicate_conflicts=len(conflicts),
        conflicts=tuple(conflicts),
    )
