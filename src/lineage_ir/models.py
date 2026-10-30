"""Pydantic models that carry all state between stages (§5)."""

from typing import Any, Literal, TypeVar

from pydantic import BaseModel, ConfigDict


class FrozenModel(BaseModel):
    """Strict, immutable base: unknown fields are rejected."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


_SHARED_FIELD_SETS: dict[type[BaseModel], set[str]] = {}
M = TypeVar("M", bound=BaseModel)


def construct_trusted(cls: type[M], /, **values: Any) -> M:
    """Build a model from values that normalization already typed, without re-validating.

    Used only for high-volume records (activities, image loads). All instances of a class
    share one fields-set, which roughly halves the per-object cost; the models are frozen,
    and pydantic copies the set before any update.
    """
    shared = _SHARED_FIELD_SETS.setdefault(cls, set(cls.model_fields))
    return cls.model_construct(shared, **values)


def trusted_event(file: str, file_sha256: str, index: int, **values: Any) -> "Event":
    """Build an Event and its SourceRef from values normalize has just validated.

    Only ``ingest/normalize.py`` calls this (enforced by a source test); a test checks that
    every Event built here equals the same Event built through full validation.
    """
    source = construct_trusted(
        SourceRef, file=file, file_sha256=file_sha256, index=index, record_id=values["record_id"]
    )
    return construct_trusted(Event, source=source, **values)


class SourceRef(FrozenModel):
    """Provenance of one record: input base name, its SHA-256 and position."""

    file: str
    file_sha256: str
    index: int
    record_id: int | None


class Event(FrozenModel):
    """One normalized Sysmon record."""

    host: str
    channel: str
    event_id: int
    ts_us: int
    ts_source: Literal["utc_time", "time_created", "other"]
    record_id: int | None
    process_guid: str | None
    pid: int | None
    image: str | None
    fields: dict[str, str]
    source: SourceRef


# §5.4 plus the approved "file_stream" (event 15) and "other" (generic Sysmon IDs) kinds.
ActivityKind = Literal[
    "network",
    "dns",
    "file_create",
    "file_delete",
    "file_stream",
    "registry",
    "process_access",
    "remote_thread",
    "pipe",
    "wmi",
    "terminate",
    "other",
]
GhostReason = Literal["parent_reference", "activity_reference", "access_reference"]

IMAGE_LOAD_EVENT_ID = 7
IMAGE_LOADS_KEPT = 50


class ImageLoad(FrozenModel):
    """One retained event 7 on a node; image loads are stored in this slim form only."""

    ts_us: int
    image_loaded: str | None
    signed: str | None
    source: SourceRef


class ImageLoadRecord:
    """Slim, immutable ingest form of an event 7: routing fields plus provenance.

    A plain slotted class instead of an Event keeps millions of image loads affordable;
    an ImageLoad with a full SourceRef is built only for the loads a node retains.
    """

    __slots__ = (
        "host",
        "channel",
        "record_id",
        "ts_us",
        "process_guid",
        "pid",
        "image",
        "user",
        "image_loaded",
        "signed",
        "file",
        "file_sha256",
        "index",
    )
    event_id = IMAGE_LOAD_EVENT_ID

    host: str
    channel: str
    record_id: int | None
    ts_us: int
    process_guid: str | None
    pid: int | None
    image: str | None
    user: str | None
    image_loaded: str | None
    signed: str | None
    file: str
    file_sha256: str
    index: int

    def __init__(self, **values: object) -> None:
        for name in self.__slots__:
            object.__setattr__(self, name, values[name])

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(f"{type(self).__name__} is immutable")

    def content(self) -> list[object]:
        """The identity of the record without its provenance."""
        return [
            self.host,
            self.channel,
            self.record_id,
            self.ts_us,
            self.process_guid,
            self.pid,
            self.image,
            self.user,
            self.image_loaded,
            self.signed,
        ]

    @property
    def source(self) -> SourceRef:
        return construct_trusted(
            SourceRef,
            file=self.file,
            file_sha256=self.file_sha256,
            index=self.index,
            record_id=self.record_id,
        )

    def to_image_load(self) -> ImageLoad:
        return construct_trusted(
            ImageLoad,
            ts_us=self.ts_us,
            image_loaded=self.image_loaded,
            signed=self.signed,
            source=self.source,
        )


class Activity(FrozenModel):
    """A non-creation event attached to a process node."""

    kind: ActivityKind
    event_id: int
    ts_us: int
    role: Literal["actor", "target"]
    summary: str
    fields: dict[str, str]
    source: SourceRef


class ProcessNode(FrozenModel):
    """One process instance on one host, created by event 1 or reconstructed as a ghost."""

    host: str
    guid: str
    pid: int | None
    image: str | None
    image_name: str | None
    command_line: str | None
    decoded_command: str | None
    decode_note: str | None
    user: str | None
    integrity_level: str | None
    hashes: dict[str, str]
    current_directory: str | None
    logon_id: str | None
    start_us: int | None
    end_us: int | None
    parent_guid: str | None
    children: tuple[str, ...]
    is_ghost: bool
    ghost_reason: GhostReason | None
    create_record: SourceRef | None
    activity: tuple[Activity, ...]
    image_load_count: int
    image_loads: tuple[ImageLoad, ...]


class ErrorEntry(FrozenModel):
    """A non-fatal problem; names files, indexes and reason codes, never record content."""

    kind: str
    subject: str
    message: str


InputFormat = Literal["evtx", "json", "jsonl"]


class InputFile(FrozenModel):
    """One analyzed input file."""

    label: str
    format: InputFormat
    sha256: str
    size_bytes: int


class InvalidRecord(FrozenModel):
    """Location and reason code of a record that could not be used."""

    file: str
    index: int
    reason: str


class IngestCounters(FrozenModel):
    """Ingest-stage counters reported into coverage (§10.1)."""

    records_total: int
    sysmon: int
    irrelevant: int
    irrelevant_by_channel: dict[str, int]
    invalid: int
    invalid_by_reason: dict[str, int]
    duplicates_dropped: int
    duplicate_conflicts: int
    bad_guid: int
    out_of_order: int


class TimeSpan(FrozenModel):
    """First and last event time in microseconds."""

    start_us: int
    end_us: int


class IngestResult(FrozenModel):
    """Deduplicated, sorted events plus everything ingest could not use.

    Event 7 records are kept apart in ``image_loads`` (same global order as ``events``).
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    inputs: tuple[InputFile, ...]
    events: tuple[Event, ...]
    image_loads: tuple[ImageLoadRecord, ...]
    counters: IngestCounters
    event_ids_seen: dict[str, int]
    hosts: tuple[str, ...]
    span: TimeSpan | None
    unknown_keys: dict[str, int]
    invalid_samples: tuple[InvalidRecord, ...]
    record_cap_reached: bool
    reasons: tuple[str, ...]
    warnings: tuple[str, ...]
    errors: tuple[ErrorEntry, ...]

    @property
    def event_count(self) -> int:
        """Sysmon events kept after deduplication, image loads included."""
        return len(self.events) + len(self.image_loads)


class Readiness(FrozenModel):
    """Whether the telemetry a rule family needs is present."""

    family: str
    needs: tuple[int, ...]
    mode: Literal["all", "any"]
    state: Literal["ready", "partial", "missing"]
    missing: tuple[int, ...]


class ValidateResult(FrozenModel):
    """Outcome of `lineage validate`: ingest result, readiness and exit code."""

    ingest: IngestResult
    event_ids_missing: tuple[int, ...]
    readiness: tuple[Readiness, ...]
    valid: bool
    exit_code: int
    started_us: int
    completed_us: int
    run_id: str
