"""Pydantic models that carry all state between stages (§5)."""

from typing import Literal

from pydantic import BaseModel, ConfigDict


class FrozenModel(BaseModel):
    """Strict, immutable base: unknown fields are rejected."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


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
    """Deduplicated, sorted events plus everything ingest could not use."""

    inputs: tuple[InputFile, ...]
    events: tuple[Event, ...]
    counters: IngestCounters
    event_ids_seen: dict[str, int]
    hosts: tuple[str, ...]
    span: TimeSpan | None
    unknown_keys: dict[str, int]
    invalid_samples: tuple[InvalidRecord, ...]
    record_cap_reached: bool
    reasons: tuple[str, ...]
    warnings: tuple[str, ...]


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
