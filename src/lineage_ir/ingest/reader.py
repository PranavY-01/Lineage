"""Input discovery, hashing, format sniffing and the ingest pipeline (§4.3 steps 1-4)."""

import hashlib
from collections import Counter
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from lineage_ir.config import (
    DEFAULT_MAX_ERRORS,
    DEFAULT_MAX_FILE_SIZE_MB,
    DEFAULT_MAX_RECORDS,
    EVTX_MAGIC,
    HASH_CHUNK_BYTES,
    JSON_LINE_CAP_BYTES,
    MAX_INPUTS,
    MIB,
)
from lineage_ir.errors import InputError, UsageError
from lineage_ir.ingest.normalize import Invalid, Irrelevant, dedupe_and_sort, normalize_record
from lineage_ir.ingest.windows.evtx_reader import read_evtx
from lineage_ir.ingest.windows.json_reader import (
    UTF8_BOM,
    RawItem,
    is_jsonl,
    read_json_document,
    read_jsonl,
)
from lineage_ir.models import (
    Event,
    IngestCounters,
    IngestResult,
    InputFile,
    InputFormat,
    InvalidRecord,
    TimeSpan,
)

UTF16_HINT = (
    "re-export as UTF-8, for example in PowerShell: "
    "Get-Content in.json | Out-File -Encoding utf8 out.json"
)

_WIDE_BOMS = (
    (b"\xff\xfe\x00\x00", "UTF-32"),
    (b"\x00\x00\xfe\xff", "UTF-32"),
    (b"\xff\xfe", "UTF-16"),
    (b"\xfe\xff", "UTF-16"),
)


@dataclass(frozen=True)
class IngestOptions:
    """Caps and filters that apply while reading."""

    max_records: int = DEFAULT_MAX_RECORDS
    max_file_size_mb: int = DEFAULT_MAX_FILE_SIZE_MB
    max_error_samples: int = DEFAULT_MAX_ERRORS
    hosts: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True, slots=True)
class _Resolved:
    path: Path
    info: InputFile


def check_paths(paths: Sequence[Path], max_file_size_mb: int) -> None:
    """Reject missing paths, directories and over-size files before any reading (exit 2)."""
    if not paths:
        raise UsageError("at least one input file is required")
    if len(paths) > MAX_INPUTS:
        raise UsageError(f"at most {MAX_INPUTS} input files are accepted")
    limit = max_file_size_mb * MIB
    for path in paths:
        if path.is_dir():
            raise UsageError(
                f"{path}: is a directory; directory input is not supported, "
                "pass the files inside it instead"
            )
        if not path.exists():
            raise UsageError(f"{path}: file not found")
        if not path.is_file():
            raise UsageError(f"{path}: not a regular file")
        if path.stat().st_size > limit:
            raise UsageError(f"{path}: larger than --max-file-size {max_file_size_mb} MB")


def hash_file(path: Path) -> str:
    """Streamed SHA-256 of a file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(HASH_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sniff_format(path: Path) -> InputFormat:
    """Detect EVTX, JSON or JSONL from content; raise InputError when it is none of them."""
    with path.open("rb") as handle:
        head = handle.read(len(EVTX_MAGIC))
        if head == EVTX_MAGIC:
            return "evtx"
        for bom, name in _WIDE_BOMS:
            if head.startswith(bom):
                raise InputError(f"{path.name}: {name} encoded JSON is not supported; {UTF16_HINT}")
        handle.seek(len(UTF8_BOM) if head.startswith(UTF8_BOM) else 0)
        first_line = b""
        while True:
            line = handle.readline(JSON_LINE_CAP_BYTES + 1)
            if not line:
                break
            if line.strip():
                first_line = line
                break

    stripped = first_line.lstrip()
    if not stripped:
        return "jsonl"
    if stripped.startswith(b"["):
        return "json"
    if stripped.startswith(b"{"):
        too_long = len(first_line) > JSON_LINE_CAP_BYTES and not first_line.endswith(b"\n")
        return "jsonl" if too_long or is_jsonl(first_line) else "json"
    raise InputError(f"{path.name}: not an EVTX, JSON or JSONL file")


def resolve_inputs(
    paths: Sequence[Path], options: IngestOptions
) -> tuple[list[_Resolved], list[str]]:
    """Check, hash and sniff every input; drop byte-identical repeats with a warning."""
    check_paths(paths, options.max_file_size_mb)
    resolved: list[_Resolved] = []
    warnings: list[str] = []
    seen: dict[str, str] = {}
    for path in paths:
        try:
            sha256 = hash_file(path)
            fmt = sniff_format(path)
            size = path.stat().st_size
        except OSError as exc:
            raise InputError(f"{path}: cannot be read") from exc
        if sha256 in seen:
            warnings.append(f"{path.name}: skipped, same content as {seen[sha256]}")
            continue
        seen[sha256] = path.name
        resolved.append(
            _Resolved(path, InputFile(label=path.name, format=fmt, sha256=sha256, size_bytes=size))
        )
    return resolved, warnings


def _records(item: _Resolved) -> Iterator[RawItem]:
    if item.info.format == "evtx":
        return read_evtx(item.path)
    if item.info.format == "json":
        return read_json_document(item.path)
    return read_jsonl(item.path)


def _span(events: Iterable[Event]) -> TimeSpan | None:
    stamps = [e.ts_us for e in events]
    return TimeSpan(start_us=min(stamps), end_us=max(stamps)) if stamps else None


def read_inputs(paths: Sequence[Path], options: IngestOptions | None = None) -> IngestResult:
    """Read, normalize, deduplicate and sort every input into an IngestResult."""
    options = options or IngestOptions()
    resolved, warnings = resolve_inputs(paths, options)
    host_filter = frozenset(h.lower() for h in options.hosts)

    records_total = sysmon = 0
    irrelevant: Counter[str] = Counter()
    invalid: Counter[str] = Counter()
    unknown_keys: Counter[str] = Counter()
    samples: list[InvalidRecord] = []
    bad_guid = out_of_order = 0
    cap_reached = False
    accepted: list[tuple[int, Event]] = []
    hosts_seen: set[str] = set()

    for file_order, item in enumerate(resolved):
        label = item.info.label
        previous_ts: int | None = None
        try:
            for raw in _records(item):
                if records_total >= options.max_records:
                    cap_reached = True
                    break
                records_total += 1
                if raw.reason is not None:
                    outcome: object = Invalid(raw.reason)
                else:
                    outcome = normalize_record(raw.record, label, item.info.sha256, raw.index)
                if isinstance(outcome, Invalid):
                    invalid[outcome.reason] += 1
                    if len(samples) < options.max_error_samples:
                        samples.append(
                            InvalidRecord(file=label, index=raw.index, reason=outcome.reason)
                        )
                    continue
                if isinstance(outcome, Irrelevant):
                    irrelevant[outcome.channel] += 1
                    continue
                sysmon += 1
                event = outcome.event
                unknown_keys.update(outcome.unknown_keys)
                bad_guid += outcome.bad_guids
                if previous_ts is not None and event.ts_us < previous_ts:
                    out_of_order += 1
                previous_ts = event.ts_us
                hosts_seen.add(event.host)
                if host_filter and event.host not in host_filter:
                    continue
                accepted.append((file_order, event))
        except OSError as exc:
            raise InputError(f"{label}: read failed") from exc
        if cap_reached:
            break

    warnings.extend(
        f"--host {host}: no events for this host" for host in sorted(host_filter - hosts_seen)
    )
    deduped = dedupe_and_sort(accepted)
    events = deduped.events
    event_ids = Counter(e.event_id for e in events)

    reasons: set[str] = set()
    if not events:
        reasons.add("no_events")
    if invalid:
        reasons.add("invalid_records")
    if deduped.duplicate_conflicts:
        reasons.add("duplicate_conflicts")
    if cap_reached:
        reasons.add("record_cap_reached")

    counters = IngestCounters(
        records_total=records_total,
        sysmon=sysmon,
        irrelevant=sum(irrelevant.values()),
        irrelevant_by_channel=dict(sorted(irrelevant.items())),
        invalid=sum(invalid.values()),
        invalid_by_reason=dict(sorted(invalid.items())),
        duplicates_dropped=deduped.duplicates_dropped,
        duplicate_conflicts=deduped.duplicate_conflicts,
        bad_guid=bad_guid,
        out_of_order=out_of_order,
    )
    return IngestResult(
        inputs=tuple(r.info for r in resolved),
        events=events,
        counters=counters,
        event_ids_seen={str(k): event_ids[k] for k in sorted(event_ids)},
        hosts=tuple(sorted({e.host for e in events})),
        span=_span(events),
        unknown_keys=dict(sorted(unknown_keys.items())),
        invalid_samples=tuple(samples),
        record_cap_reached=cap_reached,
        reasons=tuple(sorted(reasons)),
        warnings=tuple(warnings),
    )
