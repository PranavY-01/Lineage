"""Library entry points; the CLI calls these and hands the results to a renderer."""

import time
import uuid
from collections.abc import Callable, Sequence
from pathlib import Path

from lineage_ir.config import READINESS_FAMILIES, STANDARD_EVENT_IDS
from lineage_ir.ingest.reader import IngestOptions, read_inputs
from lineage_ir.models import IngestResult, Readiness, ValidateResult

Clock = Callable[[], int]
RunIdFactory = Callable[[], str]


def now_us() -> int:
    """Current wall-clock time in microseconds since the Unix epoch."""
    return time.time_ns() // 1000


def new_run_id() -> str:
    """A fresh UUID4 run identifier."""
    return str(uuid.uuid4())


def readiness(event_ids_seen: dict[str, int]) -> tuple[Readiness, ...]:
    """Readiness of each rule family given the event IDs present (§11.2)."""
    present = {int(k) for k, count in event_ids_seen.items() if count > 0}
    result = []
    for family, needs, mode in READINESS_FAMILIES:
        missing = tuple(i for i in needs if i not in present)
        have = len(needs) - len(missing)
        if not missing or (mode == "any" and have):
            state = "ready"
        elif have:
            state = "partial"
        else:
            state = "missing"
        result.append(
            Readiness(family=family, needs=needs, mode=mode, state=state, missing=missing)
        )
    return tuple(result)


def validate_exit_code(ingest: IngestResult) -> int:
    """0 when every record was read and valid and Sysmon events exist, else 4 (§10.5)."""
    clean = ingest.counters.invalid == 0 and bool(ingest.events) and not ingest.record_cap_reached
    return 0 if clean else 4


def run_validate(
    inputs: Sequence[Path],
    options: IngestOptions | None = None,
    *,
    clock: Clock = now_us,
    run_id_factory: RunIdFactory = new_run_id,
) -> ValidateResult:
    """Read and normalize inputs without building a graph or running rules."""
    run_id = run_id_factory()
    started = clock()
    ingest = read_inputs(inputs, options)
    seen = {int(k) for k in ingest.event_ids_seen}
    exit_code = validate_exit_code(ingest)
    return ValidateResult(
        ingest=ingest,
        event_ids_missing=tuple(i for i in STANDARD_EVENT_IDS if i not in seen),
        readiness=readiness(ingest.event_ids_seen),
        valid=exit_code == 0,
        exit_code=exit_code,
        started_us=started,
        completed_us=clock(),
        run_id=run_id,
    )
