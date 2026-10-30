"""Storyline gaps and per-host telemetry gaps (§9.5)."""

import heapq
from collections.abc import Sequence

from lineage_ir.models import Gap, IngestResult, Step, TelemetryGap

US_PER_SECOND = 1_000_000


def storyline_gaps(steps: Sequence[Step], gap_seconds: int) -> tuple[Gap, ...]:
    """A Gap after each step followed by at least ``gap_seconds`` without storyline activity."""
    gaps = []
    for earlier, later in zip(steps, steps[1:], strict=False):
        delta = later.ts_us - earlier.ts_us
        if delta >= gap_seconds * US_PER_SECOND:
            gaps.append(Gap(after_step=earlier.n, seconds=delta // US_PER_SECOND))
    return tuple(gaps)


def telemetry_gaps(ingest: IngestResult, gap_seconds: int) -> tuple[TelemetryGap, ...]:
    """Pauses between consecutive Sysmon events of any kind on a host, image loads included.

    Events and image loads are each in global order (host, then time), so they are merged
    as two streams without being copied.
    """
    stamps = heapq.merge(
        ((e.host, e.ts_us) for e in ingest.events),
        ((load.host, load.ts_us) for load in ingest.image_loads),
    )
    threshold = gap_seconds * US_PER_SECOND
    gaps = []
    previous: tuple[str, int] | None = None
    for host, ts_us in stamps:
        if previous is not None and previous[0] == host and ts_us - previous[1] >= threshold:
            gaps.append(
                TelemetryGap(
                    host=host,
                    from_us=previous[1],
                    to_us=ts_us,
                    seconds=(ts_us - previous[1]) // US_PER_SECOND,
                )
            )
        previous = (host, ts_us)
    return tuple(gaps)
