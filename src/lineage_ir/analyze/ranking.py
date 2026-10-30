"""Storyline ranking (§9.3): no combined score, only an ordered tuple of plain criteria."""

from collections.abc import Iterable

from lineage_ir.analyze.filters import SEVERITY_RANK
from lineage_ir.models import Storyline


def rank_key(story: Storyline) -> tuple[int, int, int, int, str, str]:
    """Severity, distinct tactics and findings (all descending), then start, host and root."""
    return (
        -SEVERITY_RANK[story.max_severity],
        -len(story.tactics),
        -len(story.finding_ids),
        story.start_us,
        story.host,
        story.root_guid,
    )


def rank(storylines: Iterable[Storyline]) -> tuple[Storyline, ...]:
    """Sorted by ``rank_key`` and numbered S1, S2, …"""
    ordered = sorted(storylines, key=rank_key)
    return tuple(
        s.model_copy(update={"storyline_id": f"S{n}"}) for n, s in enumerate(ordered, start=1)
    )
