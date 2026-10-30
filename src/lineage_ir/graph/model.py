"""Process graph container: one frozen graph per host (§7)."""

from lineage_ir.models import Event, FrozenModel, ImageLoad, ProcessNode


class BrokenEdge(FrozenModel):
    """A parent edge removed to break a parent loop (§7.3)."""

    child: str
    parent: str


class GraphCounters(FrozenModel):
    """Graph-stage counters reported into coverage."""

    ghosts: dict[str, int]
    creation_conflicts: int
    duplicate_creations: int
    cycles_broken: int
    unattached_events: int


class ProcessGraph(FrozenModel):
    """All process nodes of one host plus the events that belong to no node."""

    host: str
    nodes: dict[str, ProcessNode]
    roots: tuple[str, ...]
    wmi_events: tuple[Event, ...]
    unattached_events: tuple[Event, ...]
    unattached_image_loads: tuple[ImageLoad, ...]
    broken_edges: tuple[BrokenEdge, ...]
    counters: GraphCounters
