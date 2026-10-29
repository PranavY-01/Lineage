"""Record-shape detection (§6.2): where system fields and EventData live in a record."""

from collections import ChainMap
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from lineage_ir.ingest.field_aliases import (
    EVENT_ID_KEYS,
    EVENTDATA_KEYS,
    FLAT_SYSTEM_KEYS,
    SYSTEM_ALIASES,
    lookup,
)

Shape = Literal["A", "B", "C"]


@dataclass(frozen=True, slots=True)
class ShapedRecord:
    """A record split into its system container and its EventData mapping."""

    shape: Shape
    system: Mapping[str, Any]
    event_data: Mapping[str, Any]


def _flat_system_present(record: Mapping[str, Any]) -> bool:
    return any(
        lookup(record, candidate) is not None
        for name in ("host", "channel", "provider")
        for candidate in SYSTEM_ALIASES[name]
    )


def detect_shape(record: object) -> ShapedRecord | None:
    """Classify a parsed record as shape A, B or C; None when it matches none."""
    if not isinstance(record, Mapping):
        return None

    event = record.get("Event")
    if isinstance(event, Mapping):
        system = event.get("System")
        event_data = event.get("EventData")
        if isinstance(system, Mapping) and "EventData" in event:
            # Outer keys (event_record_id, timestamp) back up the System block.
            return ShapedRecord(
                "A",
                ChainMap(dict(system), {k: v for k, v in record.items() if k != "Event"}),
                event_data if isinstance(event_data, Mapping) else {},
            )

    winlog = record.get("winlog")
    if isinstance(winlog, Mapping) and isinstance(winlog.get("event_data"), Mapping):
        return ShapedRecord("C", record, winlog["event_data"])

    if any(key in record for key in EVENT_ID_KEYS):
        has_event_data = any(
            isinstance(key, str) and key.casefold() in EVENTDATA_KEYS for key in record
        )
        if has_event_data or _flat_system_present(record):
            event_data = {k: v for k, v in record.items() if k not in FLAT_SYSTEM_KEYS}
            return ShapedRecord("B", record, event_data)

    return None
