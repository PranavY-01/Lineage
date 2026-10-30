"""Normalized and virtual field resolution for rules (§8.3) and condition matching (§8.2)."""

from collections.abc import Mapping

from lineage_ir.detect.schema import NUMERIC_FIELDS, Condition, Group, Rule, fold
from lineage_ir.ingest.normalize import image_name
from lineage_ir.models import Event, ProcessNode

_BASENAME_FIELDS = {
    "image_name": "image",
    "parent_image_name": "parent_image",
    "source_image_name": "source_image",
    "target_image_name": "target_image",
    "target_filename_name": "target_filename",
}


def destination(fields: Mapping[str, str]) -> str | None:
    """``ip:port/proto`` of a network event, or None without a destination IP."""
    ip = fields.get("destination_ip")
    if not ip:
        return None
    port = fields.get("destination_port") or "?"
    protocol = fields.get("protocol") or "?"
    return f"{ip}:{port}/{protocol}"


class EventFields:
    """The values rules can read from one event, resolved and folded on first use."""

    __slots__ = ("_folded", "event", "node")

    def __init__(self, event: Event, node: ProcessNode | None) -> None:
        self.event = event
        self.node = node
        self._folded: dict[str, str | None] = {}

    def _decoded(self) -> tuple[str | None, str | None]:
        if self.event.event_id != 1 or self.node is None:
            return None, None
        return self.node.decoded_command, self.node.decode_note

    def raw(self, name: str) -> str | None:
        """The field's value as recorded (virtual fields computed), or None when absent."""
        fields = self.event.fields
        if name in _BASENAME_FIELDS:
            return image_name(fields.get(_BASENAME_FIELDS[name]))
        if name == "event_id":
            return str(self.event.event_id)
        if name == "decoded_command":
            return self._decoded()[0]
        if name == "command_line_full":
            command_line = fields.get("command_line")
            decoded = self._decoded()[0]
            if decoded is None:
                return command_line
            return f"{command_line or ''}\n{decoded}"
        if name == "encoded_command_present":
            if self.event.event_id != 1:
                return None
            decoded, note = self._decoded()
            return "true" if decoded is not None or note is not None else "false"
        return fields.get(name)

    def folded(self, name: str) -> str | None:
        if name not in self._folded:
            value = self.raw(name)
            self._folded[name] = fold(name, value) if value else None
        return self._folded[name]


def _value_matches(condition: Condition, view: EventFields, value: str | int) -> bool:
    if isinstance(value, int):
        if condition.field in NUMERIC_FIELDS:
            raw = view.raw(condition.field)
            try:
                return raw is not None and int(raw.strip()) == value
            except ValueError:
                return False
        value = str(value)
    current = view.folded(condition.field)
    if current is None:
        return False
    if condition.modifier == "contains":
        return value in current
    if condition.modifier == "startswith":
        return current.startswith(value)
    if condition.modifier == "endswith":
        return current.endswith(value)
    return current == value


def condition_matches(condition: Condition, view: EventFields) -> bool:
    """A missing or empty field makes the condition false; it never raises."""
    check = all if condition.require_all else any
    return check(_value_matches(condition, view, v) for v in condition.folded)


def group_matches(group: Group, view: EventFields) -> bool:
    if group.event_ids and view.event.event_id not in group.event_ids:
        return False
    return all(condition_matches(c, view) for c in group.conditions)


def rule_matches(rule: Rule, view: EventFields) -> bool:
    """A positive group matches and no exclude group does (excludes run only after a match)."""
    if not any(group_matches(g, view) for g in rule.groups):
        return False
    return not any(group_matches(g, view) for g in rule.exclude)
