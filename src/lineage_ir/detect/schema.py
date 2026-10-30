"""Pydantic schema for rule files (§8.1, §8.2, §8.4 and approved amendment 12)."""

from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    StrictBool,
    StringConstraints,
    field_validator,
    model_validator,
)

from lineage_ir.ingest.field_aliases import NORMALIZED_KEYS, REFERENCE_KEYS
from lineage_ir.ingest.normalize import PATH_FIELDS
from lineage_ir.models import IMAGE_LOAD_EVENT_ID, FrozenModel, RuleInfo, Severity

# The 15 ATT&CK Enterprise tactics (v20: Defense Evasion became Stealth and Defense
# Impairment, amendment 23).
TACTICS = frozenset(
    {
        "reconnaissance",
        "resource-development",
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "stealth",
        "defense-impairment",
        "credential-access",
        "discovery",
        "lateral-movement",
        "collection",
        "command-and-control",
        "exfiltration",
        "impact",
    }
)

VIRTUAL_FIELDS = frozenset(
    {
        "event_id",
        "image_name",
        "parent_image_name",
        "source_image_name",
        "target_image_name",
        "decoded_command",
        "command_line_full",
        "encoded_command_present",
        "target_filename_name",
    }
)
# Rule fields: the §6.4 keys except reference-only ones (amendment 25), plus virtual fields.
ALLOWED_FIELDS = (NORMALIZED_KEYS - REFERENCE_KEYS) | VIRTUAL_FIELDS
MATCH_PATH_FIELDS = frozenset(PATH_FIELDS)
# Fields whose integer form is compared when a rule value is an integer (§8.2 item 7).
NUMERIC_FIELDS = frozenset(
    {"destination_port", "source_port", "pid", "parent_pid", "source_pid", "target_pid"}
)

Modifier = Literal["equals", "contains", "startswith", "endswith"]
_MODIFIERS = ("contains", "startswith", "endswith")
MAX_LIST_ITEMS = 64
MAX_VALUE_CHARS = 256


def fold(field: str, value: str) -> str:
    """Matching form of a value: path fields normalized (§8.2 item 4), then casefolded."""
    if field in MATCH_PATH_FIELDS:
        value = value.replace("/", "\\")
        for prefix in ("\\\\?\\", "\\??\\"):
            if value.startswith(prefix):
                value = value[len(prefix) :]
                break
    return value.casefold()


class Condition(FrozenModel):
    """One key of a group: a field, a modifier and the values it may (or must all) match."""

    field: str
    modifier: Modifier
    require_all: bool
    values: tuple[str | int, ...]
    folded: tuple[str | int, ...]


class Group(FrozenModel):
    """Conditions that must all hold; an empty ``event_ids`` (exclude only) means any event."""

    event_ids: tuple[int, ...]
    conditions: tuple[Condition, ...]


def _event_ids(value: Any) -> tuple[int, ...]:
    items = value if isinstance(value, list) else [value]
    if not items or any(type(i) is not int or i < 1 for i in items):
        raise ValueError("event_id must be a positive integer or a non-empty list of them")
    if IMAGE_LOAD_EVENT_ID in items:
        raise ValueError(
            "image-load events (event 7) are stored in summary form in v1.0 and cannot be "
            "used in rules"
        )
    return tuple(sorted(set(items)))


def _condition(key: str, value: Any) -> Condition:
    parts = key.split("|")
    if not parts[0] or len(parts) > 3 or (len(parts) == 3 and parts[2] != "all"):
        raise ValueError(f"bad key syntax {key!r}: use field, field|modifier or field|modifier|all")
    field = parts[0]
    modifier = parts[1] if len(parts) > 1 else "equals"
    if len(parts) > 1 and modifier not in _MODIFIERS:
        raise ValueError(f"unknown modifier {modifier!r} in {key!r}")
    if field not in ALLOWED_FIELDS:
        raise ValueError(f"unknown field {field!r}")
    items = value if isinstance(value, list) else [value]
    if not items:
        raise ValueError(f"{key}: empty list")
    if len(items) > MAX_LIST_ITEMS:
        raise ValueError(f"{key}: at most {MAX_LIST_ITEMS} values")
    for item in items:
        if type(item) not in (str, int):
            raise ValueError(f"{key}: each value must be a string or integer")
        if isinstance(item, str) and len(item) > MAX_VALUE_CHARS:
            raise ValueError(f"{key}: a value is longer than {MAX_VALUE_CHARS} characters")
        if isinstance(item, int) and modifier != "equals":
            raise ValueError(f"{key}: integer values need an exact match (no modifier)")
    folded = tuple(fold(field, i) if isinstance(i, str) else i for i in items)
    return Condition(
        field=field,
        modifier=modifier,  # type: ignore[arg-type]
        require_all=len(parts) == 3,
        values=tuple(items),
        folded=folded,
    )


def parse_group(raw: Any, *, exclude: bool = False) -> Group:
    """Build a Group from its YAML mapping; ``event_id`` is optional only in exclude groups."""
    if isinstance(raw, Group):
        return raw
    if not isinstance(raw, dict):
        raise ValueError("a group must be a mapping of field keys to values")
    event_ids: tuple[int, ...] = ()
    conditions = []
    for key, value in raw.items():
        if not isinstance(key, str):
            raise ValueError(f"bad key syntax {key!r}")
        if key.split("|", 1)[0] == "event_id":
            if key != "event_id":
                raise ValueError("event_id takes no modifier")
            event_ids = _event_ids(value)
        else:
            conditions.append(_condition(key, value))
    if not event_ids and not exclude:
        raise ValueError("event_id is required in every match group")
    return Group(event_ids=event_ids, conditions=tuple(conditions))


RuleId = Annotated[str, StringConstraints(pattern=r"^[A-Z]{2,4}-\d{3}$")]
Technique = Annotated[str, StringConstraints(pattern=r"^T\d{4}(\.\d{3})?$")]


class Rule(BaseModel):
    """One YAML rule file, validated (§8.4)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: RuleId
    title: Annotated[str, StringConstraints(min_length=1, max_length=80)]
    severity: Severity
    attack: tuple[Technique, ...] = ()
    tactics: tuple[str, ...]
    why: Annotated[str, StringConstraints(min_length=1, max_length=400)]
    match: Group | None = None
    match_any: tuple[Group, ...] | None = None
    exclude: tuple[Group, ...] = ()
    references: tuple[str, ...] = ()
    enabled: StrictBool = True

    @field_validator("tactics")
    @classmethod
    def _known_tactics(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        unknown = [t for t in value if t not in TACTICS]
        if unknown:
            raise ValueError(f"unknown tactic {unknown[0]!r}")
        return value

    @field_validator("match", mode="before")
    @classmethod
    def _match(cls, value: Any) -> Group | None:
        return None if value is None else parse_group(value)

    @field_validator("match_any", mode="before")
    @classmethod
    def _match_any(cls, value: Any) -> tuple[Group, ...] | None:
        if value is None:
            return None
        if not isinstance(value, list | tuple) or not value:
            raise ValueError("match_any must be a non-empty list of groups")
        return tuple(parse_group(g) for g in value)

    @field_validator("exclude", mode="before")
    @classmethod
    def _exclude(cls, value: Any) -> tuple[Group, ...]:
        if not isinstance(value, list | tuple):
            raise ValueError("exclude must be a list of groups")
        return tuple(parse_group(g, exclude=True) for g in value)

    @model_validator(mode="after")
    def _one_match_form(self) -> "Rule":
        if (self.match is None) == (self.match_any is None):
            raise ValueError("exactly one of match or match_any is required")
        return self

    @property
    def groups(self) -> tuple[Group, ...]:
        """The positive groups, whichever form the rule uses."""
        return (self.match,) if self.match is not None else self.match_any or ()

    @property
    def info(self) -> RuleInfo:
        event_ids = sorted({i for g in self.groups for i in g.event_ids})
        return RuleInfo(
            id=self.id,
            kind="event",
            title=self.title,
            severity=self.severity,
            event_ids=tuple(event_ids),
            attack=self.attack,
            tactics=self.tactics,
            why=self.why,
        )
