"""Analysis parameters (§11.1, §11.3), rule selection and the display filters (§9.7).

The CLI builds AnalysisParams through ``make_params`` and never repeats its validation.
Display filters (time window and focus) only choose what is shown; they never change
findings, storylines, coverage or status (§10.4).
"""

import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from pydantic import ValidationError, model_validator

from lineage_ir.config import (
    DEFAULT_MAX_FILE_SIZE_MB,
    DEFAULT_MAX_RECORDS,
    MAX_FILE_SIZE_MB_RANGE,
    MAX_RECORDS_RANGE,
)
from lineage_ir.detect.graph_rules import GraphRule
from lineage_ir.detect.schema import Rule
from lineage_ir.errors import UsageError
from lineage_ir.ingest.timeparse import NaiveTimestamp, parse_iso
from lineage_ir.models import Finding, FrozenModel, Severity, Step, Storyline

SEVERITY_RANK: Mapping[str, int] = {"high": 3, "medium": 2, "low": 1, "info": 0}

_DURATION = re.compile(r"^(\d+)([smhd])$", re.IGNORECASE)
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
MINUTE, DAY = 60, 86400
GAP_RANGE = (MINUTE, 7 * DAY)
TELEMETRY_GAP_RANGE = (MINUTE, 30 * DAY)
MAX_STEPS_RANGE = (10, 10_000)
DEFAULT_WINDOW = "15m"


def parse_duration(text: str) -> int:
    """Seconds in a duration written as an integer plus ``s``, ``m``, ``h`` or ``d``."""
    match = _DURATION.fullmatch(text.strip()) if isinstance(text, str) else None
    if match is None:
        raise UsageError(f"{text!r} is not a duration (use a whole number with s, m, h or d)")
    return int(match[1]) * _UNIT_SECONDS[match[2].lower()]


def _time(option: str, text: str) -> int:
    try:
        return parse_iso(text)
    except NaiveTimestamp:
        raise UsageError(
            f"{option} {text!r}: the time needs an explicit offset (Z or ±HH:MM)"
        ) from None
    except (ValueError, OverflowError):
        raise UsageError(f"{option} {text!r} is not an RFC 3339 time with an offset") from None


def _in_range(option: str, value: int, bounds: tuple[int, int]) -> None:
    if not bounds[0] <= value <= bounds[1]:
        raise UsageError(f"{option} must be between {bounds[0]:,} and {bounds[1]:,}")


class AnalysisParams(FrozenModel):
    """Resolved analysis options with the §11.1 defaults; build it with ``make_params``."""

    hosts: tuple[str, ...] = ()
    rules: str | None = None
    min_severity: Severity = "info"
    since: str | None = None
    until: str | None = None
    around: str | None = None
    window: str | None = None
    focus: str | None = None
    hot_only: bool = False
    gap: str = "10m"
    telemetry_gap: str = "30m"
    max_steps: int = 60
    max_records: int = DEFAULT_MAX_RECORDS
    max_file_size_mb: int = DEFAULT_MAX_FILE_SIZE_MB

    @model_validator(mode="after")
    def _validate(self) -> "AnalysisParams":
        # Raises UsageError directly so callers get exit 2 with a plain message.
        _in_range("--gap", self.gap_seconds, GAP_RANGE)
        _in_range("--telemetry-gap", self.telemetry_gap_seconds, TELEMETRY_GAP_RANGE)
        _in_range("--max-steps", self.max_steps, MAX_STEPS_RANGE)
        _in_range("--max-records", self.max_records, MAX_RECORDS_RANGE)
        _in_range("--max-file-size", self.max_file_size_mb, MAX_FILE_SIZE_MB_RANGE)
        if self.window is not None and self.around is None:
            raise UsageError("--window can only be used with --around")
        if self.around is not None and (self.since is not None or self.until is not None):
            raise UsageError("--around cannot be combined with --since or --until")
        since, until = self.window_us
        if since is not None and until is not None and since >= until:
            raise UsageError("--since must be before --until")
        return self

    @property
    def gap_seconds(self) -> int:
        return parse_duration(self.gap)

    @property
    def telemetry_gap_seconds(self) -> int:
        return parse_duration(self.telemetry_gap)

    @property
    def window_us(self) -> tuple[int | None, int | None]:
        """The display window as (since, until) in microseconds; either side may be open."""
        if self.around is not None:
            center = _time("--around", self.around)
            half = parse_duration(self.window or DEFAULT_WINDOW) * 1_000_000
            return center - half, center + half
        since = _time("--since", self.since) if self.since is not None else None
        until = _time("--until", self.until) if self.until is not None else None
        return since, until


def make_params(**options: Any) -> AnalysisParams:
    """Validate options into AnalysisParams; any problem is a UsageError (exit 2)."""
    if "hosts" in options and options["hosts"] is not None:
        options["hosts"] = tuple(h.strip().lower() for h in options["hosts"])
    try:
        return AnalysisParams(**options)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()
        )
        raise UsageError(f"invalid option ({problems})") from None


def select_rules(
    rules: Sequence[Rule], graph_rules: Sequence[GraphRule], spec: str | None
) -> tuple[tuple[Rule, ...], tuple[GraphRule, ...]]:
    """Rules enabled by ``--rules``: IDs or family prefixes (``CMD``, ``PER-001``, ``GR``)."""
    if spec is None:
        return tuple(rules), tuple(graph_rules)
    ids = sorted([r.id for r in rules] + [g.info.id for g in graph_rules])
    tokens = [t.strip().upper() for t in spec.split(",") if t.strip()]
    chosen: set[str] = set()
    unknown = [] if tokens else [spec]
    for token in tokens:
        matched = {i for i in ids if i == token or i.split("-", 1)[0] == token}
        if not matched:
            unknown.append(token)
        chosen |= matched
    if unknown:
        raise UsageError(f"unknown rule {unknown[0]!r}; valid IDs: {', '.join(ids)}")
    return (
        tuple(r for r in rules if r.id in chosen),
        tuple(g for g in graph_rules if g.info.id in chosen),
    )


def keep_by_severity(findings: Iterable[Finding], minimum: Severity) -> tuple[Finding, ...]:
    """Findings at or above ``--min-severity`` (applied before storylines, §8.8 item 6)."""
    floor = SEVERITY_RANK[minimum]
    return tuple(f for f in findings if SEVERITY_RANK[f.severity] >= floor)


def _overlaps(start: int, end: int, window: tuple[int | None, int | None]) -> bool:
    since, until = window
    return (since is None or end >= since) and (until is None or start <= until)


def visible_findings(
    findings: Iterable[Finding],
    params: AnalysisParams,
    focus: Mapping[str, frozenset[str]] | None = None,
) -> tuple[Finding, ...]:
    """Findings shown under the time window and focus set (display only)."""
    window = params.window_us
    return tuple(
        f
        for f in findings
        if _overlaps(f.first_us, f.last_us, window)
        and (focus is None or f.guid in focus.get(f.host, frozenset()))
    )


def visible_storylines(
    storylines: Iterable[Storyline],
    params: AnalysisParams,
    focus: Mapping[str, frozenset[str]] | None = None,
) -> tuple[Storyline, ...]:
    """Storylines shown under the time window and focus set (display only)."""
    window = params.window_us
    return tuple(
        s
        for s in storylines
        if _overlaps(s.start_us, s.end_us, window)
        and (focus is None or not focus.get(s.host, frozenset()).isdisjoint(s.nodes))
    )


def visible_steps(storyline: Storyline, params: AnalysisParams) -> tuple[Step, ...]:
    """Steps inside the time window (display only)."""
    window = params.window_us
    return tuple(s for s in storyline.steps if _overlaps(s.ts_us, s.ts_us, window))
