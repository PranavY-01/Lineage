"""Timestamp parsing to integer UTC microseconds and RFC 3339 formatting (§6.6)."""

import re
from datetime import UTC, datetime, timedelta

from lineage_ir.config import MAX_PLAUSIBLE_YEAR, MIN_PLAUSIBLE_YEAR

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_ONE_US = timedelta(microseconds=1)

# Sysmon UtcTime: "YYYY-MM-DD HH:MM:SS.fff", no zone, UTC by definition.
_UTC_TIME = re.compile(r"^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?$")

# ISO 8601 / RFC 3339 with an optional zone; the zone is checked separately.
_ISO = re.compile(
    r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?"
    r"(Z|z|[+-]\d{2}:\d{2})?$"
)


class NaiveTimestamp(ValueError):
    """An ISO time string without a zone where UTC must not be assumed."""


def _fraction(digits: str | None) -> str:
    return "" if not digits else "." + digits[:6]


def to_us(dt: datetime) -> int:
    """Convert an aware datetime to integer microseconds since the Unix epoch."""
    return (dt - _EPOCH) // _ONE_US


def _check_range(dt: datetime) -> datetime:
    if not MIN_PLAUSIBLE_YEAR <= dt.year <= MAX_PLAUSIBLE_YEAR:
        raise OverflowError("implausible year")
    return dt


def parse_utc_time(value: str) -> int:
    """Parse a Sysmon ``UtcTime`` string; raise ValueError when malformed.

    Raises OverflowError when the year is outside the plausible range.
    """
    m = _UTC_TIME.match(value.strip())
    if not m:
        raise ValueError("not a UtcTime value")
    dt = datetime.fromisoformat(f"{m[1]}T{m[2]}{_fraction(m[3])}+00:00")
    return to_us(_check_range(dt))


def parse_iso(value: str) -> int:
    """Parse an ISO time with ``Z`` or ``±HH:MM``; fractions beyond 6 digits are truncated.

    Raises NaiveTimestamp when the zone is missing, ValueError when malformed and
    OverflowError when the year is outside the plausible range.
    """
    m = _ISO.match(value.strip())
    if not m:
        raise ValueError("not an ISO time")
    zone = m[4]
    if zone is None:
        raise NaiveTimestamp("time has no zone")
    if zone in ("Z", "z"):
        zone = "+00:00"
    dt = datetime.fromisoformat(f"{m[1]}T{m[2]}{_fraction(m[3])}{zone}")
    return to_us(_check_range(dt))


def format_rfc3339(ts_us: int) -> str:
    """Format microseconds as RFC 3339 UTC with ``Z``; fractions only when non-zero."""
    dt = _EPOCH + timedelta(microseconds=ts_us)
    if dt.microsecond:
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + "Z"
