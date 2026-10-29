from datetime import UTC, datetime

import pytest

from lineage_ir.ingest.timeparse import (
    NaiveTimestamp,
    format_rfc3339,
    parse_iso,
    parse_utc_time,
    to_us,
)


def _us(*args: int) -> int:
    return to_us(datetime(*args, tzinfo=UTC))


def test_utc_time_with_milliseconds() -> None:
    assert parse_utc_time("2026-10-12 10:41:58.123") == _us(2026, 10, 12, 10, 41, 58, 123000)


def test_utc_time_without_fraction() -> None:
    assert parse_utc_time("2026-10-12 10:41:58") == _us(2026, 10, 12, 10, 41, 58)


@pytest.mark.parametrize("value", ["2026-10-12T10:41:58Z", "12/10/2026 10:41", "", "garbage"])
def test_utc_time_rejects_other_formats(value: str) -> None:
    with pytest.raises(ValueError):
        parse_utc_time(value)


def test_iso_seven_digit_fraction_is_truncated() -> None:
    assert parse_iso("2026-10-12T10:41:58.1239876Z") == _us(2026, 10, 12, 10, 41, 58, 123987)


def test_iso_lowercase_z() -> None:
    assert parse_iso("2026-10-12T10:41:58z") == _us(2026, 10, 12, 10, 41, 58)


def test_iso_positive_offset() -> None:
    assert parse_iso("2026-10-12T16:11:58+05:30") == _us(2026, 10, 12, 10, 41, 58)


def test_iso_negative_offset() -> None:
    assert parse_iso("2026-10-12T05:41:58.5-05:00") == _us(2026, 10, 12, 10, 41, 58, 500000)


def test_iso_space_separator() -> None:
    assert parse_iso("2026-10-12 10:41:58Z") == _us(2026, 10, 12, 10, 41, 58)


@pytest.mark.parametrize("value", ["2026-10-12T10:41:58", "2026-10-12 10:41:58.123"])
def test_iso_naive_is_rejected(value: str) -> None:
    with pytest.raises(NaiveTimestamp):
        parse_iso(value)


@pytest.mark.parametrize("value", ["2026-13-12T10:41:58Z", "not a time", "2026-10-12T10:41Z"])
def test_iso_malformed(value: str) -> None:
    with pytest.raises(ValueError):
        parse_iso(value)


@pytest.mark.parametrize(
    "value", ["1601-01-01 00:00:00.000", "1989-12-31 23:59:59.999", "2101-01-01 00:00:00"]
)
def test_utc_time_implausible_years(value: str) -> None:
    with pytest.raises(OverflowError):
        parse_utc_time(value)


def test_iso_implausible_year() -> None:
    with pytest.raises(OverflowError):
        parse_iso("2150-01-01T00:00:00Z")


def test_plausible_boundaries() -> None:
    assert parse_utc_time("1990-01-01 00:00:00") == _us(1990, 1, 1)
    assert parse_iso("2100-12-31T23:59:59Z") == _us(2100, 12, 31, 23, 59, 59)


def test_format_rfc3339() -> None:
    assert format_rfc3339(_us(2026, 10, 12, 10, 41, 58)) == "2026-10-12T10:41:58Z"
    assert format_rfc3339(_us(2026, 10, 12, 10, 41, 58, 123000)) == "2026-10-12T10:41:58.123000Z"
