# Build notes

Working record of data findings, decisions, assumptions and verification for Lineage.
Section references (§) point to the project specification.

## Data recon

Real-dataset recon (P0) results are not available yet. Until they are, the field aliases,
record shapes and envelope follow the specification defaults; every value that depends on
real data is listed under Assumptions.

## Approved spec amendments

Approved by the project owner on 2026-10-29. These are binding and take precedence over the
specification text they amend.

1. **LF line endings (§3.4, §12.3).** The repository carries `.gitattributes` with
   `* text=auto eol=lf` and `*.evtx binary`; ruff formats with `line-ending = "lf"`. Code and
   tests that write reports, golden files or other output write LF explicitly (bytes, or
   `newline="\n"`), and JSON printed to stdout is written as bytes.
2. **`validate` exits 4 when the record cap is reached (§10.5).** Reading stopped before the
   end of the input, so not every record was checked.
3. **`RuleName` → `rule_name` (§6.4, §8.3, §8.4).** Added to the EventData map and therefore to
   the allowed rule field names. No bundled rule may use it, and it never counts as a finding
   or as technique evidence (enforced by a test over the bundled rules in P3). Other keys that
   real data shows to be always present are proposed in a phase plan, never added ad hoc.

## Decisions and deviations

### P1 · Skeleton and ingest

- **Development version.** `__version__` is `0.1.0` during the build and becomes `1.0.0`
  at release (§16.5).
- **JSON or JSONL.** First non-whitespace byte `[` → JSON array. First byte `{` → one JSON
  document only when the first non-blank line is a bare `{` (pretty-printed form); otherwise
  JSONL. A malformed first JSONL line is therefore counted as an invalid record instead of
  making the whole file unusable.
- **JSON documents.** Arrays and single-object documents are parsed whole (bounded by
  `--max-file-size`); per-record checks (duplicate keys, NaN/Infinity, depth) still apply to
  each element. A syntax error in a JSON document makes the file unusable (exit 3), because
  the parser cannot resynchronise to the next element.
- **NaN and Infinity** are counted as `bad_json` (§10.1 has no separate reason code).
- **Depth.** The top-level object is depth 1; depth 33 or more is `too_deep`.
- **Empty input.** An empty or whitespace-only file is read as JSONL with zero records; the
  run reports `no_events` rather than exit 3.
- **Record index.** `SourceRef.index` is the 0-based position among records as read: non-blank
  lines for JSONL, array position for JSON, parser order for EVTX. Invalid records consume an
  index; blank lines do not.
- **Shape B recognition.** An event ID key plus either a §6.4 EventData key or a system alias
  key (channel, provider, host). Without the second branch, non-Sysmon flat records in mixed
  exports would be counted invalid (`unknown_shape`) instead of irrelevant.
- **Shape B EventData** is every top-level key except the heads of the system alias
  candidates (`Computer`, `Hostname`, `host`, `Channel`, `EventID`, `RecordNumber`,
  `TimeCreated`, `@timestamp`, `EventTime`, and the others in §6.3).
- **`ts_source`.** `utc_time` when UtcTime was used; `time_created` for the `TimeCreated`
  candidates; `other` for `@timestamp`, `EventTime` and the shape A parser timestamp.
- **UtcTime precedence.** A parseable UtcTime with an out-of-range year makes the record
  `implausible_timestamp` (no fallback). An unparseable UtcTime falls back to the time-created
  candidates.
- **Missing host** is recorded as `unknown`.
- **GUID fields.** `-` and empty strings are treated as missing, not as `bad_guid`. Inside
  `Event.fields`, valid GUIDs are rewritten in canonical form; zero and malformed GUIDs keep
  their recorded value while the typed `process_guid` is null.
- **PID fields** inside `Event.fields` are rewritten as decimal when they parse.
- **Counters.** `sysmon` and `out_of_order` count Sysmon records as read, before `--host`
  filtering and deduplication; `event_ids_seen` counts the events kept after both.
- **`--host` filter** is applied in ingest; a requested host with no events produces a
  warning (§11.1).
- **Input errors.** A missing path, a directory, more than 64 inputs or an over-size file is
  a usage error (exit 2). A file that exists but cannot be read is exit 3.
- **`validate` exit code.** 4 when any record is invalid, no Sysmon event survived, or the
  record cap stopped reading (amendment 2). Conflicting duplicates are reported as a coverage
  reason but do not change the `validate` exit code (§10.5 table).
- **Readiness states.** `ready`, `partial` (some required IDs present) or `missing`.
  "Credential access" needs 10 or 1, so either one makes it ready; the missing ID is still
  listed.
- **`validate --format json`** prints the envelope, `kind: "validate"`, a `status` of `valid`
  or `invalid`, the exit code, counters, histogram, readiness, unknown keys, invalid record
  locations, reasons and warnings.
- **`render/safe.py`** provides control-character replacement, markup escaping and truncation
  from P1 so `validate` output is already safe; URL defanging follows in P5.
- **Tracebacks.** Typer's pretty exceptions are disabled so an unexpected error never prints
  local variables (which could hold record content); `--verbose` prints a plain traceback to
  stderr.
- **Large fixtures.** The over-cap JSONL line, UTF-32 and big-endian UTF-16 inputs are
  generated inside tests instead of being committed.
- **Decoder placement (for P3).** `analyze/decode.py` stays where §4.1 puts it; `engine.py`
  passes the decode function into the graph builder so graph code never imports `analyze`
  (§4.2.6).

## Assumptions

- `ASSUMPTION` Build backend is `hatchling` (§3.3 asks for the AuthWatch backend; not yet
  confirmed).
- `ASSUMPTION` Envelope `schema_version` is `"1.0"` and the envelope keys are those listed in
  §12.3 (AuthWatch sample report not yet compared).
- `ASSUMPTION` Field aliases and shape rules are the §6.2–6.4 defaults; no real dataset has
  been checked against them.
- `ASSUMPTION` No hero dataset is available, so `validate` has only been run on synthetic
  fixtures.
- `ASSUMPTION` No EVTX fixture recorded on the project VM exists yet; the EVTX reader is
  exercised with a mocked parser.

## Dependency versions

Development environment, Windows 11, Python 3.12.0:

| Package | Version |
| --- | --- |
| typer | 0.27.3 |
| rich | 15.0.0 |
| pydantic | 2.14.2 |
| evtx | 0.14.0 |
| PyYAML | 6.0.3 |
| pytest | 9.2.0 |
| pytest-cov | 7.1.0 |
| ruff | 0.17.3 |
| jsonschema | 4.26.0 |

Exact release versions are recorded at P7.

## Benchmarks

Not run yet (`scripts/bench.py`, §14.4, is a P7 deliverable).

## ATT&CK verification

Not started (P7).

## Known gaps

- EVTX reading is covered only by a mocked parser and an unopenable-file test until an EVTX
  fixture is available.
- JSON documents (not JSONL) are loaded into memory whole.
