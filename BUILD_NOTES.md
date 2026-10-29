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
4. **Activity kinds `file_stream` and `other` (§5.4, §6.5).** Event 15 is `file_stream`; any
   Sysmon ID without a listed kind that has an acting GUID is `other`. Event 15 is never mapped
   to `file_create`. Only event 11 is `file_create`: `file_stream` and `other` never feed GR-004,
   scope `files_created`, story steps or PER-004. Both kinds go into the report JSON Schema in
   P5. Every event counts in `event_ids_seen` whatever its kind.
5. **Events with no acting process (§7.1, §7.6, §8.8, §10.1).**
   - Each host graph keeps `unattached_events`, separate from `wmi_events`. Events 19–21 go only
     to `wmi_events` and are not counted as unattached.
   - No ghost is ever created for a null, zero or malformed GUID.
   - Events 8 and 10 attach to whichever side has a valid GUID, with that side's role; with
     neither, the event is unattached.
   - An event 1 with a null or invalid `process_guid` creates no node and is unattached.
   - Rules still evaluate unattached events (detection indexes events, not nodes); a hit
     attaches to `host:<host>` and increments `unattached_findings` (§8.8). P3 adds a test.
   - Coverage gains the informational counter `unattached_events` (never a reason).
   - Invariant 5 reads: every activity record with a valid acting GUID is attached to exactly
     one actor node (plus one target node for events 8 and 10); every other record is in
     `unattached_events` or `wmi_events`. A test checks that no event is lost.

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

### P2 · Process graph

- **Parent references come only from nodes.** An event 1 that created no node (identical or
  conflicting repeat, or a null GUID) never seeds a parent ghost (§7.1 "of every node").
- **Repeated creations.** An event 1 for an existing GUID with identical fields is counted as
  `duplicate_creations` (informational); different fields count as `creation_conflicts` and
  feed the `duplicate_conflicts` reason. The first in global order is kept, which is the
  earliest by time, then record order.
- **Ghost reason.** A GUID referenced several ways takes the reason and seeded fields of its
  first reference in global order.
- **Cycles are broken once, at build time**, not during later walks: nodes are visited in GUID
  order and the parent edge where a walk revisits its own path is removed and recorded in
  `broken_edges`. This keeps the result independent of input order and lets every later walk
  assume an acyclic graph; `ancestors` keeps a revisit guard anyway.
- **Child order** is (ghost last, start time, GUID); host roots use the same order.
- **Activity summary** is built by `ingest/normalize.py` (`activity_summary`), as §5.4 places it
  at normalize time, and is called when the activity is attached. Targets of events 8 and 10
  get a passive wording ("accessed by …").
- **Activity storage.** Activities are built with `model_construct` from already validated
  events and share the event's `fields` mapping instead of copying it.
- **Display collapse** is a pure function over a children list and a `keep` set (hot nodes plus
  any focus set); `hot_only_children` also returns the hidden count for `--hot-only`.
- **Shuffle invariance** is tested with 20 seeds on `ghosts`, `zero_guid`, `bad_guid`, `cycle`
  and `multi_host`. `duplicates.jsonl` is checked for invariants but not shuffled, because §6.8
  keeps the first conflicting copy by input order (open question to the owner).

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

Full benchmark (`scripts/bench.py`, §14.4) is a P7 deliverable.

**P2 watch item, 2026-10-29: ingest and graph build only.** Synthetic JSONL, 1,000,000 records
(530 MiB): 50,000 event 1, 800,000 event 7, 50,000 event 3, 40,000 event 11, 30,000 event 13,
20,000 event 22, 10,000 event 5; one host. Intel Core Ultra 7 255HX, 15.4 GiB RAM, Windows 11,
Python 3.12.0.

| Stage | Wall time | Working set after | Peak private |
| --- | --- | --- | --- |
| Ingest (read, normalize, dedupe, sort) | 86.4 s | 3,422 MiB | 3,796 MiB |
| Graph build | 18.6 s | 4,203 MiB | 4,623 MiB |

Measured per event (20,000 event 7 records): about 3,300 bytes as a full `Event`, against
about 90 bytes for a slim (time, path, record, index) tuple plus a shared path string. Peak
memory is well above the 2 GB target; a lighter storage form for image loads is awaiting the
owner's decision.

## ATT&CK verification

Not started (P7).

## Known gaps

- EVTX reading is covered only by a mocked parser and an unopenable-file test until an EVTX
  fixture is available.
- JSON documents (not JSONL) are loaded into memory whole.
