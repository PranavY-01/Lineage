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
6. **Slim image-load storage (§5.3, §5.4, §6.5, §7.1).** Event 7 is held at ingest as a slim
   `ImageLoadRecord` and on nodes as a frozen `ImageLoad` (`ts_us`, `image_loaded`, `signed`,
   `SourceRef`). `image_load` is removed from `Activity.kind`. `ProcessNode` gains
   `image_load_count` (exact) and `image_loads` (the first 50 by `ts_us`, then `record_id`,
   then content hash, so a shuffle cannot change which 50). Everything else behaves as before:
   an event 7 with an unknown GUID creates an `activity_reference` ghost; an event 7 with no
   valid GUID increments `unattached_events`, and each host keeps only the first 50 of them;
   event 7 counts in `event_ids_seen` and in events examined for coverage. Event 7 without a
   record ID is deduplicated on its slim content. `inspect` shows up to 50 per kind with the
   total (§11.2). A test checks that the graph equals a full-Event build on every graph fixture
   and on a generated mix containing event 7.
7. **Deterministic duplicate and tie resolution (§6.8, §7.1, §14.3).** A conflicting duplicate
   keeps the earliest `ts_us`, then the smallest content hash, and is still counted in
   `duplicate_conflicts`; both records are reported in the errors list by file and index only,
   never content. The §6.8 global sort is (host, `ts_us`, `record_id` or 0, content hash,
   input file order, index), with the hash computed only when the earlier keys tie. Conflicting
   event 1 creations (§7.1) use the same earliest-then-smallest-hash rule. `duplicates.jsonl` is
   in the shuffle test again, and `ties.jsonl` covers timestamp ties without record IDs.
8. **Ingest speedups (§6.1, §6.8).** (a) Records with a record ID are hashed only on a key
   collision or a sort tie; records without one are always hashed because the hash is their
   dedupe key. (b) JSONL and EVTX records are checked in a single parse: parser hooks reject
   duplicate keys and NaN/Infinity, `RecursionError` is caught, and the depth walk runs only
   when the text holds more opening brackets than the nesting limit. Each §6.1 record rule has
   a test that fails when the rule is removed (checked by removing each rule in turn).

Amendments 9–11 were approved on 2026-10-30.

9. **Compact Event storage (§5.2, §6.5).**
   - Events and their `SourceRef` are built without re-validation, from values normalize has
     just validated, through `models.trusted_event`. Only `ingest/normalize.py` calls it;
     `construct_trusted` stays limited to `models.py` and `graph/builder.py`, and
     `model_construct` to `models.py`. A source test enforces all three.
   - A test checks that every Event built this way equals the same Event built through full
     pydantic validation (JSON text of `model_dump`), on every JSONL fixture and a generated
     mix, both record by record and through the whole ingest.
   - Shared field maps and strings are immutable by convention. A test takes deep copies of
     all events before the downstream pipeline runs and checks that they still equal the
     originals afterwards. Later phases add their stages to that test.
   - Strings are reused through per-run dict pools, never `sys.intern`, and only for host,
     channel, field names, image paths, users and hashes. Each pool keeps at most 100,000
     distinct values; past the cap a string is stored as it is.
   - Report output is unchanged; golden, determinism and shuffle tests pass without edits.
10. **Memory target and default record cap (§11, §14.4).**
    - The §14.4 memory target for the realistic mix is 2.5 GB at 1,000,000 records. The binding
      memory guarantee is the default-cap rule: the default `--max-records` is the largest of
      1, 2, 3 or 5 million records whose projected realistic-mix peak is 6.0 GB or less.
    - With the measurements below, the default is 2,000,000 (measured peak 4.94 GB). The allowed
      range stays 1 to 50,000,000.
    - When the cap stops reading, the text view states the cap and says it can be raised with
      `--max-records`.
11. **No spill-to-disk in v1.0, and no further performance rounds.** A disk-backed store is
    rejected for v1.0 (§13.2: no files except requested outputs; temporary-file attack surface;
    out of proportion to the target log sizes) and is listed under Roadmap. Phases P3 to P5 do
    not take on memory or speed work unless a test fails or the 6 GB rule is violated; anything
    else goes under Known gaps.

Amendment 12 was approved on 2026-10-30 with the P3 plan.

12. **No rules on event 7 in v1.0 (§8.4).** The loader rejects any group, match or exclude,
    whose `event_id` includes 7, even when other IDs are listed beside it, with a message naming
    the rule and saying that image-load events are stored in summary form in v1.0. Detection
    reads events from the sorted event list (never from graph activities), so records with no
    acting process are still evaluated and attach to `host:<host>`.

Amendments 13 and 14 were approved on 2026-10-30 at the P3 gate.

13. **§8.6 path values corrected.** The catalogue lost backslashes to a markdown escaping error.
    A path-style value is a directory fragment with a boundary on both sides. The bundled rules
    use:
    - LOC-001 `image|contains`: `\users\public\`, `\appdata\local\temp\`, `\windows\temp\`,
      `\downloads\`, `\$recycle.bin\`, `\perflogs\`.
    - LOC-002 exclude `image|startswith`: `c:\windows\system32\`, `c:\windows\syswow64\`,
      `c:\windows\winsxs\`.
    - PER-001 `target_object|contains`: `\currentversion\run\`, `\currentversion\runonce\`,
      `\currentversion\policies\explorer\run\`.

    The other path and registry values (PER-003, PER-004, CRD-001) were already bounded.
    `tests/integration/test_rule_paths.py` covers every value above with a hit and a near
    miss; removing any one backslash makes a test fail.
14. **Detection details made binding (§8.2, §8.4, §8.5).**
    - Exclude groups may omit `event_id`.
    - YAML booleans and nulls are rejected as rule values, so bundled rules quote `'true'` and
      `'no'`.
    - Integer values match exactly (no modifier).
    - The decoder's 64 KiB output cap is measured in UTF-8 bytes.
    - Whitespace is stripped from the payload before the 128 KiB input cap.
    - Rule files may not repeat a key in any mapping (loader check).

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
  feed the `duplicate_conflicts` reason. The earliest by time, then the smallest content
  hash, is kept (amendment 7).
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
- **High-volume records.** Activities and retained image loads are built with
  `construct_trusted` from values normalization already typed: no re-validation, the event's
  `fields` mapping is shared rather than copied, and every instance of a class shares one
  pydantic fields-set (frozen models; pydantic copies the set before any update). A retained
  image load costs about 590 bytes instead of 1,020. Events follow the same pattern through
  `models.trusted_event` (amendment 9).
- **String pools.** `read_inputs` creates one `StringPools` per run and passes it to every
  `normalize_record` call. A field's value is pooled only when the field is one of `image`,
  `parent_image`, `source_image`, `target_image`, `image_loaded`, `user`, `parent_user`,
  `source_user`, `target_user` or `hashes`; every field name is pooled. The typed
  `process_guid` and `image` reuse the strings already in `fields` instead of copies. GUIDs and
  the event 7 `signed` value are no longer interned, since amendment 9 limits reuse to the
  listed fields.
- **Content hash of event 7** is taken over its slim form whether it arrives as a full Event or
  as an `ImageLoadRecord`, so both paths deduplicate and order identically.
- **Conflict errors** use kind `duplicate_conflict`, the dropped record as subject
  (`file:index`) and the kept record's location in the message.
- **Display collapse** is a pure function over a children list and a `keep` set (hot nodes plus
  any focus set); `hot_only_children` also returns the hidden count for `--hot-only`.
- **Shuffle invariance** is tested with 20 seeds on `ghosts`, `zero_guid`, `bad_guid`, `cycle`,
  `multi_host`, `duplicates` and `ties` (amendment 7).

### P3 · Detection

- **Anchor test injection.** `detect.graph_rules.AnchorTest` is `Callable[[ProcessNode], bool]`.
  `run_detection` takes it as a required keyword with no default. P3 tests use
  `tests/helpers/anchors.py`: explorer.exe, services.exe and svchost.exe, matched by name AND
  directory per §9.1 (a ghost whose image is a bare name matches by name). P4 supplies the real
  anchors from `anchors.yaml` and counts `anchor_unverified`.
- **Decoder placement.** `engine.build_host_graphs` passes `analyze.decode.decode_command` into
  `build_graphs`, so nodes carry `decoded_command` and `decode_note` and graph code never
  imports `analyze`.
- **Flag and payload detection** tokenizes the command line once (whitespace-separated, a token
  opening with a quote runs to the matching quote), then looks for a flag token followed by a
  payload token. This stays linear on hostile input; a regex over quoted spans would not.
- **Decoder caps.** Whitespace is removed before the 128 KiB input cap, so the cut always lands
  on whole base64 characters. The 64 KiB output cap is measured in UTF-8 bytes: in characters
  it could never trigger, since 128 KiB of base64 decodes to at most 48K UTF-16 characters.
- **Decode notes** are comma-joined in the order `truncated_input`, `invalid_base64`, `not_text`,
  `truncated_output`, `nested_encoding`. Failures return only these codes; the payload and
  decoded text never appear in a note or an exception.
- **`decoded_command`, `command_line_full` and `encoded_command_present`** come from the node of
  the event 1's `process_guid` (§8.3 "node's decoded payload"). `encoded_command_present` is
  `true` when the decoder found a flag and payload, even if decoding failed, and is absent (so
  never matches) on other event IDs.
- **Exclude groups** may omit `event_id` (then they apply to any event the rule matched); when
  present it restricts the exclude.
- **Rule values.** YAML booleans and nulls are rejected (quote `'true'` and `'no'`). Integer
  values allow only an exact match. Integer comparison applies to `destination_port`,
  `source_port` and the four PID fields; other fields compare an integer value as text.
- **Rule files** are read from every subdirectory of the rules directory, sorted by path; IDs
  must be unique across all of them. Rules are evaluated in ascending ID order.
- **`details`** follow §8.8 item 4 and are taken from the first matching event. Graph
  heuristics add: GR-001 `office_ancestor` and `destination`; GR-002 `binaries`; GR-003
  `target_filename`, `creator_guid` and `creator_image`; GR-004 `activity`.
- **GR-001** walks ancestors from the parent; an anchor ends the walk before it is checked.
- **GR-002** counts every discovery child inside a qualifying window; evidence is their
  creation records.
- **GR-003** "later" means after the file creation in global order (time, record ID, hash); the
  most recent write of a path is the one reported. Only the event 1 that created the node
  counts, and only event 11 (never 15) can supply the file.
- **`events_examined`** counts, per event rule, the events of its IDs that were visited; for a
  graph heuristic, the events with any of its required IDs.
- **`lineage rules --format json`** prints the envelope, `kind: "rules"` and one entry per rule
  (id, kind, title, severity, event_ids, attack, tactics), sorted by ID.
- **GR-003 creator.** The reported creator is the most recent write of the path at or before
  the execution in global order; a write after the execution is never used, and an execution
  with only later writes produces no finding (tested).
- **Duplicate keys in rule files** are rejected by `UniqueKeyLoader`, a `yaml.SafeLoader`
  subclass that checks each mapping's keys before building it. It is run the way
  `yaml.safe_load` runs its loader (`get_single_data`, then `dispose`); a test checks it is a
  `SafeLoader` and still refuses Python tags.

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
about 90 bytes for a slim (time, path, record, index) tuple plus a shared path string.

**P2 re-measure, 2026-10-30, after amendments 6–8.** Same machine and the same 80% event 7
file. Each mode was run twice, interleaved. Peak private memory was 1,580 MiB (1.66 GB) in
every run; it was 4,623 MiB (4.85 GB) before slim image loads.

| Mode | Ingest (runs 1, 2) | Graph (runs 1, 2) | Total mean |
| --- | --- | --- | --- |
| Neither speedup | 106.3 s, 102.2 s | 20.2 s, 17.6 s | 123.2 s |
| Lazy content hash (3a) | 92.0 s, 63.7 s | 14.6 s, 18.0 s | 94.2 s |
| 3a plus single-parse JSON checks (3b) | 56.7 s, 78.4 s | 17.8 s, 17.9 s | 85.4 s |

Run-to-run variation on this laptop is up to about 30% for ingest, so the gains for each step are
approximate; together they bring the mean down from 123 s to 85 s.

**Realistic mix, 1,000,000 records:** 140,000 event 1, 300,000 event 7, and 140,000 each of
events 3, 11, 13 and 22; 140,000 processes; one host. Two runs: ingest 78.9 s and 79.3 s, graph
22.5 s and 22.3 s, total about 101.5 s. Peak private memory was 3,259 MiB (3.42 GB) in both
runs. A full `Event` costs 2,795 bytes, measured over 20,000 records that are not event 7,
including the normalize outcome wrapper.

Projected at the then-default `--max-records` of 5,000,000: about 16,300 MiB (17.1 GB), above
the 8 GB ceiling. This led to amendments 9 and 10.

**P2 final measurement, 2026-10-30, after amendments 9 and 10.** Same machine. Memory is peak
private bytes; GB is decimal.

Realistic mix (the generator scales every count, so 2M has 280,000 processes):

| Records | Ingest (runs 1, 2) | Graph (runs 1, 2) | Total (runs 1, 2) | Peak |
| --- | --- | --- | --- | --- |
| 1,000,000 | 67.0 s, 77.8 s | 29.1 s, 31.1 s | 96.1 s, 108.9 s | 2,366 MiB (2.48 GB) |
| 2,000,000 | 204.1 s, 141.9 s | 78.7 s, 84.1 s | 282.9 s, 226.1 s | 4,711 MiB (4.94 GB) |

- Peak memory doubles almost exactly: 2M is 1.99 times 1M, within the 10% linearity check.
  The step from 1M to 2M is 2,345 MiB per million records, used for the projection below.
- A full `Event` costs 1,519 bytes on both files, measured over 20,000 records that are not
  event 7, parsed inside the traced window, with shared pools and the outcome wrapper. It was
  2,795 bytes measured the same way before amendment 9.
- Projected peaks: 3,000,000 records about 7,056 MiB (7.40 GB) and 5,000,000 about 11,700 MiB
  (12.3 GB), both above 6.0 GB. The default `--max-records` is therefore 2,000,000.

80% event 7 file, each mode twice, interleaved. Peak memory was 1,411 to 1,412 MiB (1.48 GB) in
every run.

| Mode | Ingest (runs 1, 2) | Graph (runs 1, 2) | Total mean |
| --- | --- | --- | --- |
| Neither speedup | 41.6 s, 39.8 s | 12.3 s, 12.4 s | 53.0 s |
| Lazy content hash (8a) | 38.8 s, 36.6 s | 9.8 s, 12.1 s | 48.7 s |
| 8a plus single-parse JSON checks (8b) | 34.9 s, 35.5 s | 12.1 s, 11.1 s | 46.8 s |

These times are well below the earlier runs in every mode. Fewer allocations after amendment 9
explain part of the drop and machine load the rest; these runs cannot separate the two.

**README limitation (to publish in the README at P7):** peak memory grows by about 2.3 GiB
(2.5 GB) per million records for a mix like the one above; at the default cap of 2,000,000
records the measured peak is 4.9 GB. Raising `--max-records` needs memory in proportion.

## ATT&CK verification

Not started (P7).

## Known gaps

- EVTX reading is covered only by a mocked parser and an unopenable-file test until an EVTX
  fixture is available.
- JSON documents (not JSONL) are loaded into memory whole.
- Graph build time grows faster than record count: 29–31 s at 1M realistic records against
  79–84 s at 2M (about 2.7 times). Ingest varies too much between runs to judge. Not addressed
  under amendment 11; total time at the 2M default cap was 226–283 s on the benchmark machine.
- Peak memory is about 2.3 GiB per million records (README limitation under Benchmarks).
- Carried to P4: re-run every GR-001 test with the real anchors from `anchors.yaml`, and count
  `anchor_unverified` there.
- Carried to P4: event 7 is never a coverage reason. It stays out of the missing event IDs that
  drive `not_evaluable` and `partially_evaluable` and out of the readiness lines; it appears in
  the event histogram only.

## Roadmap

Beyond v1.0, not planned for any current phase.

- Streaming or spill-to-disk for very large logs. Rejected for v1.0 by the owner: it conflicts
  with §13.2 (no files except requested outputs), adds a temporary-file attack surface, and is
  out of proportion to the log sizes this tool targets.
