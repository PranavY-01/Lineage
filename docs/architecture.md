# Architecture

Lineage is a six-stage pipeline with a coverage collector that every stage reports into.

```
ingest → normalize → graph → detect → analyze → render
   └────────────── counters and reasons → coverage ─────────────┘
```

## Packages

| Package | Role |
|---|---|
| `ingest/` | Input discovery, hashing, format sniffing, caps; EVTX and JSON readers; shape detection (EVTX-native, flat, Winlogbeat); normalization into `Event`; deduplication and ordering |
| `graph/` | One `ProcessGraph` per host built in three passes (creations, ghosts, activity); iterative traversal with a cycle guard; the display collapse rule |
| `detect/` | YAML rule schema and loader, field resolution with virtual fields, matching, the four graph heuristics, aggregation into `Finding`s |
| `analyze/` | Anchors, storylines (roots, membership, ranking), story steps, gaps, scope, persistence and drop links, focus, display filters, PowerShell decoding, coverage and status |
| `render/` | Text safety (`safe.py`), Rich terminal views, the JSON report, artifacts JSONL, CSV timeline |
| `outputs.py` | The only module that writes files: path checks and atomic writes |
| `engine.py` | `run_analysis(inputs, params)`, the library entry point |
| `cli.py` | Typer commands; builds `AnalysisParams`, calls the engine, hands the result to a renderer |

## Layering rules

1. `cli.py` is the only module that imports Typer; the text renderers in `render/` are the
   only ones that import Rich.
2. `ingest`, `graph`, `detect` and `analyze` never print, read environment variables or exit;
   they return models or raise typed errors from `errors.py`.
3. Dependencies point one way: `cli → engine → analyze → detect → graph → ingest → models`.
4. Renderers only format an `AnalysisResult`; they never compute findings, severities or
   coverage.
5. Graph code is iterative. `eval`, `exec`, `pickle`, `marshal`, `subprocess`, `os.system`,
   `shell=True` and `yaml.load` are not used anywhere in `src/`.

A test in `tests/safety/` enforces these rules on every run.

## Data model

All state is carried by frozen pydantic v2 models (`strict=True, extra="forbid"`):

- `SourceRef`: input base name, its SHA-256, record index and record ID. Every finding, step
  and link cites them.
- `Event`: one normalized Sysmon record.
- `ProcessNode`: one process instance, created by event 1 or reconstructed as a ghost, with
  its activity and a slim summary of image loads.
- `Finding`: rule hits aggregated per rule, host and process, with up to 20 evidence
  references.
- `Storyline`: root, members, findings, tactics, steps, gaps, scope and links.
- `Coverage`: counters from every stage, reason codes, per-rule evaluability and the
  telemetry timeline.
- `AnalysisResult`: everything above plus inputs, parameters and run metadata. `result`,
  `status` and `exit_code` are derived from findings and coverage.

Times are integer microseconds since the epoch, UTC; they are formatted as RFC 3339 with `Z`
only when rendered.

## Extension points

- **A new rule:** add `src/lineage_ir/detect/rules/windows/<ID>.yaml` with a positive and a
  near-miss negative fixture in `tests/fixtures/rules/`, then run
  `python scripts/build_docs.py` to rebuild `docs/rules.md`.
- **A new input shape:** recognise it in `ingest/shapes.py` and map its keys in
  `ingest/field_aliases.py`; add a fixture under `tests/fixtures/shapes/` that must normalize
  like the existing shapes.
- **A new platform:** `ingest/linux/` is reserved for a platform adapter that produces the
  same `Event` model.
