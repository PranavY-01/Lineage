# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Package skeleton, `lineage --version` and the overview screen.
- Ingest of Sysmon EVTX, JSON and JSONL with format sniffing, SHA-256 hashing, size, line,
  depth and record caps, three record shapes, normalization, deduplication and ordering.
- `lineage validate` with text and JSON output.
- Per-host process graph: nodes from process creation, ghost nodes with recorded reasons,
  activity attached to acting and target processes, parent-loop breaking, iterative walks and
  the display collapse rule.
- Detection: 20 YAML rules with a validating loader, field resolution with virtual fields,
  PowerShell encoded-command decoding, graph heuristics GR-001 to GR-004, findings
  aggregated per rule, host and process, and `lineage rules`.
- Analysis: anchors, storylines with roots, steps, gaps and scope, ranking, focus and
  time filters, coverage with reason codes and rule evaluability, status and exit code,
  and the `run_analysis` library entry point.
- `lineage analyze`, `tree`, `story` and `inspect` with every common option, terminal
  views with escaping and URL defanging, the JSON report (`--report`, `--format json`),
  artifacts JSONL for Lucent (`--artifacts`) and atomic, path-safe output writes.
- JSON Schemas `schema/report-1.0.json` and `schema/artifacts-1.0.json`.
- Persistence and drop links between storylines, shown in the story and tree views and in
  the report, plus `scope.unlinked_targets` for targets that link nowhere. Golden files
  `phish_chain.report.json` and `phish_chain.story.txt` changed for this (updated through
  `scripts/update_golden.py`).
- Golden files for `phish_chain.jsonl` (report JSON and story view) and
  `scripts/update_golden.py` to regenerate them.

### Changed

- `--max-records` defaults to 2,000,000 so that peak memory stays under 6 GB for typical
  logs; the cap message says how to raise it.
- The report envelope's `schema_version` is the integer `1`, as in the other series tools.
- The report envelope's `tool` is `Lineage`. Golden file `phish_chain.report.json` changed
  for this (updated through `scripts/update_golden.py`).
- Line and paragraph separators (U+2028, U+2029) are escaped in human-readable output.

### Fixed

- Text output redirected to a file on Windows no longer fails on non-ASCII characters.
- Redirected or captured output on Windows uses the full terminal width, as on Linux. Golden
  file `phish_chain.story.txt` changed for this (updated through `scripts/update_golden.py`).
