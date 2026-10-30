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

### Changed

- `--max-records` defaults to 2,000,000 so that peak memory stays under 6 GB for typical
  logs; the cap message says how to raise it.
