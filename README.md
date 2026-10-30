# Lineage

Offline Python CLI that reconstructs Windows process ancestry from Sysmon telemetry, extracts attack storylines, maps behaviour to MITRE ATT&CK, scopes the blast radius, and reports what it could not see.

**Status:** work in progress.

## Known limitations

- **Memory.** Lineage holds the whole analysis in memory. Peak memory grows by about 2.3 GiB
  (2.5 GB) per million records for a typical mix of Sysmon events. The default
  `--max-records` of 2,000,000 keeps the peak near 4.9 GB; raising it needs memory in
  proportion.
