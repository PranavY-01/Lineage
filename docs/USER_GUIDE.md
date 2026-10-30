# Lineage user guide

This guide is task by task. Every example runs on the synthetic fixtures in `tests/fixtures/`;
replace the path with your own Sysmon export to work on real data.

## Before you start: is the telemetry good enough?

```bash
lineage validate case.evtx
```

`validate` reads and normalizes only. Check:

- **Hosts and span:** the machines and the time range in the file.
- **Records:** totals, Sysmon versus irrelevant (other channels), invalid records by reason,
  duplicates.
- **Event IDs and Missing:** which standard Sysmon events are present. Missing 3 means no
  network view; missing 13 means Run-key persistence cannot be seen.
- **Readiness by rule family:** `lineage` needs event 1, `network` needs 3, `persistence`
  needs 1, 11 and 13, `injection` needs 8, `credential access` needs 10 or 1.

Exit code 4 from `validate` means invalid records, no Sysmon events or a record cap that
stopped reading early. JSON exported with `Out-File` in Windows PowerShell 5 is UTF-16; export
it again with `-Encoding utf8`.

## Triage an alert on one process (UC-1)

Your SIEM flagged a process. Pivot on it:

```bash
lineage analyze case.evtx --focus 8f3c2a71-5e4b-4d9a-a1c3-0000000000e1
lineage analyze case.evtx --focus pid:1225 --around 2026-10-12T10:02:06Z --window 5m
lineage analyze case.evtx --focus image:powershell.exe
```

`--focus` accepts a GUID (braces optional), `pid:N` or `image:NAME`. The views then show only
that process, all its ancestors and all its descendants. A PID that matches several
processes exits 2 and lists the candidates with host, GUID, image and start time; pick the
GUID. `--around` limits what is shown to a time window. Neither changes the result or exit
code.

## Find patient zero (UC-2)

```bash
lineage story tests/fixtures/phish_chain.jsonl
```

Each storyline title names its root: the topmost process below a system anchor such as
`explorer.exe` or `services.exe`. In the fixture, S1 starts at `OUTLOOK.EXE`, which opened
`WINWORD.EXE`, which started the encoded PowerShell. `lineage inspect FILE TARGET` shows the
full ancestry of any process, anchors marked.

## Scope a host (UC-3)

```bash
lineage analyze tests/fixtures/phish_chain.jsonl --hot-only
```

Under each storyline tree:

- **Scope** counts users, processes, files written (executables first), persistence keys
  and destinations.
- **Review** turns them into a checklist: verify processes, review persistence keys and
  files, hunt destinations.

`lineage story` lists the items themselves, including persistence targets that link nowhere:
"ran as GUID at TIME, in no storyline" means the target ran but nothing flagged it; "not seen
running" means no later process ran it in this log.

Persistence links appear as `↪ fires later as S2 (exact match: …)` under the step that set
them, and as `↩ persistence of S1` on the process that ran later.

## Hand IOCs to Lucent (UC-4)

```bash
lineage analyze case.evtx --artifacts out/iocs.jsonl
lucent scan out/iocs.jsonl --format both --output-dir out/
```

The artifacts file holds raw values from storyline processes only: command lines, decoded
payloads, destinations, DNS names, files, registry values and image hashes, each with its
storyline, host, process GUID and record ID. Lucent extracts IPv4 addresses, domains, URLs
and MD5/SHA-1/SHA-256 hashes.

## Check a Sysmon configuration (UC-5)

```bash
lineage validate test-run.evtx
lineage analyze test-run.evtx
```

The coverage panel names every rule that could not run and the event IDs it needs, for
example `CRD-001 not evaluable (needs 10)`. A run with any such reason exits 4 and prints
"Coverage is partial: no findings in what could be analyzed is NOT a clean result." To test
only what your configuration collects, scope the rules:

```bash
lineage analyze test-run.evtx --rules LIN,CMD,NET
```

Rules left out with `--rules` never create coverage reasons.

## Reading each view

- **Header:** inputs with SHA-256 and size, hosts, time span, parameters, and any display
  filter in effect.
- **Coverage:** `✓ COMPLETE` or `✗ PARTIAL`, absent event IDs, and one line per reason.
- **Storylines table:** ID, root, host, highest severity, number of tactics, number of
  findings, start. Storylines with only low or info findings are collapsed under
  "Low-signal storylines"; `lineage story --storyline N` shows one in full.
- **Trees:**
  - Markers: `!` a process with findings (rule IDs at the end); `?` a ghost (never seen
    created); `(anchor)` a system anchor; dim text a process on the path to a finding;
    `× N name` same-named siblings with no findings folded together.
  - Under flagged processes the tree shows their network, DNS, file, registry and
    process-access activity, five lines per kind.
- **Story:** numbered steps in time order with tactic headings, `⏸` marks for pauses of at
  least `--gap` (10 minutes), and link lines.
- **Result:** status, counts and the exit code.

URLs in human-readable output are defanged (`hxxp[://]example[.]com`); the JSON report,
artifacts and CSV keep raw values.

## Troubleshooting

- **"UTF-16/32 JSON" (exit 3):** export again as UTF-8.
- **No Sysmon records:** the file holds other channels only; `validate` lists them by
  channel.
- **Focus is ambiguous or not found (exit 2):** use the GUID from the candidate list, or add
  `--host`.
- **Record cap reached (exit 4):** the default `--max-records` is 2,000,000 (about 4.9 GB of
  memory); raise it only with enough memory, or split the input by time or host.
- **Output refused (exit 2):** Lineage will not write over an input, a link, a directory, an
  existing file without `--force`, or a file it did not write.
