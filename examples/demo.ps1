# The Lineage demo journey (README "Quick start"), on the synthetic fixtures.
# Run from the repository root after `pip install -e .`.
New-Item -ItemType Directory -Force out | Out-Null

lineage validate tests/fixtures/phish_chain.jsonl                 # what is here, what is missing
lineage analyze tests/fixtures/phish_chain.jsonl --hot-only       # storylines, hot trees, scope
lineage story tests/fixtures/phish_chain.jsonl --storyline 1      # the attack as a narrative
lineage inspect tests/fixtures/phish_chain.jsonl image:powershell.exe   # one process in full
lineage analyze tests/fixtures/phish_chain.jsonl --report out/report.json --artifacts out/iocs.jsonl --csv out/timeline.csv --force
lineage analyze tests/fixtures/missing_telemetry.jsonl            # honest coverage: exit 4

# With Lucent installed, hand the artifacts over:
#   lucent scan out/iocs.jsonl --format both --output-dir out/
