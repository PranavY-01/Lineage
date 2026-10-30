"""Regenerate the golden files for phish_chain.jsonl (§14.3 item 4) and apply oracle revisions.

Run from the repository root:  python scripts/update_golden.py
Then review the diff and add a CHANGELOG note for every golden file that changed.

The oracle (phish_chain.storylines.json) is never rebuilt from output. A spec change that
alters it is applied here as a hand-derived revision: the old value must still be in the
file, it is replaced by the new value, and the reason is appended to the oracle's
``revisions`` list. Applying a revision twice changes nothing.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from helpers.golden import GOLDEN, GOLDEN_DIR, golden_path, render  # noqa: E402

ORACLE = GOLDEN_DIR / "phish_chain.storylines.json"

# (storyline, field, old value, new value, reason). Values are derived by hand from the rule
# catalogue and the fixture, never copied from output.
ORACLE_REVISIONS = [
    (
        "S1",
        "tactics",
        ["execution", "defense-evasion", "command-and-control", "persistence"],
        ["execution", "stealth", "command-and-control", "persistence"],
        "Amendment 23 (sections 8.4, 8.6, 8.7, ATT&CK v20): CMD-001 and NET-001 list stealth "
        "instead of defense-evasion and GR-001 lists execution only, so the S1 tactics in "
        "first-seen order are execution, stealth, command-and-control, persistence (was "
        "execution, defense-evasion, command-and-control, persistence).",
    ),
    (
        "S2",
        "tactics",
        ["execution", "discovery"],
        ["command-and-control", "execution", "discovery"],
        "Amendment 23: GR-003 lists command-and-control; its first event (11:00:00, the "
        "execution) sorts before LOC-001 at the same time by rule ID, so the S2 tactics are "
        "command-and-control, execution, discovery (was execution, discovery).",
    ),
]


def _json_list(values: list[str]) -> str:
    return json.dumps(values)


def _append_revision(text: str, reason: str) -> str:
    """Add ``reason`` as the last entry of the oracle's revisions list."""
    marker = '  "revisions": ['
    if text.count(marker) != 1:
        raise SystemExit("oracle has no revisions list")
    start = text.index(marker) + len(marker)
    end = text.index("  ],", start)
    body = text[start:end].rstrip()
    entry = "    " + json.dumps(reason)
    body = f"{body},\n{entry}\n" if body else f"\n{entry}\n"
    return text[:start] + body + text[end:]


def apply_oracle_revisions() -> bool:
    """Apply pending oracle revisions in place, keeping the file's layout; True if changed."""
    text = ORACLE.read_text(encoding="utf-8")
    document = json.loads(text)
    by_id = {s["storyline_id"]: s for s in document["storylines"]}
    changed = False
    for storyline, field, old, new, reason in ORACLE_REVISIONS:
        current = by_id[storyline][field]
        if current == new:
            continue
        if current != old:
            raise SystemExit(f"oracle {storyline}.{field} is {current}, expected {old}")
        old_line = f'"{field}": {_json_list(old)},'
        new_line = f'"{field}": {_json_list(new)},'
        if text.count(old_line) != 1:
            raise SystemExit(f"oracle line for {storyline}.{field} is not unique")
        text = text.replace(old_line, new_line)
        text = _append_revision(text, reason)
        changed = True
    if changed:
        json.loads(text)  # still valid JSON
        ORACLE.write_text(text, encoding="utf-8", newline="\n")
    return changed


def main() -> int:
    changed = []
    if apply_oracle_revisions():
        changed.append(ORACLE.relative_to(ROOT).as_posix())
    for name in GOLDEN:
        path = golden_path(name)
        data = render(name)
        old = path.read_bytes() if path.exists() else None
        if old != data:
            path.write_bytes(data)
            changed.append(path.relative_to(ROOT).as_posix())
    for item in changed:
        print(f"updated {item}")
    if not changed:
        print("golden files are up to date")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
