"""Regenerate the golden files for phish_chain.jsonl (§14.3 item 4).

Run from the repository root:  python scripts/update_golden.py
Then review the diff and add a CHANGELOG note for every golden file that changed.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from helpers.golden import GOLDEN, golden_path, render  # noqa: E402


def main() -> int:
    changed = []
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
