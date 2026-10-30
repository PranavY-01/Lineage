"""Capture the README and user-guide screenshots as SVG (§16.4).

Run from the repository root:

    python scripts/capture_screenshots.py
    python scripts/capture_screenshots.py --hero PATH --secondary PATH --inspect TARGET

Each image is the real CLI's output, recorded through Rich and exported with ``export_svg``.
Without options the synthetic fixtures are used. With ``--hero`` and ``--secondary`` the
screenshots come from your own datasets, which stay outside the repository; name the dataset
under each image where it is shown. Images are never edited by hand.
"""

import argparse
import io
import re
import sys
from collections.abc import Sequence
from pathlib import Path

from rich.console import Console
from typer.testing import CliRunner

from lineage_ir import cli
from lineage_ir.render import terminal

ROOT = Path(__file__).resolve().parents[1]
IMAGES = ROOT / "docs" / "images"
FIXTURES = ROOT / "tests" / "fixtures"
WIDTH = 120
POWERSHELL_GUID = "8f3c2a71-5e4b-4d9a-a1c3-0000000000e1"
# Rich puts a credit comment in every SVG; it is reworded to "Rendered with Rich" so the
# repository's wording rules hold, and the credit and link are kept.
RICH_CREDIT = re.compile(r"<!-- [A-Za-z]+ with Rich (https://www\.textualize\.io) -->")


def _shots(hero: Path, secondary: Path, inspect: str) -> list[tuple[str, list[str]]]:
    return [
        ("overview", []),
        ("validate", ["validate", str(hero)]),
        ("analyze-hot", ["analyze", str(hero), "--hot-only"]),
        ("story", ["story", str(hero), "--storyline", "1"]),
        ("inspect", ["inspect", str(hero), inspect]),
        ("coverage-partial", ["analyze", str(secondary)]),
        ("rules", ["rules"]),
    ]


def capture(args: Sequence[str]) -> str:
    """Run ``lineage ARGS`` and return its standard output as SVG."""
    recorded: list[Console] = []
    original = terminal.make_console

    def recording_console(*, no_color: bool = False, stderr: bool = False) -> Console:
        console = Console(
            record=True,
            width=WIDTH,
            file=io.StringIO(),
            force_terminal=True,
            color_system="truecolor",
            emoji=False,
            highlight=False,
            legacy_windows=False,
            stderr=stderr,
        )
        if not stderr:
            recorded.append(console)
        return console

    terminal.make_console = recording_console  # type: ignore[assignment]
    try:
        result = CliRunner().invoke(cli.app, list(args), env={"COLUMNS": str(WIDTH)})
    finally:
        terminal.make_console = original  # type: ignore[assignment]
    if result.exit_code not in (0, 1, 4) or not recorded:
        raise SystemExit(f"lineage {' '.join(args)} exited {result.exit_code}")
    shown = ["lineage", *(Path(a).name if Path(a).exists() else a for a in args)]
    svg = recorded[0].export_svg(title=" ".join(shown))
    return RICH_CREDIT.sub(r"<!-- Rendered with Rich \1 -->", svg)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--hero", type=Path, default=FIXTURES / "phish_chain.jsonl")
    parser.add_argument("--secondary", type=Path, default=FIXTURES / "missing_telemetry.jsonl")
    parser.add_argument("--inspect", default=POWERSHELL_GUID, help="TARGET for `inspect`.")
    parser.add_argument("--out", type=Path, default=IMAGES)
    options = parser.parse_args(argv)
    options.out.mkdir(parents=True, exist_ok=True)
    for name, args in _shots(options.hero, options.secondary, options.inspect):
        path = options.out / f"{name}.svg"
        path.write_text(capture(args), encoding="utf-8", newline="\n")
        print(f"wrote {path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT) else path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
