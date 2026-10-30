"""Release checks (P7, §15.2, §15.3, §16)."""

import json
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from helpers.reports import validator
from lineage_ir import __version__, cli

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import build_docs  # noqa: E402

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
README_SECTIONS = [
    "Problem and aim",
    "Why Lineage",
    "Features and non-goals",
    "How it works",
    "Installation",
    "Quick start",
    "Commands and options",
    "Rules",
    "Coverage: reading a result",
    "Report format and artifacts",
    "Exit codes",
    "Security considerations and limitations",
    "Privacy and responsible use",
    "Tests and CI",
    "Roadmap",
    "Licence and dataset credits",
]


def _text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_version_is_a_release_with_a_changelog_entry() -> None:
    major, minor, patch = (int(part) for part in __version__.split("."))
    assert major >= 1 and minor >= 0 and patch >= 0
    pattern = rf"^## \[{re.escape(__version__)}\] - \d{{4}}-\d{{2}}-\d{{2}}$"
    assert re.search(pattern, _text("CHANGELOG.md"), re.MULTILINE)


def test_version_flag_prints_the_package_version() -> None:
    result = CliRunner().invoke(cli.app, ["--version"])
    assert result.exit_code == 0 and result.output.strip() == f"lineage {__version__}"


def test_html_report_is_not_offered() -> None:
    analyze = typer.main.get_command(cli.app).commands["analyze"]  # type: ignore[attr-defined]
    options = {opt for param in analyze.params for opt in param.opts}
    assert "--html" not in options and "--csv" in options
    # Typer forces coloured help when GITHUB_ACTIONS is set, so compare the text without
    # ANSI escape sequences.
    result = CliRunner().invoke(cli.app, ["analyze", "--help"], env={"COLUMNS": "200"})
    help_text = ANSI_ESCAPE.sub("", result.output)
    assert "--html" not in help_text and "--csv" in help_text
    pyproject = _text("pyproject.toml")
    assert "jinja2" not in pyproject.lower()
    roadmap = _text("README.md").split("## Roadmap", 1)[1]
    assert "HTML report" in roadmap


def test_rules_doc_is_current() -> None:
    text = _text("docs/rules.md")
    assert text == build_docs.rules_markdown()
    assert "ATT&CK v20" in text and "MITRE" in text
    for rule in ("CMD-007", "GR-003", "T1685.005"):
        assert rule in text


def test_sample_report_is_current_and_valid() -> None:
    text = _text("examples/sample-report.json")
    assert text == build_docs.sample_report_text()
    document = json.loads(text)
    assert list(validator("report-1.0.json").iter_errors(document)) == []
    assert document["parameters"]["attack_version"] == "v20"


def _demo_commands(path: Path) -> list[list[str]]:
    commands = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line.startswith("lineage "):
            commands.append(shlex.split(line, posix=True))
    return commands


@pytest.mark.parametrize("name", ["demo.sh", "demo.ps1"])
def test_demo_scripts_use_only_existing_commands_and_options(name: str) -> None:
    group = typer.main.get_command(cli.app)
    commands = _demo_commands(ROOT / "examples" / name)
    assert len(commands) >= 6
    for words in commands:
        command = group.commands[words[1]]  # type: ignore[attr-defined]
        known = {opt for param in command.params for opt in param.opts}
        for word in words[2:]:
            if word.startswith("--"):
                assert word in known, f"{name}: {words[1]} has no option {word}"
        assert "--html" not in words


def test_readme_sections_in_order() -> None:
    readme = _text("README.md")
    headings = re.findall(r"^## (.+)$", readme, re.MULTILINE)
    assert [h for h in headings if h in README_SECTIONS] == README_SECTIONS
    assert "Day 7 of *7 Days – 7 Cybersecurity Projects*" in readme
    assert "docs/images/analyze-hot.svg" in readme
    assert "A partial analysis is never presented as clean" in readme


def test_docs_and_examples_exist() -> None:
    for relative in (
        "docs/USER_GUIDE.md",
        "docs/architecture.md",
        "docs/rules.md",
        "scripts/fetch_demo_data.md",
        "scripts/capture_screenshots.py",
        "examples/demo.sh",
        "examples/demo.ps1",
        "LICENSE",
    ):
        assert (ROOT / relative).is_file(), relative
    for image in (
        "overview",
        "validate",
        "analyze-hot",
        "story",
        "inspect",
        "coverage-partial",
        "rules",
    ):
        svg = ROOT / "docs" / "images" / f"{image}.svg"
        assert svg.is_file() and svg.read_text(encoding="utf-8").lstrip().startswith("<svg")


def test_fetch_notes_link_only_the_named_samples() -> None:
    text = _text("scripts/fetch_demo_data.md")
    assert "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES" in text
    assert "Execution/Exec_sysmon_meterpreter_reversetcp_msipackage.evtx" in text
    assert "Lateral Movement/lm_sysmon_18_remshell_over_namedpipe.evtx" in text


def _tracked() -> list[str]:
    git = shutil.which("git")
    if git is None:
        pytest.skip("git is not installed")
    proc = subprocess.run([git, "ls-files"], cwd=ROOT, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        pytest.skip("not a git checkout")
    return proc.stdout.splitlines()


def test_no_dataset_files_are_tracked() -> None:
    files = _tracked()
    assert not [f for f in files if f.lower().endswith(".evtx")]
    assert not [f for f in files if f.startswith("data/")]
    assert not [
        f for f in files if "attack-samples" in f.lower() or "security-datasets" in f.lower()
    ]
