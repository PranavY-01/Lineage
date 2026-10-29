"""Static checks over src/: forbidden calls, import boundaries and layering (§4.2, §13.2)."""

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "lineage_ir"
MODULES = sorted(SRC.rglob("*.py"))

FORBIDDEN_MODULES = {"pickle", "marshal", "subprocess", "shelve"}
FORBIDDEN_BUILTINS = {"eval", "exec", "compile", "__import__"}
FORBIDDEN_ATTRS = {("os", "system"), ("os", "popen"), ("yaml", "load"), ("yaml", "unsafe_load")}

# Lower layers that must stay free of process-level side effects.
PURE_PACKAGES = ("ingest", "graph", "detect", "analyze")

# Allowed import direction: a package may import itself and anything to its right.
LAYERS = ("cli", "engine", "analyze", "detect", "graph", "ingest", "models")

TEXT_RENDERERS = {"render/terminal.py", "render/safe.py"}


def _rel(path: Path) -> str:
    return path.relative_to(SRC).as_posix()


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _imports(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
    return names


def _top(name: str) -> str:
    return name.split(".", 1)[0]


def test_sources_found() -> None:
    assert len(MODULES) > 20


@pytest.mark.parametrize("path", MODULES, ids=_rel)
def test_no_forbidden_calls(path: Path) -> None:
    tree = _tree(path)
    problems = [m for m in _imports(tree) if _top(m) in FORBIDDEN_MODULES]
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in FORBIDDEN_BUILTINS:
                problems.append(func.id)
            for keyword in node.keywords:
                if (
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                ):
                    problems.append("shell=True")
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and (node.value.id, node.attr) in FORBIDDEN_ATTRS
        ):
            problems.append(f"{node.value.id}.{node.attr}")
        if isinstance(node, ast.ImportFrom) and node.module in {"os", "yaml"}:
            for alias in node.names:
                if (node.module, alias.name) in FORBIDDEN_ATTRS:
                    problems.append(f"from {node.module} import {alias.name}")
    assert problems == []


@pytest.mark.parametrize("path", MODULES, ids=_rel)
def test_typer_only_in_cli(path: Path) -> None:
    uses_typer = any(_top(m) in {"typer", "click"} for m in _imports(_tree(path)))
    assert not uses_typer or _rel(path) == "cli.py"


@pytest.mark.parametrize("path", MODULES, ids=_rel)
def test_rich_only_in_text_renderers(path: Path) -> None:
    uses_rich = any(_top(m) == "rich" for m in _imports(_tree(path)))
    assert not uses_rich or _rel(path) in TEXT_RENDERERS


def _package(path: Path) -> str:
    rel = _rel(path)
    return rel.split("/", 1)[0].removesuffix(".py")


@pytest.mark.parametrize("path", [p for p in MODULES if _package(p) in PURE_PACKAGES], ids=_rel)
def test_pure_layers_have_no_side_effects(path: Path) -> None:
    tree = _tree(path)
    problems = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in {"print", "exit", "quit", "input"}:
                problems.append(node.func.id)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            pair = (node.value.id, node.attr)
            if pair in {("sys", "exit"), ("os", "environ"), ("os", "getenv"), ("os", "_exit")}:
                problems.append(".".join(pair))
        if isinstance(node, ast.ImportFrom) and node.module in {"os", "sys"}:
            for alias in node.names:
                if alias.name in {"environ", "getenv", "exit", "_exit"}:
                    problems.append(f"from {node.module} import {alias.name}")
    assert problems == []


@pytest.mark.parametrize("path", [p for p in MODULES if _package(p) in LAYERS], ids=_rel)
def test_imports_follow_layer_direction(path: Path) -> None:
    own = LAYERS.index(_package(path))
    for name in _imports(_tree(path)):
        parts = name.split(".")
        if parts[0] != "lineage_ir" or len(parts) < 2:
            continue
        target = parts[1]
        if target in LAYERS:
            assert LAYERS.index(target) >= own, f"{_rel(path)} imports {name}"
        if target in {"render", "outputs"}:
            assert _package(path) == "cli", f"{_rel(path)} imports {name}"
