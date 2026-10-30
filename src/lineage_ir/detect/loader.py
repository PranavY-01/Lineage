"""Loading and validation of rule files (§8.1, §8.4); any failure is a RuleError (exit 2)."""

from collections.abc import Hashable
from importlib.resources import files
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from lineage_ir.detect.schema import Rule
from lineage_ir.errors import RuleError

RULE_SUFFIX = ".yaml"


def bundled_rules_dir() -> Traversable:
    """The rules shipped as package data (``detect/rules/<platform>/<ID>.yaml``)."""
    return files("lineage_ir.detect") / "rules"


def _describe(exc: ValidationError) -> str:
    problems = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error["loc"]) or "rule"
        if error["type"] == "extra_forbidden":
            problems.append(f"unknown key {location!r}")
            continue
        message = error["msg"].removeprefix("Value error, ")
        problems.append(f"{location}: {message}")
    return "; ".join(problems)


class DuplicateKeyError(yaml.YAMLError):
    """A mapping in a rule file repeats a key (``yaml.safe_load`` would keep the last one)."""


class UniqueKeyLoader(yaml.SafeLoader):
    """The safe loader, plus a check that no mapping repeats a key."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: set[Any] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)  # type: ignore[no-untyped-call]
            if isinstance(key, Hashable) and key in seen:
                raise DuplicateKeyError(f"duplicate key {key!r}")
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def load_yaml(text: str) -> Any:
    """What yaml.safe_load does, with the duplicate-key check; raises yaml.YAMLError."""
    loader = UniqueKeyLoader(text)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()  # type: ignore[no-untyped-call]


def parse_rule(text: str, file_name: str) -> Rule:
    """Parse and validate one rule file; ``file_name`` must be ``<id>.yaml``."""
    try:
        data = load_yaml(text)
    except DuplicateKeyError as exc:
        raise RuleError(f"{file_name}: {exc}") from None
    except yaml.YAMLError as exc:
        raise RuleError(f"{file_name}: not valid YAML") from exc
    if not isinstance(data, dict):
        raise RuleError(f"{file_name}: a rule file must be a mapping")
    label = data.get("id") if isinstance(data.get("id"), str) else "rule"
    try:
        rule = Rule.model_validate(data)
    except ValidationError as exc:
        raise RuleError(f"{file_name}: {label}: {_describe(exc)}") from None
    if file_name != f"{rule.id}{RULE_SUFFIX}":
        raise RuleError(f"{file_name}: file name must be {rule.id}{RULE_SUFFIX}")
    return rule


def _rule_files(root: Traversable) -> list[tuple[str, Traversable]]:
    """Every ``*.yaml`` below ``root`` with its relative path, sorted by that path."""
    found: list[tuple[str, Traversable]] = []
    pending: list[tuple[str, Traversable]] = [("", root)]
    while pending:
        prefix, directory = pending.pop()
        for entry in directory.iterdir():
            relative = f"{prefix}{entry.name}"
            if entry.is_dir():
                pending.append((f"{relative}/", entry))
            elif entry.name.endswith(RULE_SUFFIX):
                found.append((relative, entry))
    return sorted(found, key=lambda item: item[0])


def load_rules(directory: Path | Traversable | None = None) -> tuple[Rule, ...]:
    """Load every rule below ``directory`` (default: the bundled rules), sorted by rule ID."""
    root = bundled_rules_dir() if directory is None else directory
    rules: dict[str, tuple[str, Rule]] = {}
    for relative, entry in _rule_files(root):
        rule = parse_rule(entry.read_text(encoding="utf-8"), entry.name)
        if rule.id in rules:
            raise RuleError(
                f"{relative}: duplicate rule id {rule.id} (also in {rules[rule.id][0]})"
            )
        rules[rule.id] = (relative, rule)
    return tuple(rule for _, (_, rule) in sorted(rules.items()))
