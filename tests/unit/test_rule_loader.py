"""Rule schema and loader validation (§8.1, §8.4 and approved amendment 12)."""

from pathlib import Path

import pytest
import yaml

from lineage_ir.detect.loader import UniqueKeyLoader, load_rules, parse_rule
from lineage_ir.detect.schema import ALLOWED_FIELDS, TACTICS, VIRTUAL_FIELDS, Rule
from lineage_ir.errors import RuleError

VALID: dict[str, object] = {
    "id": "TST-001",
    "title": "Test rule",
    "severity": "medium",
    "attack": ["T1059.001"],
    "tactics": ["execution"],
    "why": "Exists to exercise the loader.",
    "match": {"event_id": 1, "image_name": ["powershell.exe", "pwsh.exe"]},
}


def _text(**changes: object) -> str:
    data = {**VALID, **changes}
    return yaml.safe_dump({k: v for k, v in data.items() if v is not _DROP}, sort_keys=False)


_DROP = object()


def _parse(file_name: str = "TST-001.yaml", **changes: object) -> Rule:
    return parse_rule(_text(**changes), file_name)


def _fails(pattern: str, file_name: str = "TST-001.yaml", **changes: object) -> None:
    with pytest.raises(RuleError, match=pattern) as info:
        _parse(file_name, **changes)
    assert info.value.exit_code == 2


def test_valid_rule_parses() -> None:
    rule = _parse()
    assert rule.id == "TST-001"
    assert rule.groups[0].event_ids == (1,)
    assert rule.info.event_ids == (1,)
    assert rule.info.kind == "event"


@pytest.mark.parametrize("rule_id", ["TS-01", "tst-001", "TOOLONG-001", "TST-0001", "TST001"])
def test_id_pattern(rule_id: str) -> None:
    _fails("id", file_name=f"{rule_id}.yaml", id=rule_id)


def test_file_name_must_equal_id() -> None:
    _fails("file name", file_name="TST-002.yaml")


def test_duplicate_ids_across_files(tmp_path: Path) -> None:
    (tmp_path / "TST-001.yaml").write_text(_text(), encoding="utf-8")
    (tmp_path / "TST-002.yaml").write_text(_text(id="TST-002"), encoding="utf-8")
    assert [r.id for r in load_rules(tmp_path)] == ["TST-001", "TST-002"]
    # Rules are read from every subdirectory, so the same ID can appear twice.
    (tmp_path / "other").mkdir()
    (tmp_path / "other" / "TST-001.yaml").write_text(_text(), encoding="utf-8")
    with pytest.raises(RuleError, match="duplicate"):
        load_rules(tmp_path)


def test_title_length() -> None:
    _parse(title="x" * 80)
    _fails("title", title="x" * 81)


def test_why_required_and_bounded() -> None:
    _fails("why", why=_DROP)
    _fails("why", why="")
    _parse(why="y" * 400)
    _fails("why", why="y" * 401)


def test_severity_enum() -> None:
    _fails("severity", severity="critical")


@pytest.mark.parametrize("technique", ["T105", "t1059", "T1059.01", "T1059.0011", "TA0002"])
def test_attack_pattern(technique: str) -> None:
    _fails("attack", attack=[technique])


def test_attack_may_be_empty_for_context_rules() -> None:
    assert _parse(attack=[]).attack == ()


def test_tactics_are_enterprise_slugs() -> None:
    assert len(TACTICS) == 14
    _parse(tactics=sorted(TACTICS))
    _fails("tactic", tactics=["execution", "lateral_movement"])


def test_unknown_field_name() -> None:
    _fails("unknown field", match={"event_id": 1, "imagename": "x.exe"})


def test_rule_name_is_an_allowed_field() -> None:
    assert "rule_name" in ALLOWED_FIELDS
    assert _parse(match={"event_id": 1, "rule_name": "x"}).groups[0].conditions


def test_virtual_fields_are_allowed() -> None:
    assert VIRTUAL_FIELDS <= ALLOWED_FIELDS
    for name in sorted(VIRTUAL_FIELDS - {"event_id"}):
        _parse(match={"event_id": 1, name: "x"})


@pytest.mark.parametrize(
    "key", ["image|regex", "image|contains|any", "image|all", "image|contains|all|x", "|contains"]
)
def test_key_syntax_and_modifiers(key: str) -> None:
    _fails("modifier|key", match={"event_id": 1, key: "x"})


def test_lists_non_empty_and_bounded() -> None:
    _fails("empty", match={"event_id": 1, "image_name": []})
    _parse(match={"event_id": 1, "image_name": [f"a{i}.exe" for i in range(64)]})
    _fails("64", match={"event_id": 1, "image_name": [f"a{i}.exe" for i in range(65)]})


def test_value_length() -> None:
    _parse(match={"event_id": 1, "command_line|contains": "c" * 256})
    _fails("256", match={"event_id": 1, "command_line|contains": "c" * 257})


@pytest.mark.parametrize("value", [True, None, 1.5, {"a": 1}, [["x"]]])
def test_values_are_strings_or_integers(value: object) -> None:
    _fails("string or integer", match={"event_id": 1, "image_name": value})


def test_integer_values_only_with_equals() -> None:
    _parse(match={"event_id": 3, "destination_port": 443})
    _fails("integer", match={"event_id": 3, "destination_port|contains": 443})


def test_unknown_top_level_key() -> None:
    _fails("extra|unknown|forbidden", author="someone")


def test_exactly_one_of_match_and_match_any() -> None:
    _fails("match", match=_DROP)
    _fails("match", match_any=[{"event_id": 1, "image_name": "a.exe"}])
    _fails("match_any", match=_DROP, match_any=[])


def test_group_requires_event_id() -> None:
    _fails("event_id", match={"image_name": "a.exe"})
    _fails("event_id", match_any=[{"event_id": 1}, {"image_name": "a.exe"}], match=_DROP)


@pytest.mark.parametrize("value", ["1", True, 0, -3, [1, "2"], []])
def test_event_id_values(value: object) -> None:
    _fails("event_id", match={"event_id": value, "image_name": "a.exe"})


def test_event_id_takes_no_modifier() -> None:
    _fails("event_id", match={"event_id|contains": 1, "image_name": "a.exe"})


@pytest.mark.parametrize(
    "changes",
    [
        {"match": {"event_id": 7, "image_loaded|endswith": "x.dll"}},
        {"match": {"event_id": [1, 7], "image_name": "a.exe"}},
        {
            "match": _DROP,
            "match_any": [{"event_id": 1, "image_name": "a.exe"}, {"event_id": [3, 7]}],
        },
        {"exclude": [{"event_id": [7], "image_name": "a.exe"}]},
    ],
)
def test_event_7_is_rejected(changes: dict[str, object]) -> None:
    with pytest.raises(RuleError, match="TST-001.*image-load events.*summary form in v1.0"):
        _parse(**changes)


def test_exclude_groups_may_omit_event_id() -> None:
    rule = _parse(exclude=[{"image|startswith": "c:\\windows\\"}])
    assert rule.exclude[0].event_ids == ()


def test_leading_and_trailing_spaces_are_preserved() -> None:
    text = (
        "id: TST-001\ntitle: Spaces\nseverity: low\nattack: []\ntactics: [impact]\nwhy: Test.\n"
        'match:\n  event_id: 1\n  command_line|contains:\n    - " cl "\n    - " clear-log "\n'
        '  image_name: "  padded.exe "\n'
    )
    rule = parse_rule(text, "TST-001.yaml")
    values = {c.field: (c.values, c.folded) for c in rule.groups[0].conditions}
    assert values["command_line"] == ((" cl ", " clear-log "), (" cl ", " clear-log "))
    assert values["image_name"] == (("  padded.exe ",), ("  padded.exe ",))


@pytest.mark.parametrize(
    "text",
    [
        "id: TST-001\nid: TST-002\n",
        "id: TST-001\nmatch:\n  event_id: 1\n  image_name: a.exe\n  image_name: b.exe\n",
        "id: TST-001\nmatch_any:\n  - {event_id: 1, event_id: 3}\n",
    ],
)
def test_duplicate_keys_are_rejected(text: str) -> None:
    with pytest.raises(RuleError, match="TST-001.yaml: duplicate key"):
        parse_rule(text, "TST-001.yaml")


def test_rule_yaml_loader_stays_safe() -> None:
    assert issubclass(UniqueKeyLoader, yaml.SafeLoader)
    with pytest.raises(RuleError):
        parse_rule("id: !!python/object/apply:os.getcwd []\n", "TST-001.yaml")


def test_yaml_that_is_not_a_mapping() -> None:
    with pytest.raises(RuleError):
        parse_rule("- just\n- a list\n", "TST-001.yaml")
    with pytest.raises(RuleError):
        parse_rule("id: [unclosed\n", "TST-001.yaml")


def test_loader_errors_name_the_file(tmp_path: Path) -> None:
    (tmp_path / "TST-001.yaml").write_text(_text(severity="urgent"), encoding="utf-8")
    with pytest.raises(RuleError, match="TST-001.yaml"):
        load_rules(tmp_path)


def test_every_bundled_rule_loads_and_passes_the_loader() -> None:
    rules = load_rules()
    assert len(rules) == 20
    assert [r.id for r in rules] == sorted(r.id for r in rules)
    assert all(r.enabled for r in rules)


def test_no_bundled_rule_uses_rule_name() -> None:
    for rule in load_rules():
        for group in (*rule.groups, *rule.exclude):
            assert all(c.field != "rule_name" for c in group.conditions), rule.id


def test_no_bundled_rule_uses_event_7() -> None:
    for rule in load_rules():
        assert 7 not in rule.info.event_ids
