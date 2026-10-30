"""ATT&CK mappings as verified by the owner against ATT&CK v20 (P7, amendment 23)."""

import pytest

from lineage_ir.config import ATTACK_VERSION
from lineage_ir.detect.schema import TACTICS
from lineage_ir.engine import list_rules

# Rule ID → (technique IDs, tactics), in the order the rule lists them.
EXPECTED = {
    "CMD-001": (("T1059.001", "T1027.010"), ("execution", "stealth")),
    "CMD-002": (("T1059.001", "T1105"), ("execution", "command-and-control")),
    "CMD-003": (("T1105", "T1140"), ("command-and-control", "stealth")),
    "CMD-004": (("T1218.005",), ("stealth",)),
    "CMD-005": (("T1218.010",), ("stealth",)),
    "CMD-006": (("T1490",), ("impact",)),
    "CMD-007": (("T1685.005",), ("defense-impairment",)),
    "CRD-001": (("T1003.001",), ("credential-access",)),
    "CRD-002": (("T1003.001",), ("credential-access",)),
    "INJ-001": (("T1055",), ("stealth", "privilege-escalation")),
    "LIN-001": (("T1204.002",), ("execution",)),
    "LIN-002": (("T1059.005", "T1059.007"), ("execution",)),
    "LIN-003": (("T1047",), ("execution",)),
    "LOC-001": ((), ("execution",)),
    "LOC-002": (("T1036.005",), ("stealth",)),
    "NET-001": (("T1218", "T1105"), ("stealth", "command-and-control")),
    "PER-001": (("T1547.001",), ("persistence",)),
    "PER-002": (("T1053.005",), ("persistence", "execution")),
    "PER-003": (("T1543.003",), ("persistence",)),
    "PER-004": (("T1547.001",), ("persistence",)),
    "GR-001": (("T1204.002",), ("execution",)),
    "GR-002": (
        ("T1033", "T1082", "T1016", "T1087", "T1482", "T1057"),
        ("discovery",),
    ),
    "GR-003": (("T1105",), ("command-and-control",)),
    "GR-004": ((), ()),
}


def test_attack_version_is_pinned() -> None:
    assert ATTACK_VERSION == "v20"


def test_the_fifteen_enterprise_tactics() -> None:
    assert len(TACTICS) == 15
    assert {"stealth", "defense-impairment"} <= TACTICS
    assert "defense-evasion" not in TACTICS


@pytest.mark.parametrize("rule_id", sorted(EXPECTED))
def test_rule_mapping(rule_id: str) -> None:
    rule = {r.id: r for r in list_rules()}[rule_id]
    assert (rule.attack, rule.tactics) == EXPECTED[rule_id]


def test_every_rule_is_covered() -> None:
    assert sorted(r.id for r in list_rules()) == sorted(EXPECTED)
