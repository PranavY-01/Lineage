"""Build docs/rules.md and examples/sample-report.json from the code (§16.2, §16.5).

Run from the repository root:  python scripts/build_docs.py
A test fails when either file differs from what this script builds, so rebuild after any
rule, mapping or version change.
"""

import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

from lineage_ir.config import ATTACK_VERSION  # noqa: E402
from lineage_ir.detect.graph_rules import GRAPH_RULES  # noqa: E402
from lineage_ir.detect.loader import load_rules  # noqa: E402
from lineage_ir.detect.schema import Group, Rule  # noqa: E402
from lineage_ir.engine import rule_set_sha256, run_analysis  # noqa: E402
from lineage_ir.ingest.timeparse import to_us  # noqa: E402
from lineage_ir.models import RuleInfo  # noqa: E402
from lineage_ir.render import report_json  # noqa: E402

RULES_DOC = ROOT / "docs" / "rules.md"
SAMPLE_REPORT = ROOT / "examples" / "sample-report.json"
SAMPLE_INPUT = ROOT / "tests" / "fixtures" / "phish_chain.jsonl"
SAMPLE_RUN_ID = "00000000-0000-4000-8000-000000000001"
SAMPLE_TIME_US = to_us(datetime(2026, 10, 30, 12, 0, 0, tzinfo=UTC))

# ATT&CK Enterprise v20 names, as verified by the project owner (BUILD_NOTES, amendment 23).
TECHNIQUES = {
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1016": "System Network Configuration Discovery",
    "T1027.010": "Obfuscated Files or Information: Command Obfuscation",
    "T1033": "System Owner/User Discovery",
    "T1036.005": "Masquerading: Match Legitimate Resource Name or Location",
    "T1047": "Windows Management Instrumentation",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1055": "Process Injection",
    "T1057": "Process Discovery",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1059.005": "Command and Scripting Interpreter: Visual Basic",
    "T1059.007": "Command and Scripting Interpreter: JavaScript",
    "T1082": "System Information Discovery",
    "T1087": "Account Discovery",
    "T1105": "Ingress Tool Transfer",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1204.002": "User Execution: Malicious File",
    "T1218": "System Binary Proxy Execution",
    "T1218.005": "System Binary Proxy Execution: Mshta",
    "T1218.010": "System Binary Proxy Execution: Regsvr32",
    "T1482": "Domain Trust Discovery",
    "T1490": "Inhibit System Recovery",
    "T1543.003": "Create or Modify System Process: Windows Service",
    "T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
    "T1685.005": "Disable or Modify Tools: Clear Windows Event Logs",
}
TACTIC_NAMES = {
    "command-and-control": "Command and Control",
    "credential-access": "Credential Access",
    "defense-impairment": "Defense Impairment",
    "discovery": "Discovery",
    "execution": "Execution",
    "impact": "Impact",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "stealth": "Stealth",
}
GRAPH_LOGIC = {
    "GR-001": (
        "A process made an outbound connection (event 3, initiated) and one of its ancestors, "
        "up to the first anchor, is an Office application from the LIN-001 list. The finding "
        "is on the connecting process."
    ),
    "GR-002": (
        "Three or more different discovery tools (whoami, systeminfo, nltest, net, net1, "
        "ipconfig, quser, tasklist, netstat, arp, route, nslookup) started by one parent "
        "within 120 seconds. The finding is on the parent."
    ),
    "GR-003": (
        "A file written by event 11 is later started by event 1 on the same host (same "
        "normalized path). The finding is on the started process; the most recent earlier "
        "write is reported as the creator."
    ),
    "GR-004": (
        "A process with no creation record (a ghost seen through its own activity) made "
        "network connections or created files. The finding is on the ghost. Anchors with a "
        "verified path and the path-less System and Registry processes are skipped; a "
        "ghost that matches an anchor by name alone is still flagged."
    ),
}
FALSE_POSITIVES = {
    "CMD-001": "Management agents and installers that pass scripts as encoded commands.",
    "CMD-002": "Admin or bootstrap scripts that download modules or installers inline.",
    "CMD-003": "Administrators decoding certificates or checking revocation lists.",
    "CMD-004": "Legacy internal tools built as HTML applications.",
    "CMD-005": "Old software that registers scriptlets during installation.",
    "CMD-006": "Backup software or administrators removing old shadow copies.",
    "CMD-007": "Planned log maintenance and lab or image resets.",
    "CRD-001": "Security, backup or monitoring agents that are not on the exclusion list.",
    "CRD-002": "Administrators taking LSASS dumps on purpose for troubleshooting.",
    "INJ-001": "Debuggers, accessibility tools and some security products.",
    "LIN-001": "Office add-ins or macros that legitimately start scripts or helpers.",
    "LIN-002": "Logon or maintenance scripts written in VBScript or JScript.",
    "LIN-003": "Systems management tools that run commands through WMI.",
    "LOC-001": "Installers, updaters and portable tools run from Temp or Downloads.",
    "LOC-002": "Third-party software that ships a binary with the same name.",
    "NET-001": "Signed components hosted by rundll32 that contact update servers.",
    "PER-001": "Applications and updaters that add themselves to Run keys.",
    "PER-002": "Installers and IT management that create scheduled tasks.",
    "PER-003": "Driver and service installers, and IT tooling.",
    "PER-004": "Shortcuts placed in Startup by users or installers.",
    "GR-001": "Office add-ins or helpers launched from documents that reach the network.",
    "GR-002": "Inventory or logon scripts that run several discovery tools.",
    "GR-003": "Installers and updaters that download and then run their own binaries.",
    "GR-004": "Logs that start after the process did, so its creation is missing.",
}


def _technique_link(technique: str) -> str:
    path = technique.replace(".", "/")
    return f"[{technique}](https://attack.mitre.org/techniques/{path}/)"


def _code(value: object) -> str:
    return "`" + str(value).replace("`", "'") + "`"


def _condition_text(group: Group) -> str:
    parts = []
    if group.event_ids:
        ids = ", ".join(str(i) for i in group.event_ids)
        parts.append(f"event {ids}")
    for condition in group.conditions:
        verb = {
            "equals": "is",
            "contains": "contains",
            "startswith": "starts with",
            "endswith": "ends with",
        }.get(condition.modifier, condition.modifier)
        joiner = " and " if condition.require_all else " or "
        values = joiner.join(_code(v) for v in condition.values)
        parts.append(f"{_code(condition.field)} {verb} {values}")
    return "; ".join(parts)


def _event_rule_logic(rule: Rule) -> list[str]:
    lines = []
    groups = rule.groups
    if len(groups) == 1:
        lines.append(f"- Matches: {_condition_text(groups[0])}.")
    else:
        lines.append("- Matches any of:")
        lines.extend(f"  - {_condition_text(g)}." for g in groups)
    if rule.exclude:
        lines.append("- Unless:")
        lines.extend(f"  - {_condition_text(g)}." for g in rule.exclude)
    return lines


def _techniques(info: RuleInfo) -> str:
    if not info.attack:
        return "none (context signal)"
    return "; ".join(f"{_technique_link(t)} {TECHNIQUES[t]}" for t in info.attack)


def _tactics(info: RuleInfo) -> str:
    return ", ".join(TACTIC_NAMES[t] for t in info.tactics) or "none"


def rules_markdown() -> str:
    """The text of docs/rules.md."""
    rules = {r.id: r for r in load_rules()}
    infos = sorted(
        [r.info for r in GRAPH_RULES] + [r.info for r in rules.values()], key=lambda i: i.id
    )
    out = [
        "# Rules",
        "",
        f"Lineage ships {len(rules)} event rules and {len(GRAPH_RULES)} graph heuristics. "
        "This file is built from the rule files and the graph heuristics by "
        "`scripts/build_docs.py`; do not edit it by hand.",
        "",
        f"Technique and tactic mappings follow **MITRE ATT&CK {ATTACK_VERSION} (Enterprise)** "
        "and are advisory: a finding is a lead for an analyst, not proof of a technique. "
        "Every ID below was checked against the ATT&CK website for this version.",
        "",
        "## Summary",
        "",
        "| ID | Kind | Title | Severity | Events | ATT&CK | Tactics |",
        "|---|---|---|---|---|---|---|",
    ]
    for info in infos:
        events = ", ".join(str(i) for i in info.event_ids)
        attack = ", ".join(info.attack) or "none"
        out.append(
            f"| {info.id} | {info.kind} | {info.title} | {info.severity} | {events} | "
            f"{attack} | {_tactics(info)} |"
        )
    out.append("")
    for info in infos:
        out += [f"## {info.id} · {info.title}", ""]
        out.append(
            f"- Kind: {info.kind}; severity: {info.severity}; needs events: "
            + ", ".join(str(i) for i in info.event_ids)
            + "."
        )
        out.append(f"- ATT&CK: {_techniques(info)}.")
        out.append(f"- Tactics: {_tactics(info)}.")
        if info.id in rules:
            out += _event_rule_logic(rules[info.id])
        else:
            out.append(f"- Logic: {GRAPH_LOGIC[info.id]}")
        out.append(f"- Why it matters: {' '.join(info.why.split())}")
        out.append(f"- Known false positives: {FALSE_POSITIVES[info.id]}")
        out.append("")
    out += [
        "## Attribution",
        "",
        "Technique and tactic IDs and names are from MITRE ATT&CK®, "
        "<https://attack.mitre.org/>. ATT&CK is a registered trademark of The MITRE "
        "Corporation and is used here under the ATT&CK terms of use. Lineage is not "
        "affiliated with or endorsed by MITRE.",
        "",
    ]
    return "\n".join(out)


def sample_report_text() -> str:
    """The text of examples/sample-report.json: phish_chain.jsonl with a fixed run ID and time."""
    result = run_analysis(
        [SAMPLE_INPUT],
        clock=lambda: SAMPLE_TIME_US,
        run_id_factory=lambda: SAMPLE_RUN_ID,
    )
    return report_json.dumps(report_json.report_document(result, rule_set_sha256()))


def main() -> int:
    for path, text in ((RULES_DOC, rules_markdown()), (SAMPLE_REPORT, sample_report_text())):
        path.parent.mkdir(parents=True, exist_ok=True)
        old = path.read_text(encoding="utf-8") if path.exists() else None
        if old != text:
            path.write_text(text, encoding="utf-8", newline="\n")
            print(f"updated {path.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
