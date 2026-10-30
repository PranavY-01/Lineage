"""Artifacts JSONL for IOC extraction by Lucent (§12.4).

Values are raw (never defanged) so the extractor sees the original text. Lines come from
storyline nodes only, in storyline rank order, then node order, then activity time order;
identical (storyline, kind, value) lines are written once.
"""

import ipaddress
import json
from collections.abc import Iterator
from typing import Any

from lineage_ir import __version__
from lineage_ir.engine import AnalysisResult
from lineage_ir.models import Activity, ProcessNode

SCHEMA = "lineage-artifacts"
SCHEMA_VERSION = "1.0"


def _destination(fields: dict[str, str]) -> str | None:
    ip = fields.get("destination_ip")
    port = fields.get("destination_port")
    if not ip or not port:
        return None
    try:
        if ipaddress.ip_address(ip).version == 6:
            return f"[{ip}]:{port}"
    except ValueError:
        pass
    return f"{ip}:{port}"


def _activity_values(activity: Activity) -> Iterator[tuple[str, str]]:
    fields = activity.fields
    if activity.role != "actor":
        return
    if activity.kind == "network":
        destination = _destination(fields)
        if destination:
            yield "destination", destination
        if fields.get("destination_hostname"):
            yield "destination_hostname", fields["destination_hostname"]
    elif activity.kind == "dns" and fields.get("query_name"):
        yield "dns_query", fields["query_name"]
    elif activity.kind == "file_create" and fields.get("target_filename"):
        yield "file", fields["target_filename"]
    elif activity.event_id == 13 and fields.get("target_object"):
        yield "registry_value", f"{fields['target_object']}={fields.get('details', '')}"


def _node_lines(node: ProcessNode) -> Iterator[tuple[str, str, int | None]]:
    create_id = node.create_record.record_id if node.create_record is not None else None
    if node.command_line:
        yield "command_line", node.command_line, create_id
    if node.decoded_command:
        yield "decoded_command", node.decoded_command, create_id
    for _, value in sorted(node.hashes.items()):
        yield "image_hash", value, create_id
    for activity in node.activity:
        for kind, value in _activity_values(activity):
            yield kind, value, activity.source.record_id


def artifact_records(result: AnalysisResult) -> list[dict[str, Any]]:
    """The header record followed by one record per distinct artifact."""
    records: list[dict[str, Any]] = [
        {
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "tool_version": __version__,
            "run_id": result.run_id,
            "source_sha256": [i.sha256 for i in result.inputs],
        }
    ]
    seen: set[tuple[str, str, str]] = set()
    for story in result.storylines:
        graph = result.graphs.get(story.host)
        if graph is None:
            continue
        for guid in story.nodes:
            node = graph.nodes.get(guid)
            if node is None:
                continue
            for kind, value, record_id in _node_lines(node):
                key = (story.storyline_id, kind, value)
                if key in seen:
                    continue
                seen.add(key)
                records.append(
                    {
                        "storyline": story.storyline_id,
                        "host": story.host,
                        "process_guid": guid,
                        "image": node.image,
                        "record_id": record_id,
                        "kind": kind,
                        "value": value,
                    }
                )
    return records


def artifacts_text(result: AnalysisResult) -> str:
    """The artifacts file: compact JSON, one object per line, LF endings.

    ASCII escapes keep the file valid UTF-8 even when evidence holds lone surrogates.
    """
    return "".join(
        json.dumps(r, ensure_ascii=True, separators=(",", ":")) + "\n"
        for r in artifact_records(result)
    )
