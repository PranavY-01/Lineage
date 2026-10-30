"""A small builder for synthetic Sysmon logs used by the analysis tests."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

HOST = "ws-14.corp.example"
CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SYS32 = "C:\\Windows\\System32\\"
EXPLORER = "C:\\Windows\\explorer.exe"
BASE = datetime(2026, 10, 12, 10, 0, 0, tzinfo=UTC)


def guid(tag: int) -> str:
    return f"7a6b5c4d-3e2f-4a1b-9c8d-{tag:012x}"


def at(second: float) -> str:
    """RFC 3339 text for BASE plus ``second`` seconds."""
    return (BASE + timedelta(seconds=second)).strftime("%Y-%m-%dT%H:%M:%SZ")


class Chain:
    """Rows in the order added; record IDs follow that order."""

    def __init__(self, host: str = HOST) -> None:
        self.host = host
        self.rows: list[dict[str, Any]] = []

    def _base(self, event_id: int, second: float, host: str | None = None) -> dict[str, Any]:
        ts = BASE + timedelta(seconds=second)
        return {
            "EventID": event_id,
            "Hostname": host or self.host,
            "Channel": CHANNEL,
            "RecordNumber": len(self.rows) + 1,
            "UtcTime": ts.strftime("%Y-%m-%d %H:%M:%S.") + f"{ts.microsecond // 1000:03d}",
        }

    def create(
        self,
        tag: int,
        image: str,
        parent: int | None = None,
        second: float = 0,
        command: str | None = None,
        parent_image: str | None = None,
        user: str = "CORP\\jdoe",
        **extra: Any,
    ) -> "Chain":
        row = self._base(1, second, extra.pop("host", None))
        row.update(
            ProcessGuid="{" + guid(tag) + "}",
            ProcessId=str(extra.pop("pid", 1000 + tag)),
            Image=image,
            CommandLine=command if command is not None else image.rsplit("\\", 1)[-1],
            User=user,
        )
        if parent is not None:
            row["ParentProcessGuid"] = "{" + guid(parent) + "}"
            if parent_image:
                row["ParentImage"] = parent_image
        row.update(extra)
        self.rows.append(row)
        return self

    def event(self, event_id: int, tag: int | None, second: float, **fields: Any) -> "Chain":
        row = self._base(event_id, second, fields.pop("host", None))
        if tag is not None:
            row["ProcessGuid"] = "{" + guid(tag) + "}"
        row.update(fields)
        self.rows.append(row)
        return self

    def connect(self, tag: int, second: float, ip: str, port: int = 443, **fields: Any) -> "Chain":
        defaults = {
            "Image": SYS32 + "rundll32.exe",
            "Protocol": "tcp",
            "Initiated": "true",
            "DestinationIp": ip,
            "DestinationPort": str(port),
        }
        return self.event(3, tag, second, **{**defaults, **fields})

    def write(self, path: Path) -> Path:
        text = "".join(json.dumps(r) + "\n" for r in self.rows)
        path.write_text(text, encoding="utf-8", newline="\n")
        return path
