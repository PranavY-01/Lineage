"""Atomic, path-safe output writes (§12.7); the only module that writes files.

Every requested path is checked before anything is written, so a refused path leaves no
partial output behind.
"""

import json
import os
import re
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from lineage_ir.errors import OutputError, UsageError

OutputKind = Literal["report", "artifacts"]

# Bytes read from the head of an existing file to recognise a Lineage output.
OWNERSHIP_PROBE_BYTES = 64 * 1024
_REPORT_HEAD = re.compile(r'\A\s*\{\s*"envelope"\s*:\s*')


@dataclass(frozen=True, slots=True)
class OutputRequest:
    """One file to write: where, what and which kind of Lineage output it is."""

    path: Path
    content: bytes
    kind: OutputKind


def _is_lineage_output(path: Path, kind: OutputKind) -> bool:
    """True when the file starts like a report or artifacts file that Lineage wrote."""
    try:
        with path.open("rb") as handle:
            head = handle.read(OWNERSHIP_PROBE_BYTES).decode("utf-8", errors="replace")
    except OSError:
        return False
    try:
        if kind == "report":
            match = _REPORT_HEAD.match(head)
            if match is None:
                return False
            envelope, _ = json.JSONDecoder().raw_decode(head, match.end())
            return isinstance(envelope, dict) and envelope.get("tool") == "lineage"
        first = json.loads(head.split("\n", 1)[0])
        return isinstance(first, dict) and first.get("schema") == "lineage-artifacts"
    except (ValueError, RecursionError):
        return False


def _same_file(a: Path, b: Path) -> bool:
    try:
        return os.path.samefile(a, b)
    except OSError:
        return False


def check_outputs(requests: Sequence[OutputRequest], inputs: Sequence[Path], force: bool) -> None:
    """Refuse unsafe or conflicting output paths with a UsageError (exit 2)."""
    claimed: list[Path] = []
    for request in requests:
        path = request.path
        if path.is_symlink():
            raise UsageError(f"{path}: output path is a symbolic link; choose another path")
        if path.is_dir():
            raise UsageError(f"{path}: output path is a directory")
        absolute = Path(os.path.abspath(path))
        for source in inputs:
            if absolute == Path(os.path.abspath(source)) or _same_file(path, source):
                raise UsageError(f"{path}: output path is one of the inputs")
        if any(absolute == other or _same_file(path, other) for other in claimed):
            raise UsageError(f"{path}: the same output path was requested twice")
        claimed.append(absolute)
        if not absolute.parent.is_dir():
            raise UsageError(f"{path}: the output directory does not exist; create it first")
        if path.exists():
            if not force:
                raise UsageError(f"{path}: file exists; pass --force to replace a Lineage output")
            if not _is_lineage_output(path, request.kind):
                raise UsageError(
                    f"{path}: file exists and is not a Lineage {request.kind}; it is never replaced"
                )


def _write_atomic(path: Path, content: bytes) -> None:
    directory = Path(os.path.abspath(path)).parent
    # mkstemp creates the file with mode 0600 on POSIX (§12.7 item 5).
    handle, temp_name = tempfile.mkstemp(prefix=".lineage-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    except BaseException:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def write_outputs(
    requests: Sequence[OutputRequest], inputs: Sequence[Path], force: bool
) -> list[Path]:
    """Check every path, then write each file atomically; returns the paths written."""
    check_outputs(requests, inputs, force)
    written = []
    for request in requests:
        try:
            _write_atomic(request.path, request.content)
        except OSError as exc:
            raise OutputError(f"{request.path}: could not write output ({exc.strerror})") from None
        written.append(request.path)
    return written
