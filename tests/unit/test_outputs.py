"""Atomic, path-safe output writes (§12.7)."""

import json
import os
import stat
import sys
from pathlib import Path

import pytest

from lineage_ir import outputs
from lineage_ir.errors import OutputError, UsageError
from lineage_ir.outputs import OutputRequest, check_outputs, write_outputs

REPORT = (json.dumps({"envelope": {"schema": "7d7b-report", "tool": "lineage"}}) + "\n").encode()
ARTIFACTS = b'{"schema":"lineage-artifacts","schema_version":"1.0"}\n'


@pytest.fixture
def evidence(tmp_path: Path) -> Path:
    path = tmp_path / "case.jsonl"
    path.write_bytes(b"{}\n")
    return path


def _report(path: Path, content: bytes = REPORT) -> OutputRequest:
    return OutputRequest(path, content, "report")


def test_writes_atomically_and_leaves_no_temp_files(tmp_path: Path, evidence: Path) -> None:
    target = tmp_path / "out" / "report.json"
    target.parent.mkdir()
    assert write_outputs([_report(target)], [evidence], force=False) == [target]
    assert target.read_bytes() == REPORT
    assert sorted(p.name for p in target.parent.iterdir()) == ["report.json"]


def test_refuses_an_input_path(evidence: Path) -> None:
    with pytest.raises(UsageError, match="one of the inputs"):
        check_outputs([_report(evidence)], [evidence], force=True)
    assert evidence.read_bytes() == b"{}\n"


def test_refuses_a_hard_link_to_an_input(tmp_path: Path, evidence: Path) -> None:
    link = tmp_path / "alias.json"
    try:
        os.link(evidence, link)
    except OSError:
        pytest.skip("hard links are not supported here")
    with pytest.raises(UsageError, match="one of the inputs"):
        check_outputs([_report(link)], [evidence], force=True)


def test_refuses_a_symlink(tmp_path: Path, evidence: Path) -> None:
    target = tmp_path / "real.json"
    target.write_bytes(REPORT)
    link = tmp_path / "link.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links need Developer Mode on Windows")
    with pytest.raises(UsageError, match="symbolic link"):
        check_outputs([_report(link)], [evidence], force=True)


def test_refuses_a_symlink_twin(
    tmp_path: Path, evidence: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "looks-like-a-link.json"
    monkeypatch.setattr(Path, "is_symlink", lambda self: self == path)
    with pytest.raises(UsageError, match="symbolic link"):
        check_outputs([_report(path)], [evidence], force=True)


def test_refuses_a_directory(tmp_path: Path, evidence: Path) -> None:
    with pytest.raises(UsageError, match="is a directory"):
        check_outputs([_report(tmp_path)], [evidence], force=True)


def test_missing_parent_directory(tmp_path: Path, evidence: Path) -> None:
    with pytest.raises(UsageError, match="does not exist; create it first"):
        check_outputs([_report(tmp_path / "nope" / "r.json")], [evidence], force=False)


def test_same_path_twice(tmp_path: Path, evidence: Path) -> None:
    target = tmp_path / "r.json"
    with pytest.raises(UsageError, match="requested twice"):
        check_outputs(
            [_report(target), OutputRequest(target, ARTIFACTS, "artifacts")], [evidence], False
        )


def test_existing_file_needs_force(tmp_path: Path, evidence: Path) -> None:
    target = tmp_path / "r.json"
    target.write_bytes(REPORT)
    with pytest.raises(UsageError, match="pass --force"):
        check_outputs([_report(target)], [evidence], force=False)
    write_outputs([_report(target, REPORT + b" ")], [evidence], force=True)
    assert target.read_bytes() == REPORT + b" "


def test_force_never_replaces_a_foreign_file(tmp_path: Path, evidence: Path) -> None:
    for name, content, kind in (
        ("notes.json", b'{"envelope": {"tool": "authwatch"}}', "report"),
        ("other.json", b'{"tool": "lineage"}', "report"),
        ("plain.txt", b"hello", "report"),
        ("iocs.jsonl", b'{"schema":"something-else"}\n', "artifacts"),
        ("report-as-artifacts.jsonl", REPORT, "artifacts"),
    ):
        target = tmp_path / name
        target.write_bytes(content)
        with pytest.raises(UsageError, match="never replaced"):
            check_outputs([OutputRequest(target, b"x", kind)], [evidence], force=True)  # type: ignore[arg-type]
        assert target.read_bytes() == content


def test_force_replaces_lineage_artifacts(tmp_path: Path, evidence: Path) -> None:
    target = tmp_path / "iocs.jsonl"
    target.write_bytes(ARTIFACTS + b'{"kind":"file"}\n')
    write_outputs([OutputRequest(target, ARTIFACTS, "artifacts")], [evidence], force=True)
    assert target.read_bytes() == ARTIFACTS


def test_a_refused_path_writes_nothing(tmp_path: Path, evidence: Path) -> None:
    good = tmp_path / "good.json"
    with pytest.raises(UsageError):
        write_outputs([_report(good), _report(evidence)], [evidence], force=False)
    assert not good.exists()


def test_write_failure_is_exit_4_and_cleans_up(
    tmp_path: Path, evidence: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*_args: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(outputs.os, "replace", fail)
    target = tmp_path / "r.json"
    with pytest.raises(OutputError) as caught:
        write_outputs([_report(target)], [evidence], force=False)
    assert caught.value.exit_code == 4
    assert list(tmp_path.iterdir()) == [evidence]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_reports_are_private_on_posix(tmp_path: Path, evidence: Path) -> None:
    target = tmp_path / "r.json"
    write_outputs([_report(target)], [evidence], force=False)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_temp_files_are_created_private(
    tmp_path: Path, evidence: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Windows twin of the POSIX check: the temporary file comes from mkstemp, which
    # creates it with mode 0600, and that file is what os.replace moves into place.
    seen: list[str] = []
    real = outputs.tempfile.mkstemp

    def spy(*args: object, **kwargs: object) -> tuple[int, str]:
        handle, name = real(*args, **kwargs)  # type: ignore[call-overload]
        seen.append(name)
        return handle, name

    monkeypatch.setattr(outputs.tempfile, "mkstemp", spy)
    target = tmp_path / "r.json"
    write_outputs([_report(target)], [evidence], force=False)
    assert len(seen) == 1 and Path(seen[0]).parent == tmp_path
    assert not Path(seen[0]).exists()
