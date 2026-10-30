"""Anchors (§9.1): long-lived system processes that storylines never merge through."""

from collections.abc import Mapping
from importlib.resources import files
from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import BaseModel, ConfigDict, StringConstraints, ValidationError, field_validator

from lineage_ir.detect.loader import load_yaml
from lineage_ir.detect.schema import fold
from lineage_ir.errors import UsageError
from lineage_ir.graph.model import ProcessGraph
from lineage_ir.models import ProcessNode

Verdict = Literal["verified", "name_only"]
ANCHORS_FILE = "anchors.yaml"


class Anchor(BaseModel):
    """An image name and the directories it is trusted in (``""`` means no path)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: Annotated[str, StringConstraints(min_length=1, pattern=r"^[^A-Z\\/]+$")]
    paths: tuple[str, ...]

    @field_validator("paths")
    @classmethod
    def _directories(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("paths must not be empty")
        for path in value:
            if path and (not path.endswith("\\") or path != path.casefold()):
                raise ValueError(f"{path!r}: use a lowercase directory ending with a backslash")
        return value


class _AnchorFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    anchors: tuple[Anchor, ...]


def _directory(image: str) -> str:
    """The image's normalized directory with a trailing backslash, or "" without one."""
    directory, sep, _ = fold("image", image).rpartition("\\")
    return f"{directory}\\" if sep else ""


class AnchorSet:
    """The anchor test, usable wherever detection expects ``AnchorTest``."""

    def __init__(self, anchors: tuple[Anchor, ...]) -> None:
        self.anchors = anchors
        self._paths: Mapping[str, tuple[str, ...]] = {a.name: a.paths for a in anchors}

    def verdict(self, node: ProcessNode) -> Verdict | None:
        """``verified`` when name and directory match; ``name_only`` for a ghost whose image
        is a bare name that matches; None otherwise."""
        paths = self._paths.get(node.image_name or "")
        if paths is None or not node.image:
            return None
        directory = _directory(node.image)
        if directory in paths:
            return "verified"
        if node.is_ghost and not directory:
            return "name_only"
        return None

    def __call__(self, node: ProcessNode) -> bool:
        return self.verdict(node) is not None


def load_anchors(path: Path | None = None) -> AnchorSet:
    """The bundled anchor table, or the one at ``path``; an invalid table exits 2."""
    source = path if path is not None else files("lineage_ir.analyze") / ANCHORS_FILE
    label = path.name if path is not None else ANCHORS_FILE
    try:
        data = _AnchorFile.model_validate(load_yaml(source.read_text(encoding="utf-8")))
    except (yaml.YAMLError, ValidationError) as exc:
        raise UsageError(f"{label}: invalid anchor table ({exc.__class__.__name__})") from None
    names = [a.name for a in data.anchors]
    if len(names) != len(set(names)):
        raise UsageError(f"{label}: an anchor name is listed twice")
    return AnchorSet(data.anchors)


def count_unverified(graphs: Mapping[str, ProcessGraph], anchors: AnchorSet) -> int:
    """Ghost nodes accepted as anchors by name alone (coverage ``anchor_unverified``)."""
    return sum(
        1
        for graph in graphs.values()
        for node in graph.nodes.values()
        if node.is_ghost and anchors.verdict(node) == "name_only"
    )
