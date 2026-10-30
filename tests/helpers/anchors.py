"""Stand-in anchor test for P3; P4 replaces it with analyze/anchors.yaml.

Follows the §9.1 rule: the image name AND its directory must both match. A same-named binary
in another directory is not an anchor. A ghost whose image is a bare name matches by name.
"""

from lineage_ir.ingest.normalize import normalize_path
from lineage_ir.models import ProcessNode

STUB_ANCHORS: dict[str, tuple[str, ...]] = {
    "explorer.exe": ("c:\\windows\\",),
    "services.exe": ("c:\\windows\\system32\\",),
    "svchost.exe": ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\"),
}


def stub_is_anchor(node: ProcessNode) -> bool:
    directories = STUB_ANCHORS.get(node.image_name or "")
    if directories is None:
        return False
    path = normalize_path(node.image or "")
    directory, sep, _ = path.rpartition("\\")
    if not sep:
        return node.is_ghost
    return directory + "\\" in directories
