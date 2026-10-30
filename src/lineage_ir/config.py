"""Defaults, caps and constants shared across stages."""

from types import MappingProxyType

MIB = 1024 * 1024

MAX_INPUTS = 64
DEFAULT_MAX_FILE_SIZE_MB = 2048
MAX_FILE_SIZE_MB_RANGE = (1, 65_536)
# Largest step whose projected peak for a realistic mix stays at or under 6 GB (BUILD_NOTES).
DEFAULT_MAX_RECORDS = 2_000_000
MAX_RECORDS_RANGE = (1, 50_000_000)
DEFAULT_MAX_ERRORS = 50

# Distinct values each per-run string pool keeps; later values are stored as they are.
STRING_POOL_CAP = 100_000

JSON_LINE_CAP_BYTES = 1 * MIB
JSON_MAX_DEPTH = 32
HASH_CHUNK_BYTES = 1 * MIB

EVTX_MAGIC = b"ElfFile\x00"

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"

MIN_PLAUSIBLE_YEAR = 1990
MAX_PLAUSIBLE_YEAR = 2100

STANDARD_EVENT_IDS = (1, 3, 5, 7, 8, 10, 11, 12, 13, 22, 23)

SYSMON_EVENT_NAMES = MappingProxyType(
    {
        1: "Process create",
        2: "File creation time changed",
        3: "Network connection",
        4: "Sysmon service state changed",
        5: "Process terminated",
        6: "Driver loaded",
        7: "Image loaded",
        8: "CreateRemoteThread",
        9: "RawAccessRead",
        10: "Process access",
        11: "File create",
        12: "Registry object added or deleted",
        13: "Registry value set",
        14: "Registry object renamed",
        15: "File stream created",
        16: "Sysmon config state changed",
        17: "Pipe created",
        18: "Pipe connected",
        19: "WMI event filter",
        20: "WMI event consumer",
        21: "WMI consumer binding",
        22: "DNS query",
        23: "File delete archived",
        24: "Clipboard change",
        25: "Process tampering",
        26: "File delete detected",
        27: "File block executable",
        28: "File block shredding",
        29: "File executable detected",
        255: "Sysmon error",
    }
)

# Event IDs each rule family needs before `validate` reports it ready (§11.2).
# "all" families need every listed ID; "any" families need at least one.
READINESS_FAMILIES: tuple[tuple[str, tuple[int, ...], str], ...] = (
    ("lineage", (1,), "all"),
    ("network", (3,), "all"),
    ("persistence", (1, 11, 13), "all"),
    ("injection", (8,), "all"),
    ("credential access", (10, 1), "any"),
)

UNKNOWN_KEYS_SHOWN = 20
