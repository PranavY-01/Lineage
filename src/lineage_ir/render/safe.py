"""Neutralizes attacker-controlled text before it reaches a human-readable output (§12.1)."""

import re

from rich.markup import escape

_BIDI = frozenset(range(0x202A, 0x202F)) | frozenset(range(0x2066, 0x206A))
ELLIPSIS = "…"

# Scheme, separator and host of a URL. Bounded and single quantifiers over disjoint classes
# keep the match linear on any input; no word boundary is required, so text glued to the
# front of a scheme cannot hide a URL.
_URL = re.compile(r"([A-Za-z][A-Za-z0-9+.-]{0,15})://([^\s/?#'\"<>\\]*)")


def _replacement(code: int) -> str | None:
    if code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F:
        return f"\\x{code:02x}"
    if code in _BIDI:
        return f"\\u{{{code:04x}}}"
    return None


def clean(text: str) -> str:
    """Replace control characters and bidi overrides with visible escape notation."""
    out = []
    for char in text:
        replacement = _replacement(ord(char))
        out.append(char if replacement is None else replacement)
    return "".join(out)


def defang_host(name: str) -> str:
    """A host or DNS name with every dot shown as ``[.]``."""
    return name.replace(".", "[.]")


def _defang_url(match: re.Match[str]) -> str:
    scheme = match[1]
    folded = scheme.casefold()
    for name in ("https", "http"):
        if folded.endswith(name):
            at = len(scheme) - len(name)
            xx = "XX" if scheme[at + 1].isupper() else "xx"
            scheme = scheme[: at + 1] + xx + scheme[at + 3 :]
            break
    return f"{scheme}[://]{defang_host(match[2])}"


def defang(text: str) -> str:
    """Defang URLs for display: ``http`` → ``hxxp``, ``://`` → ``[://]``, host dots → ``[.]``."""
    return _URL.sub(_defang_url, text)


def truncate(text: str, limit: int | None) -> str:
    """Cut text to ``limit`` characters, marking the cut with an ellipsis."""
    if limit is None or len(text) <= limit:
        return text
    return text[: max(limit - 1, 0)] + ELLIPSIS


def safe(text: str | None, limit: int | None = None) -> str:
    """Clean, defang, truncate and markup-escape untrusted text for Rich output."""
    if text is None:
        return ""
    return escape(truncate(defang(clean(text)), limit))
