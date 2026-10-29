"""Neutralizes attacker-controlled text before it reaches a human-readable output (§12.1)."""

from rich.markup import escape

_BIDI = frozenset(range(0x202A, 0x202F)) | frozenset(range(0x2066, 0x206A))
ELLIPSIS = "…"


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


def truncate(text: str, limit: int | None) -> str:
    """Cut text to ``limit`` characters, marking the cut with an ellipsis."""
    if limit is None or len(text) <= limit:
        return text
    return text[: max(limit - 1, 0)] + ELLIPSIS


def safe(text: str | None, limit: int | None = None) -> str:
    """Clean, truncate and markup-escape untrusted text for Rich output."""
    if text is None:
        return ""
    return escape(truncate(clean(text), limit))
