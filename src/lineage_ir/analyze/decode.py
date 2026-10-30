"""PowerShell encoded-command decoding (§8.5).

Decoding never executes, evaluates or writes anything, and failures are reported only as note
codes: the payload and the decoded text never reach an error message.
"""

import binascii
import re
from collections.abc import Iterator

# Every accepted form of -EncodedCommand: "ec" plus each prefix of "encodedcommand".
ENCODED_FLAG_TOKENS = ("ec", *("encodedcommand"[:n] for n in range(1, 15)))
_FLAGS = frozenset(ENCODED_FLAG_TOKENS)

MAX_ENCODED_BYTES = 128 * 1024
MAX_DECODED_BYTES = 64 * 1024
MIN_PAYLOAD_CHARS = 8
PRINTABLE_RATIO = 0.85

DECODE_NOTES = (
    "truncated_input",
    "invalid_base64",
    "not_text",
    "truncated_output",
    "nested_encoding",
)

_CANDIDATE_IMAGES = frozenset({"powershell.exe", "pwsh.exe"})
_BASE64 = re.compile(r"[A-Za-z0-9+/=]+")
_SPACES = re.compile(r"\s*")
_WORD = re.compile(r"\S*")
_QUOTES = "\"'"


def command_tokens(text: str) -> Iterator[tuple[str, bool]]:
    """Whitespace-separated tokens in one linear pass; a token opening with a quote runs to
    the matching quote (or the end) and is returned without the quotes."""
    i, n = 0, len(text)
    while True:
        i = _SPACES.match(text, i).end()  # type: ignore[union-attr]
        if i >= n:
            return
        if text[i] in _QUOTES:
            end = text.find(text[i], i + 1)
            end = n if end < 0 else end
            yield text[i + 1 : end], True
            i = end + 1
        else:
            end = _WORD.match(text, i).end()  # type: ignore[union-attr]
            yield text[i:end], False
            i = end


def _is_flag(token: str) -> bool:
    return len(token) > 1 and token[0] in "-/" and token[1:].casefold() in _FLAGS


def find_encoded_payload(text: str) -> str | None:
    """The payload after the first encoded-command flag, or None when there is none."""
    expecting = False
    for token, quoted in command_tokens(text):
        if expecting:
            payload = "".join(token.split()) if quoted else token
            if len(payload) >= MIN_PAYLOAD_CHARS and _BASE64.fullmatch(payload):
                return token
        expecting = not quoted and _is_flag(token)
    return None


def _is_candidate(command_line: str, image_name: str | None) -> bool:
    folded = command_line.casefold()
    return image_name in _CANDIDATE_IMAGES or "powershell" in folded or "pwsh" in folded


def _mostly_text(text: str) -> bool:
    if not text:
        return False
    readable = sum(1 for ch in text if ch.isprintable() or ch.isspace())
    return readable / len(text) >= PRINTABLE_RATIO


def decode_command(
    command_line: str | None, image_name: str | None
) -> tuple[str | None, str | None]:
    """Return (decoded_command, decode_note); (None, None) when no encoded command is present.

    Notes are comma-joined codes from DECODE_NOTES in that order.
    """
    if not command_line or not _is_candidate(command_line, image_name):
        return None, None
    found = find_encoded_payload(command_line)
    if found is None:
        return None, None

    notes: list[str] = []
    payload = "".join(found.split())
    if len(payload) > MAX_ENCODED_BYTES:
        payload = payload[:MAX_ENCODED_BYTES]
        notes.append("truncated_input")
    payload += "=" * (-len(payload) % 4)
    try:
        raw = binascii.a2b_base64(payload, strict_mode=True)
    except (binascii.Error, ValueError):
        notes.append("invalid_base64")
        return None, ",".join(notes)

    if len(raw) % 2:
        raw = raw[:-1]
    text = raw.decode("utf-16-le", errors="replace").replace("\x00", "")
    if not _mostly_text(text):
        notes.append("not_text")
        return None, ",".join(notes)

    encoded = text.encode("utf-8")
    if len(encoded) > MAX_DECODED_BYTES:
        text = encoded[:MAX_DECODED_BYTES].decode("utf-8", errors="ignore")
        notes.append("truncated_output")
    if find_encoded_payload(text) is not None:
        notes.append("nested_encoding")
    return text, ",".join(notes) or None
