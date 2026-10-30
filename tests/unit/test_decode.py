"""PowerShell encoded-command decoding (§8.5): flag matrix, payload forms and every note."""

import base64

import pytest

from lineage_ir.analyze.decode import (
    DECODE_NOTES,
    ENCODED_FLAG_TOKENS,
    MAX_DECODED_BYTES,
    MAX_ENCODED_BYTES,
    decode_command,
    find_encoded_payload,
)

PS = "powershell.exe"


def enc(text: str) -> str:
    return base64.b64encode(text.encode("utf-16-le")).decode("ascii")


PAYLOAD = enc("Write-Output 'decoded text'")


def test_token_list_is_explicit() -> None:
    expected = {"ec", *("encodedcommand"[:n] for n in range(1, 15))}
    assert set(ENCODED_FLAG_TOKENS) == expected
    assert "ep" not in ENCODED_FLAG_TOKENS


@pytest.mark.parametrize("token", ENCODED_FLAG_TOKENS)
@pytest.mark.parametrize("prefix", ["-", "/"])
@pytest.mark.parametrize("case", [str.lower, str.upper])
def test_every_flag_prefix_matches(token: str, prefix: str, case: object) -> None:
    flag = prefix + case(token)  # type: ignore[operator]
    decoded, note = decode_command(f"powershell.exe -NoP {flag} {PAYLOAD}", PS)
    assert decoded == "Write-Output 'decoded text'"
    assert note is None


@pytest.mark.parametrize(
    "command",
    [
        "powershell.exe -ep bypass -File a.ps1",
        "powershell.exe -ExecutionPolicy Bypass AAAAAAAAAAAA",
        "powershell.exe -ex AAAAAAAAAAAA",
        "powershell.exe -encodedcommandx " + PAYLOAD,
        "powershell.exe x-enc " + PAYLOAD,
        "powershell.exe -enc short",
        "powershell.exe -enc",
    ],
)
def test_non_flags_never_match(command: str) -> None:
    assert decode_command(command, PS) == (None, None)


@pytest.mark.parametrize("quote", ['"', "'"])
def test_quoted_payloads(quote: str) -> None:
    decoded, note = decode_command(f"powershell -enc {quote}{PAYLOAD}{quote}", PS)
    assert (decoded, note) == ("Write-Output 'decoded text'", None)


def test_whitespace_inside_quoted_payload_is_removed() -> None:
    split = PAYLOAD[:12] + "  " + PAYLOAD[12:]
    decoded, _ = decode_command(f'powershell -enc "{split}"', PS)
    assert decoded == "Write-Output 'decoded text'"


def test_missing_padding_is_added() -> None:
    payload = enc("abcd")
    assert payload.endswith("=")
    assert decode_command("powershell -enc " + payload.rstrip("="), PS) == ("abcd", None)


def test_candidates_by_image_or_command_line() -> None:
    line = f"cmd.exe /c powershell -enc {PAYLOAD}"
    assert decode_command(line, "cmd.exe")[0] == "Write-Output 'decoded text'"
    assert decode_command(f"pwsh -e {PAYLOAD}", "pwsh.exe")[0] is not None
    assert decode_command(f"app.exe -e {PAYLOAD}", "app.exe") == (None, None)
    assert decode_command(None, PS) == (None, None)


def test_invalid_base64() -> None:
    assert decode_command("powershell -enc AAAA=AAAAAAA", PS) == (None, "invalid_base64")


def test_odd_byte_length_drops_last_byte() -> None:
    raw = "hi".encode("utf-16-le") + b"\x41"
    payload = base64.b64encode(raw).decode("ascii")
    assert decode_command("powershell -enc " + payload, PS) == ("hi", None)


def test_nul_characters_are_stripped() -> None:
    assert decode_command("powershell -enc " + enc("a\x00b\x00c"), PS) == ("abc", None)


def test_non_text_payload() -> None:
    payload = base64.b64encode(b"\x01\x00\x02\x00" * 40).decode("ascii")
    assert decode_command("powershell -enc " + payload, PS) == (None, "not_text")


def test_input_truncation() -> None:
    text = "A" * (MAX_ENCODED_BYTES // 2)
    decoded, note = decode_command("powershell -enc " + enc(text), PS)
    assert note is not None and "truncated_input" in note.split(",")
    assert decoded is not None and set(decoded) <= {"A"}


def test_output_truncation_counts_utf8_bytes() -> None:
    # 30,000 euro signs: 60,000 bytes as UTF-16 (under the input cap), 90,000 as UTF-8.
    decoded, note = decode_command("powershell -enc " + enc("€" * 30_000), PS)
    assert note == "truncated_output"
    assert decoded == "€" * (MAX_DECODED_BYTES // 3)


def test_nested_encoding_is_noted_and_not_decoded_again() -> None:
    inner = "powershell -enc " + enc("Get-Date")
    decoded, note = decode_command("powershell -enc " + enc(inner), PS)
    assert decoded == inner
    assert note == "nested_encoding"


def test_find_encoded_payload_reports_presence_without_decoding() -> None:
    assert find_encoded_payload(f"powershell -EncodedCommand {PAYLOAD}") == PAYLOAD
    assert find_encoded_payload("powershell -ep bypass") is None


def test_hostile_unterminated_quotes_stay_linear() -> None:
    line = "powershell " + '/e "AAAA/e ' * 50_000
    _, note = decode_command(line, PS)
    assert note is None or set(note.split(",")) <= set(DECODE_NOTES)


def test_failures_report_only_reason_codes() -> None:
    secret = "QUJDREVGR0hJSktM" + "=" + "TU5PUA"
    not_text = base64.b64encode(b"\x01\x00\x02\x00" * 40).decode("ascii")
    for line in (f"powershell -enc {secret}", f"powershell -enc {not_text}"):
        decoded, note = decode_command(line, PS)
        assert decoded is None
        assert note in DECODE_NOTES
        assert secret not in (note or "")
