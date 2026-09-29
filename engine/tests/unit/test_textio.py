"""Tests for whalescan.textio (spec §5.3-§5.6)."""

from __future__ import annotations

import errno
import io
import os
import sys
import threading

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from whalescan import textio
from whalescan.model import FileCtx
from whalescan.textio import (
    BINARY_EXT,
    FileTooLargeError,
    NotRegularFileError,
    decode,
    detect_bom,
    end_pos,
    head_tail,
    line_starts,
    pos,
    read_file,
    read_stream,
    sniff,
)

# --------------------------------------------------------------------------- sniff


@pytest.mark.parametrize("name", ["a.png", "dir/x.PNG", "m.safetensors", "lib.so", "x.tar.gz", "w.woff2"])
def test_sniff_binary_extensions(name: str) -> None:
    assert sniff(b"plain text", name) == (True, None)


def test_binary_ext_matches_spec_list() -> None:
    assert {".pyc", ".pkl", ".onnx", ".p12", ".jks", ".sqlite", ".db", ".zst"} <= BINARY_EXT
    assert ".svg" not in BINARY_EXT and ".txt" not in BINARY_EXT


def test_sniff_dotfile_named_like_extension_is_not_binary() -> None:
    assert sniff(b"x=1\n", ".png") == (False, None)


@pytest.mark.parametrize(
    ("bom", "enc"),
    [
        (b"\x00\x00\xfe\xff", "utf-32-be"),
        (b"\xff\xfe\x00\x00", "utf-32-le"),
        (b"\xef\xbb\xbf", "utf-8"),
        (b"\xfe\xff", "utf-16-be"),
        (b"\xff\xfe", "utf-16-le"),
    ],
)
def test_sniff_bom_wins_over_nul(bom: bytes, enc: str) -> None:
    head = bom + "hello\n".encode(enc)
    assert sniff(head, "x.sql") == (False, enc)


def test_utf32le_bom_checked_before_utf16le() -> None:
    assert detect_bom(b"\xff\xfe\x00\x00abc") == (b"\xff\xfe\x00\x00", "utf-32-le")
    assert detect_bom(b"\xff\xfea\x00") == (b"\xff\xfe", "utf-16-le")
    assert detect_bom(b"abc") is None


def test_sniff_nul_is_binary() -> None:
    assert sniff(b"abc\x00def", "x.txt") == (True, None)


def test_sniff_nul_after_8k_is_ignored() -> None:
    assert sniff(b"a" * textio.SNIFF_BYTES + b"\x00", "x.txt") == (False, None)


def test_sniff_empty_is_text() -> None:
    assert sniff(b"", "empty") == (False, None)


def test_sniff_control_ratio_threshold() -> None:
    # exactly 30% control bytes is not binary; above is
    assert sniff(b"\x01" * 30 + b"a" * 70, "x") == (False, None)
    assert sniff(b"\x01" * 31 + b"a" * 69, "x") == (True, None)


def test_sniff_esc_tab_newline_not_counted() -> None:
    ansi = b"\x1b[31mred\x1b[0m\t\n\r\x0b\x0c" * 50
    assert sniff(ansi, "log.txt") == (False, None)
    assert sniff(b"\x7f" * 40 + b"a" * 60, "x") == (True, None)


# --------------------------------------------------------------------------- decode


def test_decode_utf8() -> None:
    d = decode("héllo\r\nwörld\n".encode(), "a.txt")
    assert (d.text, d.encoding, d.fallback, d.diagnostics) == ("héllo\r\nwörld\n", "utf-8", False, [])
    text, enc, fb, diags = d  # unpacks as the 4-tuple in the contract
    assert (enc, fb, len(diags)) == ("utf-8", False, 0)
    assert "\r\n" in text  # never newline-normalized


def test_decode_utf8_bom_stripped() -> None:
    d = decode(b"\xef\xbb\xbfkey: v\n", "a.yaml")
    assert d.text == "key: v\n"
    assert d.encoding == "utf-8-sig"
    assert not d.fallback and d.diagnostics == []


@pytest.mark.parametrize("enc", ["utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"])
def test_decode_utf16_32_with_bom(enc: str) -> None:
    bom = dict((e, b) for b, e in textio.BOMS)[enc]
    payload = "SELECT 1;\r\n-- ünïcode 🐳\n"
    d = decode(bom + payload.encode(enc), "q.sql")
    assert d.text == payload
    assert d.encoding == enc
    assert d.diagnostics == []


def test_decode_bom_with_invalid_body_replaces() -> None:
    d = decode(b"\xff\xfea\x00b", "odd.ps1")  # odd trailing byte
    assert d.text.startswith("a")
    assert "�" in d.text
    assert not d.fallback
    assert [x.code for x in d.diagnostics] == ["decode-replaced"]
    assert d.diagnostics[0].file == "odd.ps1"


def test_decode_legit_fffd_in_bom_file_is_not_flagged() -> None:
    d = decode(b"\xef\xbb\xbf" + "x�y".encode(), "a.txt")
    assert d.text == "x�y" and d.diagnostics == []


def test_decode_latin1_fallback() -> None:
    raw = b"caf\xe9 \xff\xfe? no-bom here"
    raw = b"x" + raw  # make sure it does not start with a BOM
    d = decode(raw, "legacy.txt")
    assert d.fallback is True
    assert d.encoding == "latin-1"
    assert d.text.encode("latin-1") == raw
    assert len(d.text) == len(raw)
    assert [x.code for x in d.diagnostics] == ["decode-fallback-latin1"]
    assert "offset 4" in d.diagnostics[0].message


def test_decode_encoded_surrogate_falls_back() -> None:
    d = decode(b"a\xed\xa0\x80b", "s.txt")
    assert d.fallback


@given(st.binary(max_size=512))
@settings(max_examples=300)
def test_decode_never_raises_and_latin1_is_lossless(data: bytes) -> None:
    d = decode(data, "fuzz")
    assert isinstance(d.text, str)
    if d.fallback:
        assert d.text.encode("latin-1") == data
    elif detect_bom(data) is None:
        assert d.text.encode("utf-8") == data


@given(st.text(max_size=300))
def test_decode_roundtrips_utf8_text(s: str) -> None:
    data = s.encode("utf-8", "surrogatepass")
    d = decode(data, "t")
    if detect_bom(data) is None and not any(0xD800 <= ord(c) <= 0xDFFF for c in s):
        assert d.text == s and not d.fallback


# --------------------------------------------------------------------------- read_file


def test_read_file_regular(tmp_path: object) -> None:
    p = os.path.join(str(tmp_path), "f.txt")
    with open(p, "wb") as fh:
        fh.write(b"abc" * 100)
    assert read_file(p, 1000) == b"abc" * 100
    assert read_file(p, 300) == b"abc" * 100  # exactly the cap is fine


def test_read_file_empty(tmp_path: object) -> None:
    p = os.path.join(str(tmp_path), "e")
    open(p, "wb").close()
    assert read_file(p, 10) == b""
    assert read_file(p, 0) == b""


def test_read_file_too_large(tmp_path: object) -> None:
    p = os.path.join(str(tmp_path), "big")
    with open(p, "wb") as fh:
        fh.write(b"x" * 101)
    with pytest.raises(FileTooLargeError) as ei:
        read_file(p, 100)
    assert ei.value.size == 101 and ei.value.limit == 100
    assert isinstance(ei.value, OSError)


def test_read_file_refuses_symlink(tmp_path: object) -> None:
    target = os.path.join(str(tmp_path), "t")
    with open(target, "wb") as fh:
        fh.write(b"secret")
    link = os.path.join(str(tmp_path), "l")
    os.symlink(target, link)
    with pytest.raises(OSError) as ei:
        read_file(link, 100)
    assert ei.value.errno == errno.ELOOP


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs mkfifo")
def test_read_file_fifo_does_not_hang(tmp_path: object) -> None:
    fifo = os.path.join(str(tmp_path), "pipe")
    os.mkfifo(fifo)
    result: list[BaseException] = []

    def run() -> None:
        try:
            read_file(fifo, 100)
        except BaseException as exc:
            result.append(exc)

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(5)
    assert not t.is_alive(), "reading a FIFO must not block"
    assert result and isinstance(result[0], NotRegularFileError)


def test_read_file_directory_rejected(tmp_path: object) -> None:
    with pytest.raises(OSError):
        read_file(str(tmp_path), 100)


@pytest.mark.skipif(not os.path.exists("/proc/self/status"), reason="needs procfs")
def test_read_file_procfs_zero_size_still_read() -> None:
    with pytest.raises(NotRegularFileError):
        read_file("/dev/null", 10)  # character device
    data = read_file("/proc/self/status", 1 << 20)
    assert b"Name:" in data


def test_read_file_negative_cap() -> None:
    with pytest.raises(ValueError):
        read_file("x", -1)


# --------------------------------------------------------------------------- streams


def test_read_stream_under_and_over_cap() -> None:
    assert read_stream(io.BytesIO(b"hello"), 10) == (b"hello", False)
    assert read_stream(io.BytesIO(b"hello"), 5) == (b"hello", False)
    assert read_stream(io.BytesIO(b"hello!"), 5) == (b"hello", True)
    assert read_stream(io.BytesIO(b""), 0) == (b"", False)


def test_head_tail_passthrough_and_truncation() -> None:
    assert head_tail(b"abc", 10) == (b"abc", False)
    out, trunc = head_tail(b"A" * 50 + b"B" * 50, 20)
    assert trunc and out == b"A" * 10 + b"B" * 10


def test_head_tail_utf8_boundaries() -> None:
    data = ("é" * 100).encode()  # 2 bytes each
    out, trunc = head_tail(data, 51)
    assert trunc
    out.decode("utf-8")  # strict: never split a character
    assert decode(out, "x").fallback is False


def test_head_tail_utf16_alignment() -> None:
    data = b"\xff\xfe" + ("x" * 101).encode("utf-16-le")
    out, trunc = head_tail(data, 51)
    assert trunc
    assert (len(out) - 2) % 2 == 0
    assert decode(out, "x").diagnostics == []


@given(st.text(min_size=1, max_size=400), st.integers(min_value=2, max_value=300))
@settings(max_examples=300)
def test_head_tail_never_breaks_utf8(s: str, cap: int) -> None:
    data = s.encode("utf-8", "surrogatepass")
    if any(0xD800 <= ord(c) <= 0xDFFF for c in s) or detect_bom(data):
        return
    out, trunc = head_tail(data, cap)
    assert trunc == (len(data) > cap)
    assert len(out) <= max(cap, len(data) if not trunc else cap)
    out.decode("utf-8")  # must stay valid UTF-8 so the unicode rules keep working


# --------------------------------------------------------------------------- positions


def test_line_starts_only_newline_breaks() -> None:
    text = "a\r\nb\rc\u2028d\u0085e\nf"
    assert line_starts(text) == [0, 3, 11]
    starts = line_starts(text)
    assert pos(starts, 0) == (1, 1)
    assert pos(starts, 3) == (2, 1)
    assert pos(starts, 5) == (2, 3)  # after a lone \r: same line
    assert pos(starts, 8) == (2, 6)  # U+2028 and U+0085 are not breaks either
    assert pos(starts, 11) == (3, 1)
    assert end_pos(starts, 4) == (2, 2)
    assert end_pos(starts, 0) == (1, 1)


def test_columns_count_code_points() -> None:
    text = "🐳🐳x"
    starts = line_starts(text)
    assert pos(starts, 2) == (1, 3)  # not UTF-16 units


@given(st.text(alphabet=st.sampled_from("ab\n\r\u2028é🐳"), max_size=200), st.data())
def test_positions_agree_with_filectx(text: str, data: st.DataObject) -> None:
    starts = line_starts(text)
    ctx = FileCtx(path="x", text=text)
    assert starts == ctx.line_starts
    off = data.draw(st.integers(min_value=0, max_value=len(text)))
    assert pos(starts, off) == ctx.pos(off)
    assert end_pos(starts, off) == ctx.end_pos(off)
    line, col = pos(starts, off)
    assert text[: starts[line - 1]].count("\n") == line - 1
    assert col == off - starts[line - 1] + 1


def test_module_imports_are_light() -> None:
    import subprocess

    # `ast` is loaded by dataclasses/inspect via the shared model; only check what textio controls
    code = (
        "import sys, whalescan.textio as t; "
        "print(sorted(m for m in ('json', 'subprocess', 'logging', 'tomllib') if m in sys.modules))"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "[]"
