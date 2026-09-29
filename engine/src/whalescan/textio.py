"""Byte-level text I/O: bounded reads, binary sniffing, BOM/encoding handling and positions.

Spec §5.3 (bounded reads, regular files only), §5.4 (binary detection), §5.5 (encoding and BOM),
§5.6 (positions). This module is on the hook path: it imports nothing heavier than ``os`` and
``stat`` at module level and never logs.

Positions follow the engine-wide convention: only ``"\\n"`` is a line break (a lone ``"\\r"``,
U+2028 and U+0085 are ordinary characters), lines and columns are 1-based, and columns count
Unicode code points.
"""

from __future__ import annotations

import errno
import os
import stat
from bisect import bisect_right
from collections.abc import Sequence
from typing import BinaryIO, NamedTuple

from .model import Diagnostic

__all__ = [
    "BINARY_EXT",
    "BOMS",
    "SNIFF_BYTES",
    "Decoded",
    "FileTooLargeError",
    "NotRegularFileError",
    "decode",
    "detect_bom",
    "end_pos",
    "head_tail",
    "line_starts",
    "pos",
    "read_file",
    "read_stream",
    "sniff",
]

#: Bytes examined by :func:`sniff` (spec §5.4: "head = first 8 KiB").
SNIFF_BYTES = 8192

BINARY_EXT: frozenset[str] = frozenset(
    {
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tgz", ".bz2",
        ".xz", ".zst", ".7z", ".jar", ".war", ".class", ".whl", ".so", ".dylib", ".dll", ".exe",
        ".o", ".a", ".pyc", ".parquet", ".orc", ".avro", ".npy", ".npz", ".pkl", ".onnx",
        ".safetensors", ".pt", ".db", ".sqlite", ".p12", ".pfx", ".jks", ".woff", ".woff2",
    }
)  # fmt: skip

#: BOMs in the order they MUST be tested (UTF-32 LE before UTF-16 LE; spec §5.5).
BOMS: tuple[tuple[bytes, str], ...] = (
    (b"\x00\x00\xfe\xff", "utf-32-be"),
    (b"\xff\xfe\x00\x00", "utf-32-le"),
    (b"\xef\xbb\xbf", "utf-8"),
    (b"\xfe\xff", "utf-16-be"),
    (b"\xff\xfe", "utf-16-le"),
)

# Control bytes counted by the binary heuristic: < 0x09, 0x0E-0x1F except ESC, and DEL.
_CTRL = bytes(b for b in range(256) if b < 0x09 or (0x0E <= b < 0x20 and b != 0x1B) or b == 0x7F)

_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)  # opening a FIFO must never block (fstat rejects it next)
    | getattr(os, "O_NOCTTY", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_BINARY", 0)
)
_HAS_NOFOLLOW = hasattr(os, "O_NOFOLLOW")
_READ_CHUNK = 1 << 20


class NotRegularFileError(OSError):
    """The path is not a regular file (FIFO, socket, device, directory)."""


class FileTooLargeError(OSError):
    """The file exceeds the byte cap. ``size`` is the observed size."""

    def __init__(self, path: str, size: int, limit: int) -> None:
        super().__init__(errno.EFBIG, f"file too large ({size} > {limit} bytes)", path)
        self.size = size
        self.limit = limit


class Decoded(NamedTuple):
    """Result of :func:`decode`. Unpacks as ``(text, encoding, fallback, diagnostics)``."""

    text: str
    encoding: str  # codec label: utf-8, utf-8-sig (BOM), utf-16-le, ..., latin-1
    fallback: bool  # latin-1 fallback: the unicode matcher must be disabled
    diagnostics: list[Diagnostic]


# --------------------------------------------------------------------------- sniffing


def _suffix(name: str) -> str:
    if os.sep != "/":  # pragma: no cover - Windows (on POSIX "\\" is an ordinary name character)
        name = name.replace(os.sep, "/")
    base = name.rsplit("/", 1)[-1]
    dot = base.rfind(".")
    if dot <= 0:  # no dot, or a dotfile such as ".png" (no extension)
        return ""
    return base[dot:].lower()


def detect_bom(data: bytes) -> tuple[bytes, str] | None:
    """Return ``(bom_bytes, codec)`` for the first BOM that ``data`` starts with."""
    for bom, enc in BOMS:
        if data.startswith(bom):
            return bom, enc
    return None


def sniff(head: bytes, name: str) -> tuple[bool, str | None]:
    """Return ``(is_binary, bom_encoding)`` for the first bytes of a file (spec §5.4).

    ``head`` may be longer than :data:`SNIFF_BYTES`; only the first 8 KiB are inspected.
    """
    if _suffix(name) in BINARY_EXT:
        return True, None
    bom = detect_bom(head)
    if bom is not None:
        return False, bom[1]  # UTF-16/32 text contains NULs, so the BOM check comes first
    head = head[:SNIFF_BYTES]
    if not head:
        return False, None
    if b"\x00" in head:
        return True, None
    ctrl = len(head) - len(head.translate(None, _CTRL))
    return ctrl * 10 > len(head) * 3, None  # ctrl / len > 0.30 without floats


# --------------------------------------------------------------------------- decoding


def decode(data: bytes, name: str = "<stdin>") -> Decoded:
    """Decode file bytes per spec §5.5. Never raises for any input.

    1. A BOM selects the codec; the BOM is stripped and invalid sequences become U+FFFD with a
       ``decode-replaced`` diagnostic.
    2. Otherwise strict UTF-8.
    3. Otherwise latin-1 (lossless, one char per byte) with ``fallback=True`` and a
       ``decode-fallback-latin1`` diagnostic.

    The text is never newline-normalized.
    """
    bom = detect_bom(data)
    if bom is not None:
        bom_bytes, codec = bom
        body = data[len(bom_bytes) :]
        label = "utf-8-sig" if codec == "utf-8" else codec
        try:
            return Decoded(body.decode(codec), label, False, [])
        except UnicodeDecodeError as exc:
            text = body.decode(codec, errors="replace")
            diag = Diagnostic(
                "warning",
                "decode-replaced",
                f"invalid {codec} data at byte {exc.start + len(bom_bytes)}; "
                "undecodable sequences were replaced with U+FFFD",
                file=name,
            )
            return Decoded(text, label, False, [diag])
    try:
        return Decoded(data.decode("utf-8"), "utf-8", False, [])
    except UnicodeDecodeError as exc:
        diag = Diagnostic(
            "warning",
            "decode-fallback-latin1",
            f"not valid UTF-8 (first invalid byte at offset {exc.start}); decoded as latin-1 and "
            "code-point (unicode) rules are disabled for this file",
            file=name,
        )
        return Decoded(data.decode("latin-1"), "latin-1", True, [diag])


# --------------------------------------------------------------------------- bounded reads


def read_file(path: str | os.PathLike[str], max_bytes: int) -> bytes:
    """Read a regular file, refusing symlinks, special files and files above ``max_bytes``.

    The final path component is opened with ``O_NOFOLLOW`` (a symlink raises ``OSError`` with
    ``errno.ELOOP``) and ``O_NONBLOCK`` (a FIFO cannot hang the caller); ``fstat`` then rejects
    anything that is not ``S_ISREG`` with :class:`NotRegularFileError`. At most
    ``max_bytes + 1`` bytes are read; a larger file raises :class:`FileTooLargeError`.
    """
    if max_bytes < 0:
        raise ValueError("max_bytes must be >= 0")
    spath = os.fspath(path)
    if not _HAS_NOFOLLOW and stat.S_ISLNK(os.lstat(spath).st_mode):  # pragma: no cover - Windows
        raise OSError(errno.ELOOP, "refusing to follow symlink", spath)
    fd = os.open(spath, _OPEN_FLAGS)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise NotRegularFileError(errno.EINVAL, "not a regular file", spath)
        if st.st_size > max_bytes:
            raise FileTooLargeError(spath, st.st_size, max_bytes)
        cap = max_bytes + 1
        # One read() of st_size + 1 bytes in the common case: a short read means EOF for a
        # regular file. Files that under-report st_size (procfs) keep reading, bounded by `cap`.
        want = min(cap, st.st_size + 1)
        chunks: list[bytes] = []
        got = 0
        while got < cap:
            chunk = os.read(fd, want)
            if not chunk:
                break
            chunks.append(chunk)
            got += len(chunk)
            if len(chunk) < want:
                break
            want = min(_READ_CHUNK, cap - got)
        data = chunks[0] if len(chunks) == 1 else b"".join(chunks)
        if len(data) > max_bytes:
            raise FileTooLargeError(spath, len(data), max_bytes)
        return data
    finally:
        os.close(fd)


def read_stream(stream: BinaryIO, max_bytes: int) -> tuple[bytes, bool]:
    """Read at most ``max_bytes`` from a binary stream. Returns ``(data, truncated)``.

    One extra byte is read to detect truncation; the rest of the stream is left unread.
    """
    if max_bytes < 0:
        raise ValueError("max_bytes must be >= 0")
    cap = max_bytes + 1
    chunks: list[bytes] = []
    got = 0
    while got < cap:
        chunk = stream.read(min(_READ_CHUNK, cap - got))
        if not chunk:
            break
        chunks.append(chunk)
        got += len(chunk)
    data = b"".join(chunks)
    if len(data) > max_bytes:
        return data[:max_bytes], True
    return data, False


def _unit_for(data: bytes) -> tuple[int, int]:
    """(bom_length, code_unit_size) of ``data``; unit 1 means UTF-8 or unknown."""
    bom = detect_bom(data)
    if bom is None:
        return 0, 1
    size = {"utf-32-be": 4, "utf-32-le": 4, "utf-16-be": 2, "utf-16-le": 2}.get(bom[1], 1)
    return len(bom[0]), size


def head_tail(data: bytes, max_bytes: int) -> tuple[bytes, bool]:
    """Keep the first and last ``max_bytes // 2`` bytes of oversized input (``inject``, §2.2).

    Cut points are moved to character boundaries (UTF-8 lead bytes, or whole UTF-16/32 code
    units after a BOM) so that truncation can never push the document into the latin-1
    fallback, which would silence the code-point rules. Returns ``(data, truncated)``.
    """
    if len(data) <= max_bytes:
        return data, False
    half = max_bytes // 2
    bom_len, unit = _unit_for(data)
    head_end = max(bom_len, half)
    tail_start = max(head_end, len(data) - half)
    if unit > 1:
        head_end -= (head_end - bom_len) % unit
        tail_start += (-(tail_start - bom_len)) % unit
    else:
        # Back the head cut off to a lead byte and push the tail cut forward past continuations.
        for _ in range(3):
            if head_end > 0 and 0x80 <= data[head_end] < 0xC0:
                head_end -= 1
        for _ in range(3):
            if tail_start < len(data) and 0x80 <= data[tail_start] < 0xC0:
                tail_start += 1
    return data[:head_end] + data[tail_start:], True


# --------------------------------------------------------------------------- positions


def line_starts(text: str) -> list[int]:
    """Offsets at which each line starts. Only ``"\\n"`` breaks lines (spec §5.5-§5.6)."""
    starts = [0]
    find = text.find
    i = find("\n")
    while i != -1:
        starts.append(i + 1)
        i = find("\n", i + 1)
    return starts


def pos(starts: Sequence[int], off: int) -> tuple[int, int]:
    """1-based ``(line, col)`` of code-point offset ``off``; col counts code points."""
    i = bisect_right(starts, off) - 1
    if i < 0:
        return 1, 1
    return i + 1, off - starts[i] + 1


def end_pos(starts: Sequence[int], end: int) -> tuple[int, int]:
    """Position just after the last char of a span with exclusive ``end``."""
    if end <= 0:
        return 1, 1
    line, col = pos(starts, end - 1)
    return line, col + 1
