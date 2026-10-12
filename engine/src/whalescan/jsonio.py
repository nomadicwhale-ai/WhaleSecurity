"""Bound untrusted JSON before calling the stdlib's recursive decoder.

A decoder can exhaust the native stack before raising RecursionError. This iterative lexical
preflight uses bounded memory and ignores delimiters inside strings, including escaped quotes.
Callers retain their existing JSON hooks and translate ValueError to their documented error.
"""

from __future__ import annotations

from typing import Final

MAX_JSON_DEPTH: Final = 64
_SIZE_CHUNK: Final = 4096


def preflight(text: str, *, max_bytes: int) -> None:
    """Reject JSON exceeding its UTF-8 byte cap or 64 open containers; raise ValueError.

    This is not a replacement parser: json.loads still checks the full JSON grammar. All
    scanning is iterative; the delimiter stack cannot grow beyond MAX_JSON_DEPTH.
    """
    if len(text) > max_bytes:
        raise ValueError(f"JSON larger than {max_bytes} bytes")
    if not text.isascii():
        size = 0
        for offset in range(0, len(text), _SIZE_CHUNK):
            size += len(text[offset : offset + _SIZE_CHUNK].encode("utf-8"))
            if size > max_bytes:
                raise ValueError(f"JSON larger than {max_bytes} bytes")
    stack: list[str] = []
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            if len(stack) == MAX_JSON_DEPTH:
                raise ValueError(f"JSON nested too deeply (maximum depth {MAX_JSON_DEPTH})")
            stack.append("]" if char == "[" else "}")
        elif char in "]}" and (not stack or stack.pop() != char):
            raise ValueError("JSON mismatched container delimiters")
