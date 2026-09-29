"""Secret redaction and output sweep (spec §13).

A scanner report must never become the leak. Rules mark secret spans; every output string is
passed through :meth:`Redactor.finalize`, which sweeps any raw secret value seen during the run
and then reveals hidden code points. Raw values live only in memory and are never serialized.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable

from .matchers.unicode import reveal

# Values shorter than this are redacted where a rule reports them as a span, but are not swept
# from arbitrary text (sweeping "abc" would mangle unrelated output).
MIN_SWEEP_LEN = 6
_PEM_HEADER = re.compile(r"^-----BEGIN [A-Z0-9 ]{1,40}-----")


def _digest8(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8", "surrogatepass")).hexdigest()[:8]


def redact_value(secret: str) -> str:
    """Redacted form of one secret value.

    - ``L >= 16``: first ``min(4, L // 4)`` chars + ``…[sha256:<8 hex>]``
    - ``L < 16``: ``…[REDACTED len=L]`` (no hash, so short secrets cannot be dictionary-checked)
    - PEM blocks keep their ``-----BEGIN … -----`` header; the body becomes ``…[sha256:<8 hex>]``
    """
    n = len(secret)
    m = _PEM_HEADER.match(secret)
    if m:
        return f"{m.group(0)}\n…[sha256:{_digest8(secret)}]"
    if n >= 16:
        return f"{secret[: min(4, n // 4)]}…[sha256:{_digest8(secret)}]"
    return f"…[REDACTED len={n}]"


def redact_spans(text: str, spans: Iterable[tuple[int, int]]) -> str:
    """Replace each ``(start, end)`` span of ``text`` with its redacted form."""
    out = text
    for s, e in sorted(set(spans), reverse=True):
        if 0 <= s < e <= len(out):
            out = out[:s] + redact_value(out[s:e]) + out[e:]
    return out


class Redactor:
    """Collects raw secrets during a run and sanitizes every output string."""

    def __init__(self) -> None:
        self._secrets: set[str] = set()
        self._pattern: re.Pattern[str] | None = None

    def __len__(self) -> int:
        return len(self._secrets)

    def add(self, secret: str) -> None:
        if len(secret) >= MIN_SWEEP_LEN and secret not in self._secrets:
            self._secrets.add(secret)
            self._pattern = None
            # A PEM body is often echoed line by line; sweep the individual long lines too.
            if _PEM_HEADER.match(secret):
                for raw in secret.splitlines():
                    line = raw.strip()
                    if len(line) >= 16 and not line.startswith("-----"):
                        self._secrets.add(line)

    def add_span(self, text: str, span: tuple[int, int]) -> None:
        self.add(text[span[0] : span[1]])

    def redact_text(self, text: str, spans: Iterable[tuple[int, int]]) -> str:
        """Register the spans' raw values, then return ``text`` with them redacted."""
        spans = list(spans)
        for s, e in spans:
            if 0 <= s < e <= len(text):
                self.add(text[s:e])
        return redact_spans(text, spans)

    def sweep(self, text: str) -> str:
        """Replace every known raw secret occurring anywhere in ``text``."""
        if not self._secrets or not text:
            return text
        if self._pattern is None:
            ordered = sorted(self._secrets, key=len, reverse=True)
            self._pattern = re.compile("|".join(re.escape(s) for s in ordered))
        return self._pattern.sub(lambda m: redact_value(m.group(0)), text)

    def finalize(self, text: str) -> str:
        """Sweep known secrets, then reveal hidden code points (second line of defense)."""
        return reveal(self.sweep(text))


def sweep_free(text: str) -> str:
    """Reveal-only pass for strings that can carry no secret (titles, rule ids)."""
    return reveal(text)
