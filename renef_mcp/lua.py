"""Small Lua helpers shared by the MCP tools and the TCP client.

Kept dependency-free: the values interpolated into Lua are host-controlled
module names, class names, and hook selectors, never raw user Lua.  The goal is
to make the generated Lua a valid string literal regardless of quotes,
backslashes, newlines, or non-ASCII bytes.
"""

from __future__ import annotations

import re


def quote(value: str) -> str:
    """Return a double-quoted Lua string literal for *value*."""
    out = ['"']
    for ch in str(value):
        code = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif code < 0x20 or code == 0x7F:
            out.append(f"\\{code:03d}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


_HEX_TOKEN = re.compile(r"^(?:[0-9a-fA-F]{2}|\?\?)$")


def normalize_hex_pattern(pattern: str, *, wildcards: bool) -> str:
    """Normalize a user hex pattern to space-separated byte tokens.

    Accepts compact (``7f454c46``), spaced (``7F 45 4C 46``), ``0x``-prefixed
    tokens, and (when *wildcards* is true) ``??`` tokens.  Raises ValueError on
    anything else instead of silently sending a corrupted pattern upstream.
    """
    raw = str(pattern).strip().lower()
    if not raw:
        raise ValueError("pattern must not be empty")

    # Drop a single leading 0x, and tolerate 0x on individual spaced tokens.
    if raw.startswith("0x"):
        raw = raw[2:]
    raw = re.sub(r"\b0x", "", raw)
    raw = raw.replace(",", " ").replace(":", " ")

    tokens: list[str] = []
    for chunk in raw.split():
        if len(chunk) <= 2:
            tokens.append(chunk)
            continue
        if len(chunk) % 2 != 0:
            raise ValueError(
                f"hex pattern chunk {chunk!r} has an odd number of digits "
                "(expected pairs such as 7f45 or 7f 45)"
            )
        tokens.extend(chunk[i : i + 2] for i in range(0, len(chunk), 2))

    if not tokens:
        raise ValueError("pattern must contain at least one byte")
    for token in tokens:
        if token == "??":
            if not wildcards:
                raise ValueError(
                    "?? wildcards are not supported by the upstream full-memory "
                    "scan; pass module=... to use the Lua Memory.search backend"
                )
            continue
        if not _HEX_TOKEN.fullmatch(token):
            raise ValueError(
                f"invalid hex byte {token!r}; use two hex digits per byte or ??"
            )
    return " ".join(tokens)
