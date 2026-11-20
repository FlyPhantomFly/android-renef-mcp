"""Vendored Lua script library for renef-mcp.

Scripts come from ahmeth4n/renef-mcp (MIT) and are small, self-contained Renef
Lua examples: hook demos, hexdump, syscall tracing, and ready-made bypasses
(flutter_ssl, ssl_unpin, root_bypass).  They are exposed to agents through the
renef_list_scripts / renef_get_script tools, mirroring the frida script library
pattern in android-re-mcp.
"""

from __future__ import annotations

from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent / "scripts"


def list_scripts() -> list[str]:
    """Names (without .lua) of all bundled scripts, sorted."""
    return sorted(p.stem for p in _SCRIPT_DIR.glob("*.lua"))


def get_script_content(name: str) -> str:
    """Return the Lua source of a bundled script. Raises FileNotFoundError."""
    safe = Path(name).stem  # reject paths/subdirs
    path = _SCRIPT_DIR / f"{safe}.lua"
    if not path.is_file():
        raise FileNotFoundError(f"no bundled script named {name!r}")
    return path.read_text(encoding="utf-8", errors="replace")
