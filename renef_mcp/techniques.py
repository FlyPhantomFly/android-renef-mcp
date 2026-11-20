"""Vendored technique documentation loader (from ahmeth4n/renef-mcp, MIT).

Currently ships the ssl_pinning knowledge base: platform-mapped markdown that
explains how certificate pinning works per framework (android_native, flutter,
react_native, unity, xamarin, cordova/ionic) and how to bypass it.  Exposed to
agents via the renef_technique_list / renef_technique tools.
"""

from __future__ import annotations

import json
from pathlib import Path

_TECH_DIR = Path(__file__).resolve().parent / "techniques"

# Keep assembled documents within a sane context budget.
MAX_CHARS = 120_000


def list_categories() -> dict[str, list[str]]:
    """Map technique category -> available platforms."""
    out: dict[str, list[str]] = {}
    for category_dir in sorted(_TECH_DIR.iterdir()):
        mapping = category_dir / "platform_mapping.json"
        if category_dir.is_dir() and mapping.is_file():
            data = json.loads(mapping.read_text(encoding="utf-8"))
            out[category_dir.name] = sorted(data.get("platforms", {}))
    return out


def get_technique(category: str, platform: str) -> str:
    """Assemble the markdown documents for category+platform.

    Platform names are normalized like upstream: case-insensitive, hyphens to
    underscores, with common aliases (android -> android_native,
    rn/reactnative -> react_native, cordova/ionic -> cordova_ionic).
    """
    categories = list_categories()
    if category not in categories:
        raise ValueError(
            f"unknown technique category {category!r}; "
            f"available: {', '.join(categories)}"
        )
    mapping = json.loads(
        (_TECH_DIR / category / "platform_mapping.json").read_text(encoding="utf-8")
    )

    key = platform.strip().lower().replace("-", "_")
    aliases = {
        "android": "android_native",
        "rn": "react_native",
        "reactnative": "react_native",
        "cordova": "cordova_ionic",
        "ionic": "cordova_ionic",
    }
    key = aliases.get(key, key)
    if key not in mapping.get("platforms", {}):
        raise ValueError(
            f"unknown platform {platform!r} for {category}; "
            f"available: {', '.join(sorted(mapping['platforms']))}"
        )

    base = _TECH_DIR / category
    sections = []
    for filename in mapping["platforms"][key].get("files", []):
        path = base / filename
        if not path.is_file():
            continue
        sections.append(path.read_text(encoding="utf-8", errors="replace"))

    text = "\n\n---\n\n".join(sections)
    if len(text) > MAX_CHARS:
        text = text[:MAX_CHARS] + f"\n\n... [truncated, {len(text) - MAX_CHARS} chars dropped]"
    return text
