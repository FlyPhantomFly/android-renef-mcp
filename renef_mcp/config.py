"""Path/env configuration for renef-mcp.

Environment variables:
    RENEF_HOME   Renef repo root (default: ~/github/renef)
    RENEF_HOST   renef_server host (default: 127.0.0.1, via adb forward)
    RENEF_PORT   renef_server TCP port (default: 1907)
    RENEF_ADB    adb binary path (default: "adb")
"""

from __future__ import annotations

import os
from pathlib import Path

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 1907
# Abstract UDS socket the on-device server listens on (see renef Makefile install target)
FORWARD_REMOTE = "localabstract:com.android.internal.os.RuntimeInit"


def renef_home() -> Path:
    """Renef repo root containing build/librenef.so, bindings/python and RENEF_AI_PROMPT.md."""
    env = os.environ.get("RENEF_HOME", "").strip()
    if env:
        return Path(env).expanduser().resolve()
    return (Path.home() / "github" / "renef").resolve()


def binding_python_dir() -> Path:
    return renef_home() / "bindings" / "python"


def binding_core_py() -> Path:
    return binding_python_dir() / "renef" / "core.py"


def native_lib_path() -> Path:
    return renef_home() / "build" / "librenef.so"


def lua_api_doc_path() -> Path:
    return renef_home() / "RENEF_AI_PROMPT.md"


def adb_binary() -> str:
    return os.environ.get("RENEF_ADB", "adb").strip() or "adb"


def host() -> str:
    return os.environ.get("RENEF_HOST", DEFAULT_HOST).strip() or DEFAULT_HOST


def port() -> int:
    raw = os.environ.get("RENEF_PORT", "").strip()
    try:
        return int(raw) if raw else DEFAULT_PORT
    except ValueError:
        return DEFAULT_PORT


def uses_local_forward() -> bool:
    """True when the server is reached through a local adb port forward."""
    h = host()
    return h in ("127.0.0.1", "localhost", "::1", "0.0.0.0")
