"""android-renef-mcp: MCP server exposing Renef (Android dynamic instrumentation) to AI agents."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("android-renef-mcp")
except PackageNotFoundError:
    # Keep in sync with pyproject.toml [project].version.
    __version__ = "0.1.3"
