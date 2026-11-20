"""android-renef-mcp: MCP server exposing Renef to AI agents (stdio transport).

Architecture notes (important for maintenance):
- renef_server on the device is a SINGLE-CLIENT TCP server. renef-mcp keeps one
  TCP connection for everything (status commands and the instrumented session)
  and at most one attached target, all serialized by a lock.
- `exec` responses: the server relay only exits early on a "✓ Lua executed"/
  "✗ Lua" marker, otherwise it lingers ~5s. renef_mcp.client.wrap_lua() makes
  every exec print the marker itself, so execs return promptly and reliably.
- Module helpers are implemented over exec with correct Lua (the upstream C
  binding's Module.list wrapper is broken: it ipairs-iterates a string).
"""

import os
import re
import time
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from renef_mcp import adb, config
from renef_mcp import scripts as renef_scripts
from renef_mcp import techniques as technique_docs
from renef_mcp.client import RenefError
from renef_mcp.lua import normalize_hex_pattern, quote
from renef_mcp.session import MANAGER, NoSessionError

mcp = FastMCP(
    "renef",
    instructions=(
        "Renef MCP: dynamic instrumentation for Android ARM64 (Frida-like, Lua scripting).\n"
        "Workflow: renef_status -> renef_attach(pid) or renef_spawn(package) -> "
        "renef_exec(lua) / hook tools. Read resource renef://docs/lua-api for the full "
        "Lua API (Module/Memory/hook/Java/Syscall/Thread/File/OS/KCov). Renef is NOT "
        "Frida: no Interceptor/Java.perform. Java class names use slashes, e.g. "
        "'com/example/Class'. Use pcall() around hooks for classes that may not exist."
    ),
)

MAX_OUTPUT_CHARS = 60_000
MAX_MEM_READ = 4096

# On-device install paths (match the upstream server's RENEF_PAYLOAD_PATH).
SERVER_BIN = "/data/local/tmp/renef_server"
SERVER_LOG = "/data/local/tmp/renef_server.log"
AGENT_BIN = "/data/local/tmp/libagent.so"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _truncate(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated, {len(text) - limit} chars dropped]"


def _run_lua(lua_code: str, total_cap: float = 30.0) -> str:
    """exec Lua in the target; return cleaned output (raises RenefError on Lua error)."""
    is_err, text = MANAGER.exec(lua_code, total_cap=total_cap)
    if is_err:
        raise RenefError(f"Lua execution failed:\n{text}")
    return text or "(no output)"


def _require_session() -> None:
    if not MANAGER.is_active():
        raise NoSessionError(
            "No active target. Use renef_attach(pid) or renef_spawn(package) first "
            "(renef_list_processes / renef_list_apps help find targets)."
        )


def _hexdump(data: bytes, base: int) -> str:
    lines = []
    for off in range(0, len(data), 16):
        row = data[off : off + 16]
        hex_part = " ".join(f"{b:02x}" for b in row).ljust(16 * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"0x{base + off:016x}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines)


def _to_int(value: str, what: str) -> int:
    try:
        return int(value, 0)  # accepts 0x.. and decimal
    except (TypeError, ValueError) as e:
        raise ValueError(f"{what} must be an integer (dec or 0x-prefixed), got {value!r}") from e


def _format_symbols(items: list, filter_sub: str, limit: int) -> str:
    if filter_sub:
        f = filter_sub.lower()
        items = [i for i in items if f in i["name"].lower()]
    total = len(items)
    shown = items[: max(1, int(limit))]
    body = "\n".join(f"0x{i['offset']:x}  {i['name']}" for i in shown)
    header = f"{total} match(es)" + (f" (showing {len(shown)})" if total > len(shown) else "")
    return _truncate(f"{header}:\n{body}" if body else f"{header}")


# ---------------------------------------------------------------------------
# status / discovery tools
# ---------------------------------------------------------------------------

def _status_text() -> str:
    lines = []

    try:
        serials = adb.device_serials()
        lines.append(f"adb devices: {', '.join(serials) if serials else '(none)'}")
    except adb.AdbError as e:
        lines.append(f"adb devices: ERROR ({e})")
        serials = []

    if config.uses_local_forward():
        try:
            lines.append("adb forward: " + adb.ensure_forward())
        except adb.AdbError as e:
            lines.append(f"adb forward: ERROR ({e})")
    else:
        lines.append(f"adb forward: n/a (direct TCP to {config.host()})")

    def _ping(client) -> bool:
        return client.ping()

    try:
        reachable = bool(MANAGER.call(_ping))
        lines.append(f"renef_server ping: {'pong (reachable)' if reachable else 'NO RESPONSE'}")
        if not reachable:
            lines.append(
                '  hint: start it with  adb shell "su -c \'/data/local/tmp/renef_server\'"'
            )
    except Exception as e:  # noqa: BLE001
        lines.append(f"renef_server ping: ERROR ({e})")

    if MANAGER.is_active():
        try:
            out = _run_lua("print('alive', OS.getpid())")
            lines.append(
                f"session: ACTIVE pid={MANAGER.pid} ({MANAGER.last_action}) eval-check: {out}"
            )
        except Exception as e:  # noqa: BLE001
            lines.append(f"session: ACTIVE pid={MANAGER.pid} but eval failed: {e}")
    else:
        lines.append("session: none (use renef_attach or renef_spawn)")

    return "\n".join(lines)


@mcp.tool()
def renef_status() -> str:
    """Check the whole chain: adb device, adb port forward, renef_server reachability
    (ping/pong), and active target session. Start here."""
    return _status_text()


@mcp.tool()
def renef_list_apps(third_party_only: bool = False) -> str:
    """List installed packages on the device (via adb, no session needed).
    Set third_party_only=true to skip system packages."""
    pkgs = adb.list_packages(third_party_only=third_party_only)
    if not pkgs:
        return "(no packages matched)"
    return _truncate(f"{len(pkgs)} packages:\n" + "\n".join(pkgs))


@mcp.tool()
def renef_list_processes() -> str:
    """List running userland processes (pid + name) on the device, for renef_attach."""
    procs = adb.list_processes()
    if not procs:
        return "(no processes found)"
    return _truncate(
        f"{len(procs)} processes:\n"
        + "\n".join(f"{p['pid']:>7}  {p['name']}" for p in procs)
    )


# ---------------------------------------------------------------------------
# server lifecycle tools (adb only, no session needed)
# ---------------------------------------------------------------------------

def _bin_dir() -> Path:
    """Directory holding the built renef_server/libagent.so.

    RENEF_BIN_DIR wins if set; otherwise the local Renef checkout's build output.
    """
    env = os.environ.get("RENEF_BIN_DIR", "").strip()
    if env:
        return Path(env).expanduser().resolve()
    return config.renef_home() / "build" / "android"


def _server_pid() -> str:
    try:
        return adb.run_adb("shell", "pidof", "renef_server").strip()
    except adb.AdbError:
        return ""


@mcp.tool()
def renef_server_deploy() -> str:
    """Push the built renef_server + libagent.so to the device and chmod +x them.
    Binaries come from RENEF_BIN_DIR or <RENEF_HOME>/build/android (make build first).
    Pushes under a temp name and renames as root: a direct overwrite of libagent.so
    fails with "Permission denied" while a target process has it mapped."""
    import hashlib

    bdir = _bin_dir()
    server = bdir / "renef_server"
    agent = bdir / "libagent.so"
    for path in (server, agent):
        if not path.is_file():
            raise FileNotFoundError(
                f"{path} not found. Build Renef first (cd {config.renef_home()} && make), "
                "or set RENEF_BIN_DIR to a directory containing renef_server and libagent.so."
            )
    adb.run_adb("push", str(server), SERVER_BIN + ".new", timeout=120)
    adb.run_adb("push", str(agent), AGENT_BIN + ".new", timeout=120)
    try:
        adb.run_adb(
            "shell",
            f"su -c 'mv -f {SERVER_BIN}.new {SERVER_BIN} && "
            f"mv -f {AGENT_BIN}.new {AGENT_BIN} && "
            f"chmod 755 {SERVER_BIN} && chmod 777 {AGENT_BIN} && "
            f"chcon u:object_r:app_data_file:s0 {AGENT_BIN} && "
            f"chcon u:object_r:shell_data_file:s0 {SERVER_BIN}'",
            timeout=60,
        )
    finally:
        try:
            adb.run_adb("shell", f"rm -f {SERVER_BIN}.new {AGENT_BIN}.new", timeout=15)
        except adb.AdbError:
            pass

    def _local_md5(path: Path) -> str:
        h = hashlib.md5()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    remote = adb.run_adb("shell", f"su -c 'md5sum {SERVER_BIN} {AGENT_BIN}'", timeout=60)
    hashes = {}
    for line in remote.splitlines():
        parts = line.split()
        if len(parts) == 2:
            hashes[parts[1]] = parts[0]
    results = []
    for local, remote_path in ((server, SERVER_BIN), (agent, AGENT_BIN)):
        got = hashes.get(remote_path, "")
        if got == _local_md5(local):
            results.append(f"{remote_path}: md5 verified")
        else:
            results.append(f"{remote_path}: MD5 MISMATCH (got {got or 'none'})")
    results.append(f"agent path {AGENT_BIN} matches this build's RENEF_PAYLOAD_PATH")
    try:
        ctx = adb.run_adb("shell", f"su -c 'ls -Z {AGENT_BIN}'", timeout=15).split()[0]
        if "app_data_file" not in ctx:
            results.append(f"WARNING: agent context is {ctx}; targets may not be able to map it")
        else:
            results.append(f"agent context: {ctx}")
    except adb.AdbError:
        pass
    if not all("verified" in r for r in results[:2]):
        raise RenefError("deploy verification failed:\n" + "\n".join(results))
    return "\n".join(results)


@mcp.tool()
def renef_server_start() -> str:
    """Start renef_server on the device as root (idempotent) and set up the adb
    port forward. Verifies with a ping."""
    pid = _server_pid()
    if pid:
        reachable = adb.ping_server()
        return (f"renef_server already running (pid {pid}, "
                f"{'reachable' if reachable else 'NO RESPONSE to ping'})")
    adb.ensure_forward()
    # One shell string: adb joins argv with spaces, so `su -c` must receive a
    # single quoted payload or it only takes the first word as the command.
    adb.run_adb("shell", f"su -c 'nohup {SERVER_BIN} > {SERVER_LOG} 2>&1 &'", timeout=30)
    time.sleep(0.8)
    pid = _server_pid()
    if not pid:
        raise RenefError(
            f"renef_server did not start (no pid). Check the log: adb shell \"su -c 'tail {SERVER_LOG}'\" "
            "or renef_server_logs. Is the device rooted?"
        )
    reachable = adb.ping_server()
    status = "reachable" if reachable else "started but ping failed (may still be binding)"
    return f"renef_server started (pid {pid}, {status}); adb forward set"


@mcp.tool()
def renef_server_stop() -> str:
    """Stop renef_server on the device (kill as root)."""
    pid = _server_pid()
    if not pid:
        return "renef_server is not running"
    adb.run_adb("shell", f"su -c 'kill -9 {pid}'", timeout=30)
    time.sleep(0.3)
    return f"renef_server (pid {pid}) stopped" if not _server_pid() \
        else f"kill sent to pid {pid} but it is still running"


@mcp.tool()
def renef_server_restart() -> str:
    """Restart renef_server on the device (stop, then start with port forward)."""
    stopped = renef_server_stop()
    if "not running" not in stopped and "still running" not in stopped:
        time.sleep(0.5)
    return stopped + "\n" + renef_server_start()


@mcp.tool()
def renef_server_logs(lines: int = 60) -> str:
    """Tail the renef_server log from the device (last <lines> lines, default 60)."""
    lines = max(1, min(int(lines), 500))
    try:
        out = adb.run_adb("shell", "tail", "-n", str(lines), SERVER_LOG, timeout=30)
    except adb.AdbError:
        try:
            out = adb.run_adb("shell", "tail", "-n", str(lines),
                              "/data/local/tmp/renef.log", timeout=30)
        except adb.AdbError as e:
            raise RenefError(
                f"could not read the server log ({e}). If the server was started "
                "manually without redirection, there is no log file."
            ) from e
    return _truncate(out.strip() or "(log file is empty)")


# ---------------------------------------------------------------------------
# session tools
# ---------------------------------------------------------------------------

@mcp.tool()
def renef_attach(pid: int) -> str:
    """Attach to a running process and inject the renef agent."""
    try:
        new_pid = MANAGER.attach(int(pid))
    except (RenefError, OSError):
        MANAGER.disconnect()
        raise
    # verify the agent responds so failures surface immediately
    try:
        _run_lua(f"print('attached ok, pid={new_pid}')")
    except Exception:
        MANAGER.disconnect()
        raise RenefError(
            f"attach({pid}) was accepted but agent eval failed - injection may have failed"
        )
    return f"attached to pid {new_pid}. Use renef_exec to run Lua in it."


@mcp.tool()
def renef_spawn(package: str) -> str:
    """Spawn an app by package name, gated at startup (ptrace pause), inject the agent.
    The first renef_exec auto-resumes the gated process; renef_resume resumes it
    without running a script."""
    package = package.strip()
    if not package:
        raise ValueError("package must not be empty")
    try:
        new_pid = MANAGER.spawn(package)
    except (RenefError, OSError):
        MANAGER.disconnect()
        raise
    return (
        f"spawned {package} (pid {new_pid}, gated at startup). "
        "Run renef_exec to deliver a script; it auto-resumes the process. "
        "Use renef_resume to resume without running a script."
    )


@mcp.tool()
def renef_resume() -> str:
    """Resume a spawn-gated process (after renef_spawn)."""
    def _resume(client) -> str:
        return client.resume()

    out = str(MANAGER.call(_resume))
    return out or "(no response from server)"


@mcp.tool()
def renef_disconnect() -> str:
    """Close the current target session (does not kill the target process)."""
    was = MANAGER.is_active()
    MANAGER.disconnect()
    return "session closed" if was else "no session was open"


# ---------------------------------------------------------------------------
# execution tools
# ---------------------------------------------------------------------------

@mcp.tool()
def renef_exec(lua: str) -> str:
    """Execute Lua code in the target process and return print() output.
    Main tool. Examples: "print(Module.list())", "print(Memory.readString(args[0]))".
    Multi-line Lua is fine. See resource renef://docs/lua-api for the full API."""
    _require_session()
    return _truncate(_run_lua(lua))


@mcp.tool()
def renef_load_script(path: str) -> str:
    """Load a Lua script file from the MCP host machine and run it in the target."""
    _require_session()

    def _load(client):
        return client.load_script(path)

    is_err, text = MANAGER.call(_load)
    if is_err:
        raise RenefError(f"script failed:\n{text}")
    return _truncate(text or "(script ran, no output)")


# ---------------------------------------------------------------------------
# memory tools
# ---------------------------------------------------------------------------

@mcp.tool()
def renef_mem_scan(pattern: str, module: str = "") -> str:
    """Scan memory for a hex pattern. Prefer module="libfoo.so": it uses Lua
    Memory.search and supports spaces and ?? wildcards (e.g. "CA FE ?? BE").
    Without module, the upstream full-process scan is used: compact hex only and
    it can exceed the server's ~10s response cap (an error will say so)."""
    _require_session()
    # Validate locally: the upstream ms command silently corrupts spaced or
    # wildcard patterns instead of rejecting them.
    normalize_hex_pattern(pattern, wildcards=bool(module.strip()))

    def _scan(client) -> str:
        return client.memscan(pattern, module)

    raw = str(MANAGER.call(_scan))
    return _truncate(raw.strip() or "(no matches)")


@mcp.tool()
def renef_mem_read(addr: str, size: int = 64) -> str:
    """Read bytes from target memory and return a hexdump. addr accepts decimal or 0x-hex.
    size is capped at 4096 bytes."""
    _require_session()
    address = _to_int(addr, "addr")
    size = max(1, min(int(size), MAX_MEM_READ))
    return _mem_read_impl(address, size)


def _mem_read_impl(address: int, size: int) -> str:
    is_err, text = MANAGER.exec(
        "local data = Memory.read("
        f"0x{address:x}, {size}); "
        "if not data then print('__MEMFAIL__') else "
        "local hex = ''; for i = 1, #data do hex = hex .. string.format('%02x', string.byte(data, i)) end; "
        "print(hex) end",
        total_cap=15.0,
    )
    if is_err:
        raise RenefError(f"Memory.read failed: {text}")
    hex_text = text.strip().splitlines()[-1] if text.strip() else ""
    if not hex_text or "__MEMFAIL__" in hex_text:
        raise RenefError(f"could not read {size} bytes at 0x{address:x} (unmapped or protected?)")
    hex_text = "".join(hex_text.split())
    try:
        data = bytes.fromhex(hex_text)
    except ValueError as e:
        raise RenefError(f"bad hex response from agent: {hex_text[:64]!r}") from e
    return _hexdump(data[:size], address)


@mcp.tool()
def renef_mem_read_value(addr: str, size: int = 4, signed: bool = False) -> str:
    """Read an integer from target memory. size: 1, 2, 4 or 8 bytes (unsigned unless signed=true)."""
    _require_session()
    address = _to_int(addr, "addr")
    size = int(size)
    if size not in (1, 2, 4, 8):
        raise ValueError("size must be 1, 2, 4 or 8")
    lua = f"local v = Memory.readU{size * 8}(0x{address:x}); print(v or '__NIL__')"
    out = _run_lua(lua, total_cap=10.0)
    val_s = out.strip().splitlines()[-1] if out.strip() else "__NIL__"
    if "__NIL__" in val_s:
        raise RenefError(f"could not read {size}B at 0x{address:x}")
    try:
        value = int(val_s)
    except ValueError as e:
        raise RenefError(f"unexpected agent response: {val_s!r}") from e
    if signed and value >= (1 << (size * 8 - 1)):
        value -= 1 << (size * 8)
    mask = (1 << (size * 8)) - 1
    return f"{addr} ({size}B) = {value} (0x{value & mask:x})"


@mcp.tool()
def renef_mem_read_string(addr: str, max_len: int = 256) -> str:
    """Read a NUL-terminated C string from target memory."""
    _require_session()
    address = _to_int(addr, "addr")
    max_len = max(1, min(int(max_len), 65536))
    out = _run_lua(
        f"local s = Memory.readString(0x{address:x}, {max_len}); if s then print(s) else print('__NIL__') end",
        total_cap=10.0,
    )
    if "__NIL__" in out:
        raise RenefError(f"could not read string at 0x{address:x}")
    return out


@mcp.tool()
def renef_mem_write(addr: str, hex_bytes: str) -> str:
    """Write raw bytes to target memory. hex_bytes: hex string, spaces allowed, e.g. "1F 20 03 D5"."""
    _require_session()
    address = _to_int(addr, "addr")
    clean = "".join(hex_bytes.split()).replace("0x", "")
    if not clean or len(clean) % 2 != 0:
        raise ValueError("hex_bytes must be a non-empty even-length hex string")
    try:
        data = bytes.fromhex(clean)
    except ValueError as e:
        raise ValueError(f"invalid hex: {e}") from e
    lua_bytes = "".join(f"\\x{b:02x}" for b in data)
    is_err, text = MANAGER.exec(
        f"local ok = Memory.write(0x{address:x}, \"{lua_bytes}\"); print(ok and 'WROTE' or '__WFAIL__')",
        total_cap=10.0,
    )
    if is_err or "__WFAIL__" in text:
        raise RenefError(f"write failed at 0x{address:x}: {text}")
    return f"wrote {len(data)} bytes at {addr}"


@mcp.tool()
def renef_mem_write_value(addr: str, value: int, size: int = 4) -> str:
    """Write an integer to target memory. size: 1, 2, 4 or 8 bytes."""
    _require_session()
    address = _to_int(addr, "addr")
    value = int(value)
    size = int(size)
    if size not in (1, 2, 4, 8):
        raise ValueError("size must be 1, 2, 4 or 8")
    if not (0 <= value < (1 << (size * 8))):
        raise ValueError(f"value does not fit in {size} byte(s) as unsigned")
    # Memory.writeU* returns nothing on success (raw dereference) - verify by reading back
    lua = (
        f"Memory.writeU{size * 8}(0x{address:x}, {value}); "
        f"print('VERIFY ' .. string.format('0x%x', Memory.readU{size * 8}(0x{address:x})))"
    )
    is_err, text = MANAGER.exec(lua, total_cap=10.0)
    expected = value & ((1 << (size * 8)) - 1)
    if is_err or f"0x{expected:x}" not in text:
        raise RenefError(
            f"write_value failed at 0x{address:x} (read back {text.strip()!r}, "
            f"expected 0x{expected:x}) - target may have crashed or memory is not writable"
        )
    return f"wrote {value} (0x{value:x}) as {size}B at {addr} (verified)"


@mcp.tool()
def renef_mem_patch(addr: str, hex_bytes: str) -> str:
    """Write raw bytes to target memory using Memory.patch, which handles
    mprotect internally (works on read-only code pages that renef_mem_write
    cannot touch). hex_bytes: hex string, spaces allowed."""
    _require_session()
    address = _to_int(addr, "addr")
    clean = "".join(hex_bytes.split()).replace("0x", "")
    if not clean or len(clean) % 2 != 0:
        raise ValueError("hex_bytes must be a non-empty even-length hex string")
    try:
        data = bytes.fromhex(clean)
    except ValueError as e:
        raise ValueError(f"invalid hex: {e}") from e
    lua_bytes = "".join(f"\\x{b:02x}" for b in data)
    is_err, text = MANAGER.exec(
        f"local ok = Memory.patch(0x{address:x}, \"{lua_bytes}\"); print(ok and 'PATCHED' or '__PFAIL__')",
        total_cap=10.0,
    )
    if is_err or "__PFAIL__" in text:
        raise RenefError(f"patch failed at 0x{address:x}: {text}")
    return f"patched {len(data)} bytes at {addr}"


# ---------------------------------------------------------------------------
# module tools
# ---------------------------------------------------------------------------

@mcp.tool()
def renef_module_list() -> str:
    """List loaded modules/libraries in the target process (base address, name, path)."""
    _require_session()

    def _list(client):
        return client.module_list()

    mods = MANAGER.call(_list)
    if not mods:
        return "(no modules)"
    return _truncate(
        f"{len(mods)} modules:\n"
        + "\n".join(f"0x{m['base']:016x}  {m['name']}" for m in mods)
    )


@mcp.tool()
def renef_module_find(name: str) -> str:
    """Get the base address of a loaded module, e.g. renef_module_find("libc.so")."""
    _require_session()

    def _find(client):
        return client.module_find(name.strip())

    base = MANAGER.call(_find)
    if base is None:
        return f"module {name!r} not found (check name with renef_module_list)"
    return f"{name} base = 0x{base:x}"


@mcp.tool()
def renef_module_exports(name: str, filter: str = "", limit: int = 200) -> str:
    """List exported symbols of a module. Use filter to substring-match names, limit to cap output."""
    _require_session()

    def _exports(client):
        return client.module_exports(name.strip())

    items = MANAGER.call(_exports)
    if not items:
        return f"no exports for {name!r}"
    return _format_symbols(items, filter, int(limit))


@mcp.tool()
def renef_module_symbols(name: str, filter: str = "", limit: int = 200) -> str:
    """List all symbols (including non-exported) of a module. filter/limit as in renef_module_exports."""
    _require_session()

    def _symbols(client):
        return client.module_symbols(name.strip())

    items = MANAGER.call(_symbols)
    if not items:
        return f"no symbols for {name!r}"
    return _format_symbols(items, filter, int(limit))


@mcp.tool()
def renef_sections(lib: str) -> str:
    """List ELF sections of a loaded library (upstream `sec` command)."""
    _require_session()
    return _truncate(str(MANAGER.call(lambda c: c.sections(lib))))


@mcp.tool()
def renef_hook_generate(lib: str, symbol_or_offset: str = "") -> str:
    """Generate a ready-to-run Lua hook template (upstream `hookgen` command).
    With a symbol it resolves the offset first (needs a session):
    renef_hook_generate("libc.so", "fopen") or renef_hook_generate("libc.so", "0x1a2b3")."""
    _require_session()
    return _truncate(str(MANAGER.call(lambda c: c.hookgen(lib, symbol_or_offset))))


@mcp.tool()
def renef_framework_detect() -> str:
    """Detect the app framework (Flutter, React Native, Unity, Xamarin,
    Cordova/Ionic) by checking for its characteristic libraries. Needs a session."""
    _require_session()
    lua = """
local frameworks = {
    flutter = {"libflutter.so", "libapp.so"},
    react_native = {"libhermes.so", "libreactnativejni.so", "libreactnative.so"},
    unity = {"libunity.so", "libil2cpp.so"},
    xamarin = {"libmono-android.so", "libmono.so", "libmonodroid.so"},
    cordova = {"libcordova.so"},
}
local detected = {}
for framework, libs in pairs(frameworks) do
    for _, lib in ipairs(libs) do
        local base = Module.find(lib)
        if base then
            detected[framework] = detected[framework] or {}
            table.insert(detected[framework], string.format("%s @ 0x%x", lib, base))
        end
    end
end
if next(detected) == nil then
    print("Framework: native (no framework libraries found)")
else
    for framework, libs in pairs(detected) do
        print("Framework: " .. framework)
        for _, line in ipairs(libs) do print("  - " .. line) end
    end
end
"""
    return _truncate(_run_lua(lua, total_cap=20.0))


# ---------------------------------------------------------------------------
# hook tools
# ---------------------------------------------------------------------------

@mcp.tool()
def renef_hook_native(lib: str, offset: str, on_enter: str = "", on_leave: str = "",
                      caller: str = "") -> str:
    """Install a native hook at offset (from library base) in lib, e.g. renef_hook_native("libc.so", "0x1234",
    on_enter="print('fopen path:', Memory.readString(args[0]))").
    Callbacks are Lua statement strings using args[0..7] (onEnter) / retval (onLeave).
    Find offsets with renef_module_exports first.
    caller selects the upstream PLT/GOT backend (e.g. caller="libtarget.so");
    omit it for a trampoline hook. There is no separate hook_type: upstream
    ignores the old --hook= argument and auto-selects from caller.
    WARNING: do not hook ultra-hot functions like clock_gettime/read/write - the agent's
    own output path may call them, causing recursive hooks that crash the target."""
    _require_session()
    address = _to_int(offset, "offset")
    callbacks = (
        "{ "
        + (f"onEnter = function(args) {on_enter} end" if on_enter.strip() else "")
        + (", " if on_enter.strip() and on_leave.strip() else "")
        + (f"onLeave = function(retval) {on_leave} end" if on_leave.strip() else "")
        + (", " if caller.strip() and (on_enter.strip() or on_leave.strip()) else "")
        + (f"caller = {quote(caller.strip())}" if caller.strip() else "")
        + " }"
    )
    lua = f"hook({quote(lib.strip())}, 0x{address:x}, {callbacks})"
    _run_lua(lua, total_cap=15.0)
    suffix = f" (caller={caller.strip()})" if caller.strip() else ""
    return f"native hook installed at {lib}+{offset}{suffix}"


@mcp.tool()
def renef_hook_java(class_name: str, method: str, signature: str, on_enter: str = "", on_leave: str = "") -> str:
    """Install a Java method hook. class_name in JNI slash format (e.g. "com/example/Class"),
    signature in JNI format (e.g. "(Ljava/lang/String;)Z").
    arg layout: args[0]=ArtMethod* (ignore), args[1]=this (instance methods), args[2..]=parameters.
    Use on_enter="args.skip = true" to bypass void methods. Wrap uncertain classes in pcall via renef_exec."""
    _require_session()
    lua = (
        f"hook({quote(class_name.strip())}, {quote(method.strip())}, {quote(signature.strip())}, "
        "{ "
        + (f"onEnter = function(args) {on_enter} end" if on_enter.strip() else "")
        + (", " if on_enter.strip() and on_leave.strip() else "")
        + (f"onLeave = function(retval) {on_leave} end" if on_leave.strip() else "")
        + " })"
    )
    _run_lua(lua, total_cap=15.0)
    return f"java hook installed: {class_name}.{method} {signature}"


@mcp.tool()
def renef_list_hooks() -> str:
    """List active native hooks in the target process. Upstream's registry is
    native-only: Java hooks (renef_hook_java) do not appear here and cannot be
    removed by renef_unhook; they are restored when the agent connection closes,
    i.e. on the next attach/spawn."""
    _require_session()

    def _hooks(client) -> str:
        return client.hooks()

    out = str(MANAGER.call(_hooks))
    return _truncate(out or "(no active native hooks)")


@mcp.tool()
def renef_unhook(hook_id: str) -> str:
    """Remove a hook by id (from renef_list_hooks), or "all" to remove every hook."""
    _require_session()
    s = str(hook_id).strip()

    def _unhook(client, hid) -> str:
        return client.unhook(hid)

    if s.lower() == "all":
        listing = str(MANAGER.call(lambda c: c.hooks()))
        ids = sorted(
            int(m.group(1))
            for m in re.finditer(r"(?m)^\s*\[(\d+)\](.*)$", listing or "")
            if "(removed)" not in m.group(2)
        )
        if ids:
            results = []
            for hid in ids:
                results.append(f"#{hid}: {str(MANAGER.call(lambda c, h=hid: c.unhook(h))).strip() or 'ok'}")
            return f"removed {len(ids)} hook(s):\n" + "\n".join(results)
        # Listing unavailable (e.g. a hook print storm hides it): upstream
        # understands a literal `unhook all`, so use it directly.
        raw = str(MANAGER.call(lambda c: c.unhook("all"))).strip()
        if raw.lstrip().lower().startswith(("error", "fail")):
            raise RenefError(f"unhook all failed: {raw}")
        return raw or "(no hooks to remove)"
    try:
        hid = int(s, 0)
    except ValueError as e:
        raise ValueError("hook_id must be an integer or 'all'") from e
    out = str(MANAGER.call(lambda c: c.unhook(hid))).strip()
    if out.lstrip().lower().startswith(("error", "fail")):
        raise RenefError(f"unhook({hid}) failed: {out}")
    return f"hook #{hid} removed" + (f" ({out})" if out else "")


@mcp.tool()
def renef_watch(seconds: float = 5.0) -> str:
    """Collect hook output for a time window (blocks, exclusive). Install hooks first
    (renef_hook_native / renef_hook_java), then call this to capture their prints.
    seconds capped at 60."""
    _require_session()
    seconds = max(0.5, min(float(seconds), 60.0))

    def _watch(client) -> str:
        return client.watch_collect(seconds)

    text = str(MANAGER.call(_watch)).strip()
    return _truncate(text or f"(no hook output within {seconds}s)")


@mcp.tool()
def renef_backtrace() -> str:
    """Print the current thread call stack in the target process (useful inside hook debugging)."""
    _require_session()
    return _truncate(_run_lua("print(Thread.backtrace())"))


# ---------------------------------------------------------------------------
# script library (vendored from ahmeth4n/renef-mcp, MIT)
# ---------------------------------------------------------------------------

@mcp.tool()
def renef_list_scripts() -> str:
    """List the bundled Renef Lua example scripts (hook demos, tracing,
    flutter_ssl / ssl_unpin / root_bypass bypasses). Load one with renef_get_script
    + renef_load_script, or paste into renef_exec."""
    names = renef_scripts.list_scripts()
    if not names:
        return "(no bundled scripts)"
    return f"{len(names)} scripts:\n" + "\n".join(names)


@mcp.tool()
def renef_get_script(name: str) -> str:
    """Return the Lua source of a bundled script (see renef_list_scripts), e.g.
    renef_get_script("flutter_ssl")."""
    try:
        content = renef_scripts.get_script_content(name)
    except FileNotFoundError as e:
        raise ValueError(str(e)) from e
    return _truncate(content)


# ---------------------------------------------------------------------------
# technique documentation (vendored from ahmeth4n/renef-mcp, MIT)
# ---------------------------------------------------------------------------

@mcp.tool()
def renef_technique_list() -> str:
    """List available technique knowledge bases and their platforms
    (e.g. ssl_pinning: android_native, flutter, react_native, unity, xamarin, cordova_ionic)."""
    categories = technique_docs.list_categories()
    if not categories:
        return "(no technique docs vendored)"
    lines = [f"{name}: {', '.join(platforms)}" for name, platforms in categories.items()]
    return "technique categories:\n" + "\n".join(lines)


@mcp.tool()
def renef_technique(category: str = "ssl_pinning", platform: str = "android") -> str:
    """Return the assembled technique guide for a platform, e.g.
    renef_technique("ssl_pinning", "flutter") or platform="react_native"/"unity"/"xamarin"."""
    try:
        text = technique_docs.get_technique(category, platform)
    except ValueError as e:
        raise ValueError(str(e)) from e
    return _truncate(text or "(empty document set)")


# ---------------------------------------------------------------------------
# resources & prompts
# ---------------------------------------------------------------------------

@mcp.resource("renef://status")
def resource_status() -> str:
    """Current renef chain status as compact text."""
    try:
        return _status_text()
    except Exception as e:  # noqa: BLE001
        return f"status error: {e}"


@mcp.resource("renef://docs/lua-api")
def resource_lua_api() -> str:
    """Full Renef Lua API reference (Module, Memory, hook, Java, Syscall, Thread, File, OS, KCov)."""
    p = config.lua_api_doc_path()
    if p.is_file():
        return p.read_text(encoding="utf-8", errors="replace")
    return (
        "RENEF_AI_PROMPT.md not found at "
        f"{p}. Set RENEF_HOME to your renef checkout. Quick API:\n"
        "hook(lib, offset, {onEnter=function(args) end, onLeave=function(retval) return retval end})\n"
        'hook("com/example/Class", "method", "(Ljava/lang/String;)Z", {onEnter=function(args) args.skip=true end})\n'
        "Module.list/exports/symbols | Memory.read/write/patch/readU8..U64/search | "
        "Java.use(cls):call(m,sig,...) | Syscall.trace(...) | Thread.backtrace()"
    )


@mcp.prompt()
def renef_expert(task: str = "hook a function and log its arguments") -> str:
    """Guidance prompt for writing Renef Lua instrumentation scripts."""
    return (
        "You are writing Lua scripts for Renef (Android ARM64 dynamic instrumentation). "
        "You are NOT writing Frida code: no Interceptor.attach, no Java.perform, no NativeFunction.\n\n"
        f"Task: {task}\n\n"
        "Workflow:\n"
        "1. renef_status - verify server + session.\n"
        "2. renef_spawn('<package>') or renef_attach(<pid>).\n"
        "3. Discover with renef_module_list / renef_module_exports('libtarget.so', filter='...') "
        "or renef_exec('print(Module.list())'). NEVER guess offsets.\n"
        "4. Install hooks with renef_hook_native / renef_hook_java, or complex logic via "
        "renef_exec with hook(). Wrap possibly-missing classes in pcall.\n"
        "5. Capture output with renef_watch(seconds) or renef_exec prints.\n"
        "6. Clean up with renef_unhook('all').\n\n"
        "Critical rules: Java class names use slashes (com/example/Class); void-method bypasses "
        "need args.skip=true in onEnter; onLeave may return a new value (integer/boolean/JNI.string); "
        "use print() for all logging; find offsets via Module.exports, never hardcode addresses.\n"
        "Full API reference: read resource renef://docs/lua-api."
    )


def main() -> int:
    mcp.run()  # stdio transport (default)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
