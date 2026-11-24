"""Pure-Python client for renef_server (text protocol over TCP, one connection).

Protocol notes (learned from renef server sources):
- The device server is single-client: one connection handles all commands.
- Commands are text lines; multi-line payloads (Lua scripts) are fine when sent
  as one write ending in a single trailing "\\n".
- `exec <lua>` responses are: Lua print output ... then "✓ Lua executed" (the
  marker the server relay greps for) and finally "OK".  We wrap user Lua with a
  per-exec nonce so the client can wait for *our* completion marker instead of
  guessing from a quiet period.  A quiet-period guess caused scripts with a
  >0.35s silent gap to be returned early, retried and executed twice.
- If the completion marker never arrives, the client returns an explicit
  timeout and does NOT retry the script (retrying is unsafe for non-idempotent
  instrumentation).  The next agent command performs a no-op resync to discard
  any late output.
- `ms` responses end after the JSON result, but the upstream server caps its
  wait at 10s.  A full-process scan can exceed that; the late JSON then poisons
  the next command unless it is drained.  We set a resync flag on timeout.
"""

from __future__ import annotations

import os
import re
import socket
import time
from typing import Optional

from renef_mcp import adb, config
from renef_mcp.lua import normalize_hex_pattern, quote

# Exact markers the server relay greps for (byte sequences, UTF-8):
MARK_OK = "✓ Lua executed"       # early-exit success marker
MARK_ERR_PREFIX = "✗ Lua"        # early-exit error marker

_EXEC_WRAPPER_HEAD = "local __renef_ok, __renef_err = pcall(function()\n"
_EXEC_WRAPPER_TAIL_TMPL = (
    "\nend)\n"
    'if not __renef_ok then print("' + MARK_ERR_PREFIX + ' error: " .. tostring(__renef_err)) end\n'
    'print("' + MARK_OK + ' [{nonce}]")\n'
)

FIRST_LINE_TERMINATORS = ("OK", "FAIL", "ERROR")
_PACKAGE_RE = re.compile(r"^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+$")


def validate_package(package: str) -> str:
    """Validate an Android package name before it reaches the device shell.

    Upstream builds ``monkey -p <package>`` / ``pidof <package>`` shell strings,
    so a package name with spaces or metacharacters is a command-injection
    vector.  This rejects it on the host, before any server command is sent.
    """
    package = str(package).strip()
    if not _PACKAGE_RE.fullmatch(package):
        raise ValueError(
            f"invalid package name {package!r}; expected a dotted Android package "
            "such as com.example.app"
        )
    return package


class RenefError(RuntimeError):
    pass


class RenefClient:
    """One TCP connection to renef_server. Thread-confine it (manager lock)."""

    def __init__(self, host: Optional[str] = None, port: Optional[int] = None):
        self.host = host or config.host()
        self.port = port or config.port()
        self._sock: Optional[socket.socket] = None
        self.pid: int = -1
        self.target_label: str = ""
        # Set when a command timed out and late agent output may still arrive.
        self._needs_resync: bool = False

    # -- connection ----------------------------------------------------------

    def connected(self) -> bool:
        return self._sock is not None

    def connect(self) -> None:
        if self._sock is not None:
            return
        if config.uses_local_forward():
            # raises AdbError on hard failures (no device etc.)
            adb.ensure_forward()
        try:
            self._sock = socket.create_connection((self.host, self.port), timeout=5)
            self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError as e:
            raise RenefError(
                f"cannot connect to renef_server at {self.host}:{self.port} ({e}). "
                "Is the server running on the device: adb shell \"su -c '/data/local/tmp/renef_server'\"?"
            ) from e

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        self.pid = -1
        self.target_label = ""
        self._needs_resync = False

    # -- low-level read ------------------------------------------------------

    def _read_response(
        self,
        quiet_seconds: float = 0.3,
        total_cap: float = 30.0,
        first_line_fast: bool = False,
        end_marker: Optional[str] = None,
        stall_seconds: Optional[float] = None,
    ) -> str:
        """Read until completion marker / quiet-period / cap. Returns text.

        When ``end_marker`` is set, the loop waits for that exact marker (not a
        quiet gap), up to ``total_cap``.  ``stall_seconds`` aborts early when no
        data at all has arrived for that long, so a wedged agent does not burn
        the full deadline.  After the marker arrives we keep draining briefly
        for the agent's trailing "OK" line.
        """
        assert self._sock is not None
        sock = self._sock
        sock.settimeout(0.1)
        chunks: list[bytes] = []
        start = time.time()
        last_activity = start
        marker_seen_at: Optional[float] = None
        quiet_since: Optional[float] = None
        first_line_done = False

        while True:
            now = time.time()
            if now - start > total_cap:
                break

            text_so_far = b"".join(chunks).decode(errors="replace")

            if end_marker is not None:
                if end_marker in text_so_far:
                    if marker_seen_at is None:
                        marker_seen_at = now
                    if now - marker_seen_at >= 0.3:
                        break
                elif now - last_activity >= (stall_seconds if stall_seconds is not None else total_cap):
                    break
            else:
                if quiet_since is not None and now - quiet_since >= quiet_seconds:
                    break
                if marker_seen_at is not None and now - marker_seen_at >= 0.3:
                    break

            try:
                data = sock.recv(65536)
            except socket.timeout:
                if chunks and quiet_since is None:
                    quiet_since = now
                if not end_marker and not first_line_done and first_line_fast and chunks:
                    if self._has_first_line_terminator(text_so_far):
                        break
                continue
            except OSError:
                break

            if not data:
                break

            chunks.append(data)
            last_activity = time.time()
            quiet_since = None
            text_so_far = b"".join(chunks).decode(errors="replace")

            if not first_line_done:
                first_line_done = "\n" in text_so_far
                if first_line_fast and self._has_first_line_terminator(text_so_far):
                    # terminator line fully received?
                    if "\n" in text_so_far:
                        break

            if end_marker is None and marker_seen_at is None and (
                MARK_OK in text_so_far or MARK_ERR_PREFIX in text_so_far
            ):
                # Marker seen on a legacy (non-exec) read: drain trailing ack.
                marker_seen_at = time.time()

        return b"".join(chunks).decode(errors="replace")

    @staticmethod
    def _has_first_line_terminator(text: str) -> bool:
        first = text.split("\n", 1)[0].strip()
        if first.startswith("OK") or first.startswith("FAIL") or first.startswith("ERROR"):
            # "OK <pid>" from spawn, bare "OK" from attach, FAIL/ERROR lines
            return first == "OK" or first.startswith(("OK ", "FAIL", "ERROR"))
        return False

    def _send(self, cmd: str) -> None:
        self.connect()
        assert self._sock is not None
        payload = cmd.rstrip("\n").encode() + b"\n"
        self._sock.sendall(payload)

    def _raw_command(self, cmd: str, **read_kwargs) -> str:
        self._send(cmd)
        return self._read_response(**read_kwargs)

    def _resync_agent(self, total_cap: float = 15.0) -> None:
        """Consume late/stale agent output with a harmless wrapped no-op exec."""
        if not self.connected():
            self._needs_resync = False
            return
        nonce = os.urandom(4).hex()
        try:
            raw = self._raw_command(
                "exec " + self.wrap_lua("", nonce),
                end_marker=f"[{nonce}]",
                stall_seconds=5.0,
                total_cap=total_cap,
            )
            self._needs_resync = f"[{nonce}]" not in raw
        except (RenefError, OSError):
            # Do not let a failed resync turn every later command into a wait.
            self._needs_resync = False

    def _command(
        self,
        cmd: str,
        quiet_seconds: float = 0.3,
        total_cap: float = 30.0,
        first_line_fast: bool = False,
        end_marker: Optional[str] = None,
        stall_seconds: Optional[float] = None,
        resync: bool = False,
    ) -> str:
        self.connect()
        if resync and self._needs_resync:
            self._resync_agent()
        return self._raw_command(
            cmd,
            quiet_seconds=quiet_seconds,
            total_cap=total_cap,
            first_line_fast=first_line_fast,
            end_marker=end_marker,
            stall_seconds=stall_seconds,
        )

    # -- server-level commands ----------------------------------------------

    def ping(self) -> bool:
        """Probe the server without touching session state.

        A transient error must not call close(): ping shares the client with
        the live target, and close() would drop pid/target_label and make
        every subsequent tool report "No active target" even though the
        instrumented process is still running.
        """
        try:
            return "pong" in self._command("ping", quiet_seconds=0.2, total_cap=3.0,
                                           first_line_fast=True)
        except (RenefError, OSError):
            return False

    def resume(self) -> str:
        return self._command("resume", quiet_seconds=0.3, total_cap=10.0,
                             first_line_fast=True).strip()

    # -- session commands ----------------------------------------------------

    def attach(self, pid: int) -> int:
        resp = self._command(f"attach {int(pid)}",
                             quiet_seconds=0.4, total_cap=60.0, first_line_fast=True)
        first = resp.strip().splitlines()[0] if resp.strip() else ""
        if not first.startswith("OK"):
            self.close()
            raise RenefError(f"attach({pid}) failed: {first or 'no response from server'}")
        self.pid = int(pid)
        self.target_label = f"pid {pid}"
        self._needs_resync = False
        return int(pid)

    def spawn(self, package: str) -> int:
        package = validate_package(package)
        # --pause is the upstream gate: the main thread is ptrace-stopped after
        # the agent is injected.  The first exec (or renef_resume) resumes it.
        resp = self._command(f"spawn {package} --pause",
                             quiet_seconds=0.6, total_cap=90.0, first_line_fast=True)
        first = resp.strip().splitlines()[0] if resp.strip() else ""
        pid = 0
        if first.startswith("OK"):
            try:
                pid = int(first.split()[1])
            except (IndexError, ValueError):
                pid = 0
        if pid <= 0:
            self.close()
            raise RenefError(
                f"spawn({package!r}) failed: {first or 'no response from server'}. "
                "Check the package name (renef_list_apps) and that renef_server runs as root."
            )
        self.pid = pid
        self.target_label = package
        self._needs_resync = False
        return pid

    # -- exec / script ---------------------------------------------------------

    @staticmethod
    def wrap_lua(user_lua: str, nonce: str = "") -> str:
        """Wrap user Lua so execution errors surface and the relay marker prints.

        The marker carries a per-exec nonce: a stale marker from a previous exec
        will not match the current wait, so it cannot be mistaken for this
        command's completion.
        """
        tail = _EXEC_WRAPPER_TAIL_TMPL.format(nonce=nonce)
        return _EXEC_WRAPPER_HEAD + user_lua + tail

    def exec(self, user_lua: str, total_cap: float = 30.0) -> tuple[bool, str]:
        """Run Lua in the target. Returns (is_error, cleaned_text).

        Waits for this exec's nonce-bearing completion marker.  On timeout it
        returns an explicit error and deliberately does NOT re-send the script:
        a blind retry executed non-idempotent hooks twice.  The next command
        resyncs the agent stream so late output cannot poison it.
        """
        nonce = os.urandom(4).hex()
        marker = f"[{nonce}]"
        raw = self._command(
            "exec " + self.wrap_lua(user_lua, nonce),
            end_marker=marker,
            stall_seconds=6.0,
            total_cap=total_cap,
            resync=True,
        )
        if marker not in raw:
            self._needs_resync = True
            _, partial = self._interpret_exec(raw, nonce)
            detail = (
                "exec timed out: completion marker not seen "
                f"(overall limit {total_cap:g}s, ~6s silence limit). "
                "The script may still be running; it was not retried to avoid "
                "duplicate execution."
            )
            if partial.strip():
                detail += "\npartial output:\n" + partial
            return True, detail
        self._needs_resync = False
        return self._interpret_exec(raw, nonce)

    @staticmethod
    def _interpret_exec(raw: str, nonce: str = "") -> tuple[bool, str]:
        lines = raw.splitlines()
        cleaned = []
        is_error = MARK_ERR_PREFIX in raw or "ERROR: Lua execution failed" in raw
        for ln in lines:
            s = ln.strip()
            if s == "OK" or s.startswith(MARK_OK):
                # completion marker (this exec's or stale) and agent ack
                continue
            if s.startswith(MARK_ERR_PREFIX):
                is_error = True
                # keep the error detail, drop the marker token itself
                cleaned.append(s[len(MARK_ERR_PREFIX) + 1:] if len(s) > len(MARK_ERR_PREFIX) else s)
                continue
            cleaned.append(ln)
        text = "\n".join(cleaned).strip("\n")
        return is_error, text

    def load_script(self, path: str, total_cap: float = 60.0) -> tuple[bool, str]:
        """Read a Lua file on this machine and run it in the target.

        Note: the on-device server's script command is "l <device_path>" and reads
        files from the DEVICE filesystem; we instead read locally and exec the
        contents, which is equivalent and needs no adb push.
        """
        p = os.path.expanduser(path)
        if not os.path.isfile(p):
            raise FileNotFoundError(f"script not found: {p}")
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            script = f.read()
        if len(script) > 900_000:
            raise RenefError("script too large (>900KB)")
        return self.exec(script, total_cap=total_cap)

    # -- memory / hooks --------------------------------------------------------

    def memscan(self, pattern: str, module: str = "") -> str:
        """Scan process memory for a hex pattern.

        With ``module`` this uses Lua ``Memory.search`` (wildcards + spaces
        supported).  Without it, the upstream ``ms`` command is used; that path
        only accepts compact hex, has a hard ~10s wait, and is therefore not
        suitable for large/full scans.
        """
        module = module.strip()
        if module:
            normalized = normalize_hex_pattern(pattern, wildcards=True)
            lua = (
                f"local r = Memory.search({quote(normalized)}, {quote(module)}); "
                "if not r or #r == 0 then print('No matches found.') else "
                "print('Found ' .. #r .. ' match(es):'); "
                "for i, x in ipairs(r) do "
                "print(string.format('[%d] %s + 0x%x (addr: 0x%x)', i, "
                "tostring(x.library), x.offset, x.addr)); "
                "print('    Hex:   ' .. tostring(x.hex)); "
                "print('    ASCII: ' .. tostring(x.ascii)) end end"
            )
            is_err, text = self.exec(lua, total_cap=45.0)
            if is_err:
                raise RenefError(f"module-scoped scan failed: {text}")
            return text

        compact = normalize_hex_pattern(pattern, wildcards=False).replace(" ", "")
        raw = self._command("ms " + compact, quiet_seconds=0.5, total_cap=12.0,
                            resync=True)
        text = raw.strip()
        clean = text.lstrip().lower()
        # The upstream formatter can return partial JSON (which it reports as
        # "Error parsing response") or a JSON error object formatted as
        # "Error: ...". Anything that is not a complete formatted result can
        # leave late bytes queued in the agent socket -> resync next command.
        complete = (text.startswith("No matches found.")
                    or (clean.startswith("found ")
                        and "match(es):" in clean
                        and text.rstrip().endswith(("-" * 60))))
        if not text or "No response from agent" in text or not complete:
            self._needs_resync = True
        if not text or "No response from agent" in text:
            raise RenefError(
                "full-process scan exceeded the upstream server's ~10s response cap. "
                "The scan may still be running; its late output will be discarded on "
                "the next command. Re-run with module='libfoo.so' for a reliable "
                "module-scoped scan (supports spaces and ?? wildcards)."
            )
        if clean.startswith("error") or "error parsing" in clean:
            raise RenefError(f"memscan failed: {text}")
        return text

    def hooks(self) -> str:
        # Upstream `hooks` performs a single recv(). If a hook fires at the same
        # moment, that print is returned instead of the listing while the real
        # listing stays queued in the agent socket. Just send `hooks` again:
        # the queued listing surfaces on a later attempt. Resyncing between
        # attempts would DISCARD the queued listing, so only resync when a
        # previous timeout already flagged stale data.
        raw = ""
        for attempt in range(6):
            raw = self._command("hooks", quiet_seconds=0.6, total_cap=15.0,
                                first_line_fast=False, resync=(attempt == 0))
            idx = raw.find("Active hooks")
            if idx >= 0:
                return raw[idx:].strip()
            if raw.lstrip().upper().startswith("ERROR"):
                return raw.strip()
            if attempt < 5:
                time.sleep(0.3)
        # give up: queue drain on the next command so stale listings cannot
        # poison it
        self._needs_resync = True
        return raw.strip()

    def unhook(self, hook_id) -> str:
        return self._command(f"unhook {hook_id}", quiet_seconds=0.4, total_cap=15.0,
                             first_line_fast=False, resync=True).strip()

    # -- raw server commands (ELF sections, hook template generator) -----------

    @staticmethod
    def _safe_token(value: str, what: str) -> str:
        """Validate a single CLI token (lib/symbol names) before interpolation."""
        value = str(value).strip()
        if not re.fullmatch(r"[A-Za-z0-9._+/=\-]+", value):
            raise ValueError(
                f"{what} must be a plain name/path token (letters, digits, . _ + / = -), "
                f"got {value!r}"
            )
        return value

    def sections(self, lib: str) -> str:
        """Upstream `sec <lib>` server command: ELF sections of a loaded library."""
        lib = self._safe_token(lib, "lib")
        raw = self._command(f"sec {lib}", quiet_seconds=0.5, total_cap=15.0, resync=True)
        return raw.strip()

    def hookgen(self, lib: str, symbol_or_offset: str = "") -> str:
        """Upstream `hookgen` server command: generate a Lua hook template.

        hookgen(lib, offset) and hookgen(lib, symbol) need a target session;
        hookgen(symbol) searches common system libraries.
        """
        lib = self._safe_token(lib, "lib")
        cmd = f"hookgen {lib}"
        if symbol_or_offset.strip():
            cmd += " " + self._safe_token(symbol_or_offset, "symbol_or_offset")
        raw = self._command(cmd, quiet_seconds=1.0, total_cap=30.0, resync=True)
        return raw.strip()

    # -- watch ------------------------------------------------------------------

    def watch_collect(self, seconds: float, on_chunk=None) -> str:
        """Enter watch mode, collect hook output for `seconds`, then leave cleanly."""
        self.connect()
        if self._needs_resync:
            self._resync_agent()
        assert self._sock is not None
        sock = self._sock
        sock.settimeout(0.1)
        sock.sendall(b"watch\n")
        collected: list[bytes] = []
        deadline = time.time() + max(0.5, seconds)
        # read stream; hook output arrives while we hold the window open
        while time.time() < deadline:
            try:
                data = sock.recv(65536)
                if not data:
                    break
                collected.append(data)
                if on_chunk:
                    on_chunk(data)
            except socket.timeout:
                continue
            except OSError:
                break
        # exit watch: any byte makes the server exit watch mode
        try:
            sock.sendall(b"\n")
        except OSError:
            pass
        # drain the watch-exit + bare-command response (discarded)
        drain_deadline = time.time() + 2.0
        quiet_since: Optional[float] = None
        while time.time() < drain_deadline:
            try:
                data = sock.recv(65536)
                if not data:
                    break
                quiet_since = None
            except socket.timeout:
                if quiet_since is None:
                    quiet_since = time.time()
                elif time.time() - quiet_since >= 0.4:
                    break
            except OSError:
                break
        text = b"".join(collected).decode(errors="replace")
        # Filter: the watch banner, and stale exec-leftover lines (bare "OK" or
        # "✓ Lua executed" lines forwarded from the agent socket buffer by the
        # server's watch-mode initial drain).
        return "\n".join(
            ln for ln in text.splitlines()
            if ln.strip() and ln.strip() != "OK"
            and "✓ Lua executed" not in ln
            and not ln.startswith("Watching hook output")
        ).strip("\n")

    # -- module helpers (implemented over exec, correct Lua) --------------------

    def module_list(self) -> list[dict]:
        """Parse Module.list() maps-style output: first mapping per unique .so path."""
        is_err, text = self.exec(
            "local m = Module.list(); if m then print(m) else print('__NIL__') end",
            total_cap=60.0,
        )
        if is_err or "__NIL__" in text:
            if is_err:
                raise RenefError(f"Module.list failed: {text}")
            return []
        mods: list[dict] = []
        seen: set[str] = set()
        for ln in text.splitlines():
            ln = ln.strip()
            if not ln or "-" not in ln:
                continue
            head, _, path = ln.partition(" ")
            path = path.strip()
            if not path or not path.endswith(".so") or path in seen:
                continue
            start_s = head.split("-", 1)[0]
            try:
                base = int(start_s, 16)
            except ValueError:
                continue
            seen.add(path)
            mods.append({"base": base, "name": os.path.basename(path), "path": path})
        mods.sort(key=lambda m: m["base"])
        return mods

    def module_find(self, name: str) -> Optional[int]:
        is_err, text = self.exec(
            f"local a = Module.find({quote(name)}); "
            "if a then print(string.format('%d', a)) else print('__NIL__') end",
            total_cap=30.0,
        )
        if is_err:
            raise RenefError(f"Module.find failed: {text}")
        val = text.strip().splitlines()[-1] if text.strip() else ""
        if not val or "__NIL__" in val:
            return None
        try:
            return int(val)
        except ValueError:
            return None

    def _module_symbols_raw(self, fn: str, name: str) -> str:
        lua = (
            f"local s = Module.{fn}({quote(name)}); "
            "if not s then print('__NIL__') else "
            "for _, x in ipairs(s) do print(string.format('0x%x %s', x.offset, x.name)) end end"
        )
        is_err, text = self.exec(lua, total_cap=60.0)
        if is_err:
            raise RenefError(f"Module.{fn} failed: {text}")
        return text

    def module_exports(self, name: str) -> list[dict]:
        text = self._module_symbols_raw("exports", name)
        if "__NIL__" in text:
            return []
        return self._parse_symbol_lines(text)

    def module_symbols(self, name: str) -> list[dict]:
        text = self._module_symbols_raw("symbols", name)
        if "__NIL__" in text:
            return []
        return self._parse_symbol_lines(text)

    @staticmethod
    def _parse_symbol_lines(text: str) -> list[dict]:
        items = []
        for ln in text.splitlines():
            ln = ln.strip()
            if not ln.startswith("0x"):
                continue
            off_s, _, sym = ln.partition(" ")
            try:
                items.append({"offset": int(off_s, 16), "name": sym.strip()})
            except ValueError:
                continue
        return items
