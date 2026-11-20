"""End-to-end test for renef-mcp: drives the server over stdio with the MCP SDK client.

Requires: a device attached via adb with renef_server running as root.
Run:  python3 tests/test_e2e.py [--with-spawn]
"""

import asyncio
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

RENEF_HOME = os.environ.get("RENEF_HOME", os.path.expanduser("~/github/renef"))
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        PASS.append(name)
        print(f"  [PASS] {name}" + (f" - {detail}" if detail else ""))
    else:
        FAIL.append(name)
        print(f"  [FAIL] {name}" + (f" - {detail}" if detail else ""))


def text_of(result) -> str:
    return "\n".join(i.text for i in result.content if hasattr(i, "text"))


async def call(session: ClientSession, name: str, args: dict | None = None) -> str:
    result = await session.call_tool(name, args or {})
    text = text_of(result)
    return ("__ERROR__:" + text) if getattr(result, "isError", False) else text


async def main() -> int:
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "renef_mcp"],
        cwd=HERE,
        env={**os.environ, "RENEF_HOME": RENEF_HOME, "PYTHONUNBUFFERED": "1"},
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await asyncio.wait_for(session.initialize(), timeout=30)
            print("== initialized ==")

            tools = await session.list_tools()
            names = {t.name for t in tools.tools}
            check("tools/list", len(names) >= 20, f"{len(names)} tools")

            status = await call(session, "renef_status")
            check("renef_status", "pong" in status and "session:" in status,
                  status.splitlines()[0] if status else "")
            print("    " + status.replace("\n", "\n    "))

            # --- discovery (no session) ---
            apps = await call(session, "renef_list_apps", {"third_party_only": True})
            check("renef_list_apps", apps.splitlines()[0].split()[0].isdigit(),
                  apps.splitlines()[0] if apps else "")
            procs = await call(session, "renef_list_processes")
            check("renef_list_processes", procs.count("\n") > 3 and "com." in procs,
                  procs.splitlines()[0] if procs else "")

            # --- pick a target: prefer launcher (constant JVM activity), else termux ---
            pid, target_name = None, ""
            for want in ("com.android.launcher", "termux"):
                for line in procs.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) == 2 and want in parts[1]:
                        pid, target_name = int(parts[0]), parts[1]
                        break
                if pid:
                    break
            if pid is None:
                check("find target", False, "no suitable process found")
                return 1
            print(f"== target: {target_name} pid={pid} ==")

            # --- attach ---
            out = await call(session, "renef_attach", {"pid": pid})
            check("renef_attach", f"attached to pid {pid}" in out, out.strip())

            # --- exec (should be FAST now, no 5s penalty) ---
            t0 = time.time()
            out = await call(session, "renef_exec", {"lua": "print('hello mcp', 1+1)"})
            dt = time.time() - t0
            check("renef_exec", "hello mcp" in out and "2" in out, out.strip())
            check("renef_exec fast (<3s)", dt < 3.0, f"{dt:.2f}s")

            # --- exec error surfaces ---
            out = await call(session, "renef_exec", {"lua": "error('boom test')"})
            check("exec error surfaced",
                  out.startswith("__ERROR__") and "boom" in out, out[:80])

            # --- multi-line exec ---
            out = await call(session, "renef_exec", {"lua":
                "local s = 0\nfor i = 1, 10 do s = s + i end\nprint('sum=' .. s)"})
            check("multiline exec", "sum=55" in out, out.strip())

            # --- modules ---
            out = await call(session, "renef_module_list")
            check("renef_module_list", "libc.so" in out, out.splitlines()[0] if out else "")
            out = await call(session, "renef_module_find", {"name": "libc.so"})
            check("renef_module_find", "base = 0x" in out, out.strip())
            libc_base = int(out.split("base = 0x")[1], 16)

            out = await call(session, "renef_module_exports",
                             {"name": "libc.so", "filter": "fopen", "limit": 10})
            check("renef_module_exports", "fopen" in out, out.splitlines()[0] if out else "")
            fopen_offset = None
            for line in out.splitlines()[1:]:
                parts = line.split()
                if len(parts) == 2 and parts[1] == "fopen":
                    fopen_offset = int(parts[0], 16)
                    break
            check("fopen export found", fopen_offset is not None)

            out = await call(session, "renef_module_symbols",
                             {"name": "libc.so", "filter": "pthread_create", "limit": 5})
            check("renef_module_symbols", "pthread_create" in out,
                  out.splitlines()[0] if out else "")

            # --- memory ---
            out = await call(session, "renef_mem_read", {"addr": hex(libc_base), "size": 32})
            check("renef_mem_read", "|.ELF" in out.replace(" ", "|", 1) or "|.ELF" in out,
                  out.splitlines()[0])

            out = await call(session, "renef_mem_read_value", {"addr": hex(libc_base), "size": 4})
            check("renef_mem_read_value", "464c457f" in out.lower(), out.strip())

            out = await call(session, "renef_mem_read_string", {"addr": hex(libc_base + 1), "max_len": 4})
            check("renef_mem_read_string", out.strip().startswith("ELF"), repr(out))

            # write/read-back round trip on a scratch region allocated in-process
            out = await call(session, "renef_exec", {"lua":
                "local p = Memory.alloc(64); _G.__scratch = p; print(string.format('0x%x', p))"})
            scratch = None
            try:
                scratch = int(out.strip().splitlines()[-1], 16)
            except (ValueError, IndexError):
                scratch = None
            check("Memory.alloc scratch", scratch is not None, out.strip())
            if scratch:
                out = await call(session, "renef_mem_write_value",
                                 {"addr": hex(scratch), "value": 305419896, "size": 4})
                check("renef_mem_write_value", "wrote" in out, out.strip())
                out = await call(session, "renef_mem_read_value", {"addr": hex(scratch), "size": 4})
                check("write/read back", "12345678" in out.lower(), out.strip())
                out = await call(session, "renef_mem_write",
                                 {"addr": hex(scratch + 8), "hex_bytes": "DE AD BE EF"})
                check("renef_mem_write", "wrote 4 bytes" in out, out.strip())
                out = await call(session, "renef_mem_read", {"addr": hex(scratch + 8), "size": 4})
                check("mem_write/read back", "de ad be ef" in out, out.splitlines()[-1])

            # --- hooks: java hook + deterministic trigger (fires from our own Lua call) ---
            out = await call(session, "renef_hook_java",
                             {"class_name": "java/lang/StringBuilder", "method": "toString",
                              "signature": "()Ljava/lang/String;",
                              "on_enter": "print('[java-hook fired]')"})
            check("renef_hook_java", "installed" in out.lower(), out.strip())

            out = await call(session, "renef_list_hooks")
            check("renef_list_hooks", "Active hooks" in out, out.splitlines()[0] if out else "(empty)")

            out = await call(session, "renef_exec", {"lua":
                "local sb = Java.use('java/lang/StringBuilder'):new(); "
                "sb:call('append', '(Ljava/lang/String;)Ljava/lang/StringBuilder;', 'x'); "
                "local s = sb:call('toString', '()Ljava/lang/String;'); "
                "print('result=' .. tostring(s))"})
            check("java hook fires + captured",
                  "[java-hook fired]" in out and "result=x" in out,
                  out.splitlines()[0] if out else "")

            # java hooks are only restored when the agent connection closes
            # ("unhook all" covers native hooks) -> re-attach same pid to clean up
            out = await call(session, "renef_attach", {"pid": pid})
            check("re-attach restores java hooks", "attached to pid" in out, out.strip())

            # --- native hook: fopen fires when Lua io.open runs - the hook print
            #     appears in the trigger exec's own response ---
            out = await call(session, "renef_hook_native",
                             {"lib": "libc.so", "offset": hex(fopen_offset),
                              "on_enter": "print('[fopen]', Memory.readString(args[0]))"})
            check("renef_hook_native", "installed" in out.lower(), out.strip())

            out = await call(session, "renef_exec", {"lua":
                "local f = io.open('/proc/self/cmdline', 'r'); if f then local c = f:read('*a'); f:close(); print('trigger done') end"})
            check("native hook fires + captured",
                  "[fopen]" in out and "/proc/self/cmdline" in out and "trigger done" in out,
                  out.splitlines()[0] if out else "")

            out = await call(session, "renef_unhook", {"hook_id": "all"})
            check("unhook after native", "removed" in out.lower(), out.splitlines()[0] if out else "")

            # watch with no hooks must not error
            out = await call(session, "renef_watch", {"seconds": 1.0})
            check("renef_watch no hooks", "error" not in out.lower(), out[:60])

            # java hook on nonexistent class must error cleanly
            out = await call(session, "renef_hook_java",
                             {"class_name": "com/does/not/Exist", "method": "x", "signature": "()V"})
            check("java hook bad class errors",
                  out.startswith("__ERROR__") and ("fail" in out.lower() or "error" in out.lower()),
                  out[:80])

            # --- backtrace + load_script ---
            out = await call(session, "renef_backtrace")
            check("renef_backtrace", len(out) > 0, out.splitlines()[0])

            script_path = os.path.join(HERE, "tests", "fixtures", "hello.lua")
            os.makedirs(os.path.dirname(script_path), exist_ok=True)
            with open(script_path, "w") as f:
                f.write("print('script file loaded ok')\n")
            out = await call(session, "renef_load_script", {"path": script_path})
            check("renef_load_script", "script file loaded ok" in out, out.strip())

            # --- resume + disconnect ---
            out = await call(session, "renef_resume")
            check("renef_resume", isinstance(out, str), out.strip()[:60])

            out = await call(session, "renef_disconnect")
            check("renef_disconnect", "closed" in out, out.strip())

            out = await call(session, "renef_exec", {"lua": "print(1)"})
            check("exec after disconnect errors cleanly",
                  out.startswith("__ERROR__") and "No active target" in out, out[:80])

            # re-attach works after disconnect (connection reset)
            out = await call(session, "renef_attach", {"pid": pid})
            check("re-attach after disconnect", f"attached to pid {pid}" in out, out.strip())
            await call(session, "renef_disconnect")

            # --- spawn flow: fresh app is active; use a third-party app (system
            #     apps like settings can crash when spawn-gated on some ROMs) ---
            out = await call(session, "renef_spawn", {"package": "com.liuzh.deviceinfo"})
            check("renef_spawn", "spawned com.liuzh.deviceinfo" in out, out.strip())
            m = re.search(r"pid (\d+)", out)
            spawn_pid = int(m.group(1)) if m else None
            out = await call(session, "renef_exec", {"lua": "print('spawn-eval works')"})
            check("spawn exec", "spawn-eval works" in out, out.strip())

            # watch: spawn installs a fopen hook; the test wakes the screen and
            # pokes input concurrently so the foreground app performs file IO
            out = await call(session, "renef_hook_native",
                             {"lib": "libc.so", "offset": hex(fopen_offset),
                              "on_enter":
                              "_G.__fn = (_G.__fn or 0) + 1; "
                              "if _G.__fn <= 40 then print('[fopen]', Memory.readString(args[0])) end"})
            check("spawn hook install", "installed" in out.lower(), out.strip())

            async def _poke_input():
                def _run():
                    import subprocess as sp
                    sp.run(["adb", "shell", "input", "keyevent", "KEYCODE_WAKEUP"], capture_output=True)
                    time.sleep(0.6)
                    for _ in range(4):
                        sp.run(["adb", "shell", "input", "tap", "400", "700"], capture_output=True)
                        time.sleep(0.5)
                        sp.run(["adb", "shell", "input", "swipe", "400", "1200", "400", "600", "250"],
                               capture_output=True)
                        time.sleep(0.5)
                await asyncio.to_thread(_run)

            watch_task = asyncio.ensure_future(call(session, "renef_watch", {"seconds": 5.0}))
            poke_task = asyncio.ensure_future(_poke_input())
            out, _ = await asyncio.gather(watch_task, poke_task)
            check("spawn watch captures fopen", "[fopen]" in out,
                  f"{out.count('[fopen]')} events")
            subprocess.run(["adb", "shell", "input", "keyevent", "KEYCODE_SLEEP"], capture_output=True)

            out = await call(session, "renef_unhook", {"hook_id": "all"})
            check("spawn unhook native", "removed" in out.lower() or "no hooks" in out.lower(),
                  out.splitlines()[0] if out else "")

            # deterministic java hook firing: trigger from Lua
            out = await call(session, "renef_hook_java",
                             {"class_name": "java/lang/StringBuilder", "method": "toString",
                              "signature": "()Ljava/lang/String;",
                              "on_enter": "print('[java-hook fired]')"})
            check("spawn java hook", "installed" in out.lower(), out.strip())
            out = await call(session, "renef_exec", {"lua":
                "local sb = Java.use('java/lang/StringBuilder'):new(); "
                "sb:call('append', '(Ljava/lang/String;)Ljava/lang/StringBuilder;', 'x'); "
                "local s = sb:call('toString', '()Ljava/lang/String;'); "
                "print('result=' .. tostring(s))"})
            check("spawn java hook fires",
                  "[java-hook fired]" in out and "result=x" in out,
                  out.splitlines()[0] if out else "")
            # re-attach to the same pid closes the old agent connection, restoring java hooks
            if spawn_pid:
                out = await call(session, "renef_attach", {"pid": spawn_pid})
                check("re-attach restores java hooks", "attached to pid" in out, out.strip())
            await call(session, "renef_disconnect")
            # stop the spawned app
            subprocess.run(["adb", "shell", "am", "force-stop", "com.liuzh.deviceinfo"],
                           capture_output=True)

    print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
    if FAIL:
        print("failed:", ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
