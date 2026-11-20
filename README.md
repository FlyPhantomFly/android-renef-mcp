# renef-mcp

An MCP server for [Renef](https://renef.io), a Frida-like dynamic instrumentation
toolkit for Android ARM64. With it, an AI agent can attach to a process on a
rooted device (or spawn one, held paused at startup), run Lua inside the target,
hook native and Java methods, read and write process memory, and collect hook
output.

Renef is not Frida: the agent runs Lua instead of JavaScript, the API is its own
(`hook()`, `Module.*`, `Memory.*`, `Java.use`, `Syscall.trace`), and nothing
frida-related has to be on the device. Just `renef_server` and a rooted handset.
That matters for apps whose protections look for Frida.

```
┌──────────────┐   stdio/MCP   ┌─────────────┐  TCP :1907   ┌───────────────┐
│ MCP client   │ ◄───────────► │  renef-mcp  │ ◄──────────► │ renef_server  │
│ (AI agent)   │               │ (this pkg)  │  (adb fwd)   │ on device(adb)│
└──────────────┘               └─────────────┘              └──────┬────────┘
                                                                   │ agent socket
                                                                   ▼
                                                          ┌─────────────────┐
                                                          │ libagent.so     │
                                                          │ inside target   │
                                                          │ app (Lua VM)    │
                                                          └─────────────────┘
```

## Tools (38)

**Status and discovery** (no target needed)

- `renef_status()` — adb devices, port forward, server ping/pong, session state
- `renef_list_apps(third_party_only)` — installed packages
- `renef_list_processes()` — running processes, for `renef_attach`

**Server lifecycle** (no session needed)

- `renef_server_deploy()` — push the built `renef_server` and `libagent.so` to the
  device, set permissions and the SELinux context the agent needs, verify by md5
- `renef_server_start()` / `renef_server_stop()` / `renef_server_restart()` —
  root-managed lifecycle with ping verification
- `renef_server_logs(lines)` — tail the server log on the device

**Session**

- `renef_attach(pid)` — inject the agent into a running process
- `renef_spawn(package)` — spawn an app gated at startup (ptrace pause) and
  inject the agent. The first exec auto-resumes it, or call `renef_resume`
  without a script
- `renef_resume()` — resume a spawn-gated process
- `renef_disconnect()` — close the session; the target keeps running

**Execution**

- `renef_exec(lua)` — run Lua in the target and get back its `print()` output.
  The workhorse, and multi-line Lua is fine
- `renef_load_script(path)` — run a Lua file from the host machine

**Memory**

- `renef_mem_scan(pattern, module)` — scan for a hex pattern. Prefer
  `module="libfoo.so"`, which uses Lua `Memory.search` and takes spaces and `??`
  wildcards. Without a module it's the upstream full-process scan: compact hex
  only, and big processes can outrun the server's ~10s response cap
- `renef_mem_read(addr, size)` — hexdump, up to 4096 bytes
- `renef_mem_read_value(addr, size, signed)` — integer read, 1/2/4/8 bytes
- `renef_mem_read_string(addr, max_len)` — NUL-terminated C string
- `renef_mem_write(addr, hex_bytes)` — write raw bytes
- `renef_mem_write_value(addr, value, size)` — write an integer, verified by
  reading it back
- `renef_mem_patch(addr, hex_bytes)` — like `mem_write` but via `Memory.patch`,
  which handles `mprotect` itself, so read-only code pages are fair game

**Modules**

- `renef_module_list()` and `renef_module_find(name)` — loaded libraries, base
  addresses
- `renef_module_exports(name, filter, limit)` / `renef_module_symbols(name, filter, limit)`
- `renef_sections(lib)` — ELF sections of a loaded library
- `renef_framework_detect()` — flags Flutter, React Native, Unity, Xamarin or
  Cordova by their characteristic libraries
- `renef_hook_generate(lib, symbol_or_offset)` — server-generated Lua hook
  template; give it a symbol and it resolves the offset first

**Hooks**

- `renef_hook_native(lib, offset, on_enter, on_leave, caller)` — trampoline hook
  by default; pass `caller="libtarget.so"` for the PLT/GOT backend. Callbacks
  are Lua statements over `args[0..7]` (onEnter) and `retval` (onLeave). Find
  offsets with `renef_module_exports` first
- `renef_hook_java(class, method, signature, on_enter, on_leave)` — ART method
  hook. Classes in slash form (`com/example/Class`), JNI signatures. `args[0]`
  is the ArtMethod pointer, `args[1]` is `this`, `args[2..]` are the parameters,
  and `args.skip = true` bypasses a void method
- `renef_list_hooks()` / `renef_unhook(hook_id | "all")` — native hooks only.
  Java hooks aren't in the upstream registry; they're cleared on the next
  attach/spawn
- `renef_watch(seconds)` — capture hook/strace output for a window. Blocks the
  session exclusively, capped at 60s, and shows nothing if the app does nothing

**Diagnostics**

- `renef_backtrace()` — current-thread call stack

**Script library** (vendored from [ahmeth4n/renef-mcp](https://github.com/ahmeth4n/renef-mcp), MIT)

- `renef_list_scripts()` — 18 bundled examples: hook demos, tracing, and working
  bypasses like `flutter_ssl`, `ssl_unpin` and `root_bypass`
- `renef_get_script(name)` — the Lua source, ready for `renef_load_script`

**Technique knowledge base** (vendored from ahmeth4n/renef-mcp, MIT)

- `renef_technique_list()` — categories and platforms; currently `ssl_pinning`
  for android_native, flutter, react_native, unity, xamarin and cordova_ionic
- `renef_technique(category, platform)` — the assembled guide, e.g.
  `renef_technique("ssl_pinning", "flutter")`

Resources: `renef://status` for live chain status, `renef://docs/lua-api` for the
full Lua API reference (read from the Renef checkout). There's also a
`renef_expert(task)` prompt that keeps agents from accidentally writing Frida
code.

## Usage

Requirements: Python 3.10+, `adb`, and Renef built for the device. Build once:

```bash
cd ~/github/renef
make                # produces build/android/renef_server and libagent.so
```

Then install this package and register it with your MCP client:

```bash
cd ~/github/renef-mcp
uv sync
claude mcp add renef -- uv run --directory ~/github/renef-mcp renef-mcp
```

Or the JSON form most clients accept:

```json
{
  "mcpServers": {
    "renef": {
      "command": "uv",
      "args": ["run", "--directory", "/home/<you>/github/renef-mcp", "renef-mcp"]
    }
  }
}
```

After that you don't need to touch adb yourself: `renef_server_deploy()` pushes
the built binaries, `renef_server_start()` starts the server as root and sets up
the port forward, and `renef_status()` confirms the chain. If you'd rather do it
by hand, the old route still works:

```bash
adb shell "su -c '/data/local/tmp/renef_server'"   # start the server (root)
```

The server takes no arguments. Environment variables, should you need them:
`RENEF_HOME` (Renef checkout, used for the Lua API docs resource; default
`~/github/renef`), `RENEF_BIN_DIR` (where `renef_server_deploy` finds the built
binaries; default `<RENEF_HOME>/build/android`), `RENEF_HOST`/`RENEF_PORT`
(server address, default `127.0.0.1:1907` over the adb forward) and `RENEF_ADB`
(adb binary path).

A session then looks like this:

```
renef_status
renef_spawn("com.example.app")
renef_module_exports("libtarget.so", filter="crypt")
renef_hook_native("libtarget.so", "0x1a2b3",
                  on_enter="print('arg:', Memory.readString(args[0]))")
renef_watch(5)
renef_unhook("all")
renef_disconnect()
```

## Planned integration

This server is planned for integration into
[android-re-mcp](https://github.com/FlyPhantomFly/android-re-mcp) as its
Frida-alternative dynamic instrumentation layer. Until then, this repo is the
standalone source.

## License

Apache-2.0 for the code. The bundled Lua scripts and technique documents come
from [ahmeth4n/renef-mcp](https://github.com/ahmeth4n/renef-mcp) and are MIT
(license texts live in `renef_mcp/scripts/` and `renef_mcp/techniques/`).
