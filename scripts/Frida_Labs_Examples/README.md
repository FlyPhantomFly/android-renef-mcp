# Frida_Labs examples for Renef

One Lua script per challenge, translated from the Frida solutions in
`~/github/Frida_Labs` to Renef's Lua API. All eleven were **verified live** on a
rooted ARM64 device through the `android-renef-mcp` server (two consecutive
full passes, 11/11). The local (gitignored) harness is
`tests/verify_lab.py` + `tests/lab_harness.py`.

Run one with `renef_spawn("<package>")`, then `renef_load_script("<path>")`
(and the extra interaction noted below).

| Challenge | Script | What it does | Verified evidence |
|---|---|---|---|
| 0x1 | `challenge_0x1.lua` | Hooks `check(II)V` to reveal `random*2+4` (the static `get_random()I` is JIT-inlined, so hooking it is not enough). Submit any number, then the revealed one. | UI: `FRIDA{BABY_HOOK_0x1}` |
| 0x2 | `challenge_0x2.lua` | Calls `get_flag(4919)` on the main thread via `Java.registerClass` + `Handler.post`. | UI: `FLAG{BABY_HOOKS_0x2}` |
| 0x3 | `challenge_0x3.lua` | Calls `Checker.increase()` 256 times; no static-field writes in Renef. Click the button afterwards. | UI: `FRIDA{INJECT_AND_INSPECT}` |
| 0x4 | `challenge_0x4.lua` | `Check:new()` then `get_flag(1337)`. | Output: `FLAG FRIDA{XORED_INSTANCE}` |
| 0x5 | `challenge_0x5.lua` | Enumerates `ActivityThread.mActivities` via reflection, invokes `flag(1337)` on the live MainActivity. | UI: `FRIDA{ON_MATCH_THIS_INSTANCE}` |
| 0x6 | `challenge_0x6.lua` | Same live-Activity invocation; builds a Checker and sets `num1=1234`, `num2=4321` reflectively. | UI: `FRIDA{INSTANCES_AND_INSTANCES}` |
| 0x7 | `challenge_0x7.lua` | Same pattern with `Checker(600,600)` and `flag(checker)`. | UI: `FRIDA{HOOKING_CONSTRUCTORS}` |
| 0x8 | `challenge_0x8.lua` | Deferred native hook on `libfrida0x8.so!cmpstr` (0x864), forces `1`. First click may be eaten by Android's translate popup; click again. | Hook output forced `1`; screenshot: `YEY YOU GOT THE FLAG candidate` |
| 0x9 | `challenge_0x9.lua` | Deferred native hook on `liba0x9.so!check_flag` (0x614), forces `1337`. | Screenshot: `You won FRIDA{NATIVE_LAND_0x2}` |
| 0xA | `challenge_0xA.lua` | Renef has no `NativeFunction`, so patch `stringFromJNI` entry with `mov w0,#1; mov w1,#2; b get_flag`. | logcat `FLAG`: `Decrypted Flag: FRIDA{DONT_CALL_ME}` |
| 0xB | `challenge_0xB.lua` | NOPs the `b.ne` at `libfrida0xb.so+0x15248`. Click once to load the library, load the script, click again. | logcat `FLAG :`: `FRIDA{NATIVE_HACKER}` |

`_prelude.lua` is the app-classloader snippet used by the Java scripts; it is
inlined in each script because Renef Lua has no `require()`.

Notes on Renef limitations that shaped these translations: no `Java.choose`
(workaround: reflection over `mActivities`), no field `.value` writes
(workaround: `java.lang.reflect.Field.setInt`), no `NativeFunction` (0xA uses a
code patch), and native `onLeave` return overrides are observed on the UI path
but not always on direct JNI calls from Lua.
