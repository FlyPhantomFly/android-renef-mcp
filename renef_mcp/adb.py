"""adb + raw-TCP helpers for talking to renef_server."""

from __future__ import annotations

import re
import socket
import subprocess
from functools import lru_cache

from renef_mcp import config


class AdbError(RuntimeError):
    pass


def run_adb(*args: str, timeout: float = 20.0) -> str:
    """Run an adb command, raise AdbError on failure. Returns stdout."""
    try:
        proc = subprocess.run(
            [config.adb_binary(), *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as e:
        raise AdbError(f"adb binary not found: {config.adb_binary()!r}") from e
    except subprocess.TimeoutExpired as e:
        raise AdbError(f"adb {' '.join(args)} timed out") from e
    if proc.returncode != 0:
        raise AdbError(f"adb {' '.join(args)} failed: {proc.stderr.strip() or proc.stdout.strip()}")
    return proc.stdout


@lru_cache(maxsize=8)
def device_serials() -> tuple[str, ...]:
    """Serials of devices in 'device' state (cached per process, short-lived)."""
    out = run_adb("devices")
    serials = []
    for line in out.splitlines()[1:]:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            serials.append(parts[0])
    return tuple(serials)


def first_device() -> str | None:
    serials = device_serials()
    return serials[0] if serials else None


def ensure_forward() -> str:
    """Make sure tcp:<RENEF_PORT> is forwarded to the device server socket.

    Returns a short human description of what was done. Skips entirely when
    RENEF_HOST points at a remote (non-loopback) server.
    """
    if not config.uses_local_forward():
        return f"direct TCP mode (RENEF_HOST={config.host()}), no adb forward needed"

    port = config.port()
    local = f"tcp:{port}"
    out = run_adb("forward", "--list")
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] == local:
            return f"adb forward already set: {parts[0]} {local} -> {parts[2]}"

    serial = first_device()
    if serial is None:
        raise AdbError(
            "No adb device in 'device' state found. Connect a device and enable USB debugging."
        )
    run_adb("-s", serial, "forward", local, config.FORWARD_REMOTE)
    return f"adb forward set: {serial} {local} -> {config.FORWARD_REMOTE}"


def ping_server(timeout: float = 3.0) -> bool:
    """Raw protocol ping: connect to renef_server, send 'ping', expect 'pong'."""
    try:
        with socket.create_connection((config.host(), config.port()), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"ping\n")
            data = s.recv(64)
            return b"pong" in data
    except OSError:
        return False


def raw_command(command: str, timeout: float = 5.0) -> str:
    """Send a raw server-level command (e.g. 'resume') and collect the response."""
    with socket.create_connection((config.host(), config.port()), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(command.rstrip("\n").encode() + b"\n")
        chunks = []
        try:
            while True:
                data = s.recv(4096)
                if not data:
                    break
                chunks.append(data.decode(errors="replace"))
                if b"\n" in data:
                    break
        except socket.timeout:
            pass
        return "".join(chunks).strip()


def list_packages(third_party_only: bool = False) -> list[str]:
    """Installed packages via adb (no server required)."""
    args = ["shell", "pm", "list", "packages"]
    if third_party_only:
        args.append("-3")
    out = run_adb(*args, timeout=30.0)
    pkgs = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("package:"):
            pkgs.append(line[len("package:") :])
    return sorted(pkgs)


def list_processes(limit: int = 300) -> list[dict]:
    """Running userland processes via adb: [{'pid': int, 'name': str}, ...]."""
    out = run_adb("shell", "ps", "-A", "-o", "PID,NAME", timeout=30.0)
    procs = []
    for line in out.splitlines()[1:]:
        line = line.strip()
        if not line:
            continue
        m = re.match(r"^\s*(\d+)\s+(\S+)$", line)
        if not m:
            continue
        pid_s, name = m.group(1), m.group(2)
        if name.startswith("["):  # kernel thread
            continue
        procs.append({"pid": int(pid_s), "name": name})
        if len(procs) >= limit:
            break
    return procs
