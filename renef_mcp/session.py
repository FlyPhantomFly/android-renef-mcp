"""Active target session management.

renef-mcp keeps a single TCP connection to renef_server (the device server is
single-client) and at most one attached target. All access is serialized with
an RLock. The connection is lazily (re)established, so server-level commands
(ping/resume) work without a target too.
"""

from __future__ import annotations

import threading
from typing import Callable, Optional

from renef_mcp.client import RenefClient, RenefError, validate_package


class NoSessionError(RuntimeError):
    pass


class SessionManager:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._client: Optional[RenefClient] = None
        self._last_action: str = "none"

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    @property
    def pid(self) -> int:
        return self._client.pid if self._client else -1

    @property
    def last_action(self) -> str:
        return self._last_action

    def is_active(self) -> bool:
        return bool(self._client and self._client.connected() and self._client.pid > 0)

    def client(self) -> RenefClient:
        """Get the (lazily connected) client. Callers must hold the lock."""
        if self._client is None:
            self._client = RenefClient()
        if not self._client.connected():
            self._client.connect()
        return self._client

    def _reset_client(self) -> None:
        if self._client is not None:
            self._client.close()

    def require_target(self) -> RenefClient:
        if not self.is_active():
            raise NoSessionError(
                "No active target. Use renef_attach(pid) or renef_spawn(package) first "
                "(renef_list_processes / renef_list_apps help find targets)."
            )
        return self._client  # type: ignore[return-value]

    def attach(self, pid: int) -> int:
        # Mirror spawn(): validate before _reset_client() so a bad pid does
        # not tear down a healthy live session.
        pid = int(pid)
        if pid <= 0:
            raise ValueError(f"pid must be positive, got {pid}")
        with self._lock:
            self._reset_client()
            client = self.client()
            try:
                new_pid = client.attach(pid)
            except (RenefError, OSError):
                # hard failure poisons this connection (server may be mid-state)
                self._reset_client()
                raise
            self._last_action = f"attach {pid}"
            return new_pid

    def spawn(self, package: str) -> int:
        # Validate before _reset_client(): a bad package must not drop a live
        # session (the server is never touched).
        package = validate_package(package)
        with self._lock:
            self._reset_client()
            client = self.client()
            try:
                new_pid = client.spawn(package)
            except (RenefError, OSError):
                # A validation error (ValueError) happens before the server is
                # touched and must not tear down a healthy active session.
                self._reset_client()
                raise
            self._last_action = f"spawn {package} (gated)"
            return new_pid

    def disconnect(self) -> None:
        with self._lock:
            self._reset_client()
            self._last_action = "closed"

    # -- convenience wrappers -------------------------------------------------

    def exec(self, lua: str, total_cap: float = 30.0) -> tuple[bool, str]:
        with self._lock:
            return self.require_target().exec(lua, total_cap=total_cap)

    def call(self, fn: Callable[[RenefClient], object]) -> object:
        """Run fn(client) under the lock (client may or may not have a target)."""
        with self._lock:
            return fn(self.client())

    def with_target(self, fn: Callable[[RenefClient], object]) -> object:
        """Run fn(client) under the lock; requires an attached target."""
        with self._lock:
            return fn(self.require_target())


MANAGER = SessionManager()
