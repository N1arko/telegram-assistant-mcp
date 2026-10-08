"""Temporary, bounded 401 diagnostics. Never store request data or token material."""
from __future__ import annotations

import contextvars
import os
import secrets
import sqlite3
import stat
import time
from contextlib import closing
from pathlib import Path


_REASON = contextvars.ContextVar("auth_401_reason", default=None)
_REASONS = frozenset({"missing", "expired", "claims", "jwks", "other"})


def mark_auth_reason(reason: str) -> None:
    slot = _REASON.get()
    if slot is not None:
        slot["reason"] = reason if reason in _REASONS else "other"


class Auth401Diagnostics:
    """Store at most 256 anonymous 401 events, only until an explicit cutoff."""

    def __init__(self, path: Path, until_epoch: int, *, clock=time.time):
        self.path = Path(path)
        self.until_epoch = until_epoch
        self.clock = clock
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            mode = os.fstat(fd).st_mode
            if not stat.S_ISREG(mode) or mode & 0o077:
                raise ValueError("unsafe auth diagnostic file")
        finally:
            os.close(fd)
        with closing(self._connect()):
            pass

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=2)
        mode = self.path.stat().st_mode
        if not stat.S_ISREG(mode) or mode & 0o077:
            db.close()
            raise ValueError("unsafe auth diagnostic file")
        db.execute("PRAGMA secure_delete = ON")
        db.execute("CREATE TABLE IF NOT EXISTS auth_401 ("
                   "ts INTEGER NOT NULL, request_id TEXT PRIMARY KEY, "
                   "status INTEGER NOT NULL CHECK(status = 401), "
                   "reason TEXT NOT NULL CHECK(reason IN "
                   "('missing','expired','claims','jwks','other')))")
        return db

    def record(self, reason: str) -> str | None:
        now = int(self.clock())
        if now >= self.until_epoch:
            return None
        reason = reason if reason in _REASONS else "other"
        request_id = secrets.token_hex(8)
        with closing(self._connect()) as db:
            with db:
                db.execute("DELETE FROM auth_401 WHERE ts < ?", (now - 86400,))
                db.execute("INSERT INTO auth_401 VALUES (?, ?, 401, ?)",
                           (now, request_id, reason))
                db.execute("DELETE FROM auth_401 WHERE rowid NOT IN "
                           "(SELECT rowid FROM auth_401 ORDER BY rowid DESC LIMIT 256)")
        return request_id


class Auth401Middleware:
    def __init__(self, app, diagnostics: Auth401Diagnostics):
        self.app = app
        self.diagnostics = diagnostics

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or scope.get("path") != "/mcp":
            return await self.app(scope, receive, send)
        slot = {"reason": None}
        context = _REASON.set(slot)
        has_authorization = any(k.lower() == b"authorization" for k, _ in scope.get("headers", ()))

        async def diagnostic_send(event):
            if event["type"] == "http.response.start" and event["status"] == 401:
                reason = slot["reason"] or ("claims" if has_authorization else "missing")
                try:
                    request_id = self.diagnostics.record(reason)
                except (OSError, sqlite3.Error, ValueError):
                    request_id = None
                if request_id is not None:
                    event = dict(event)
                    event["headers"] = list(event.get("headers", ())) + [
                        (b"x-mcp-diag-id", request_id.encode("ascii"))]
            await send(event)

        try:
            return await self.app(scope, receive, diagnostic_send)
        finally:
            _REASON.reset(context)
