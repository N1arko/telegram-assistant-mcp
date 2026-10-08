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
_DETAILS = frozenset({"", "dns_or_connect", "timeout", "tls", "http_non200",
                      "invalid_jwks", "cooldown", "other"})
_TEMPORARY_BODY = b'{"error":"temporarily_unavailable"}'


def mark_auth_reason(reason: str, detail: str = "") -> None:
    slot = _REASON.get()
    if slot is not None:
        slot["reason"] = reason if reason in _REASONS else "other"
        slot["detail"] = detail if reason == "jwks" and detail in _DETAILS else ""


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
        db.execute("CREATE TABLE IF NOT EXISTS auth_events ("
                   "ts INTEGER NOT NULL, request_id TEXT PRIMARY KEY, "
                   "status INTEGER NOT NULL CHECK(status IN (401, 503)), "
                   "reason TEXT NOT NULL CHECK(reason IN "
                   "('missing','expired','claims','jwks','other')), "
                   "detail TEXT NOT NULL CHECK(detail IN "
                   "('','dns_or_connect','timeout','tls','http_non200',"
                   "'invalid_jwks','cooldown','other')))")
        old_table = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='auth_401'").fetchone()
        if old_table:
            with db:
                db.execute("INSERT OR IGNORE INTO auth_events (ts,request_id,status,reason,detail) "
                           "SELECT ts,request_id,status,reason,'' FROM auth_401")
                db.execute("DROP TABLE auth_401")
        db.execute("CREATE VIEW IF NOT EXISTS auth_401 AS "
                   "SELECT ts,request_id,status,reason FROM auth_events WHERE status=401")
        return db

    def record(self, reason: str, *, status: int = 401, detail: str = "") -> str | None:
        now = int(self.clock())
        if now >= self.until_epoch:
            return None
        if status not in (401, 503):
            raise ValueError("invalid diagnostic status")
        reason = reason if reason in _REASONS else "other"
        detail = detail if reason == "jwks" and detail in _DETAILS else ""
        request_id = secrets.token_hex(8)
        with closing(self._connect()) as db:
            with db:
                db.execute("DELETE FROM auth_events WHERE ts < ?", (now - 86400,))
                db.execute("INSERT INTO auth_events VALUES (?, ?, ?, ?, ?)",
                           (now, request_id, status, reason, detail))
                db.execute("DELETE FROM auth_events WHERE rowid NOT IN "
                           "(SELECT rowid FROM auth_events ORDER BY rowid DESC LIMIT 256)")
        return request_id


class Auth401Middleware:
    def __init__(self, app, diagnostics: Auth401Diagnostics | None):
        self.app = app
        self.diagnostics = diagnostics

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or scope.get("path") != "/mcp":
            return await self.app(scope, receive, send)
        slot = {"reason": None, "detail": ""}
        context = _REASON.set(slot)
        has_authorization = any(k.lower() == b"authorization" for k, _ in scope.get("headers", ()))
        replaced = False

        async def diagnostic_send(event):
            nonlocal replaced
            if event["type"] == "http.response.start" and event["status"] == 401:
                reason = slot["reason"] or ("claims" if has_authorization else "missing")
                temporary = reason == "jwks"
                try:
                    request_id = (self.diagnostics.record(reason, status=503 if temporary else 401,
                                   detail=slot["detail"]) if self.diagnostics is not None else None)
                except (OSError, sqlite3.Error, ValueError):
                    request_id = None
                if temporary:
                    replaced = True
                    headers = [(b"content-type", b"application/json"),
                               (b"content-length", str(len(_TEMPORARY_BODY)).encode("ascii")),
                               (b"retry-after", b"30"), (b"cache-control", b"no-store")]
                    if request_id is not None:
                        headers.append((b"x-mcp-diag-id", request_id.encode("ascii")))
                    event = {"type": "http.response.start", "status": 503, "headers": headers}
                elif request_id is not None:
                    event = dict(event)
                    event["headers"] = list(event.get("headers", ())) + [
                        (b"x-mcp-diag-id", request_id.encode("ascii"))]
            elif event["type"] == "http.response.body" and replaced:
                if replaced is True:
                    await send({"type": "http.response.body", "body": _TEMPORARY_BODY})
                    replaced = "sent"
                return
            await send(event)

        try:
            return await self.app(scope, receive, diagnostic_send)
        finally:
            _REASON.reset(context)
