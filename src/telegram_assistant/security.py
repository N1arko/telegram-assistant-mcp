"""Local limits and operator policy; never interpret semantic permission."""
from __future__ import annotations

import json
import math
import os
import sqlite3
import stat
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path


class Denied(Exception):
    def __init__(self, code: str, retry_after: int | None = None):
        self.code = code
        self.retry_after = retry_after
        super().__init__(code)


def integer(value, low: int, high: int, code="invalid_argument") -> int:
    if type(value) is not int or not low <= value <= high:
        raise Denied(code)
    return value


def peer_id(value) -> int:
    value = integer(value, -(2**63) + 1, 2**63 - 1)
    if value == 0:
        raise Denied("invalid_peer")
    return value


def private_file(path: Path, max_bytes=65536) -> bytes:
    """No symlinks, regular owner-only files. O_NOFOLLOW blocks final-link races."""
    if path.is_symlink():
        raise Denied("unsafe_config")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
            raise Denied("unsafe_config")
        data = os.read(fd, max_bytes + 1)
        if len(data) > max_bytes:
            raise Denied("unsafe_config")
        return data
    finally:
        os.close(fd)


@dataclass(frozen=True)
class Grant:
    peer_id: int
    expires_at: int
    max_chars: int
    per_minute: int
    per_day: int


class Policy:
    def __init__(self, grants=()):
        self.grants = {g.peer_id: g for g in grants}

    @classmethod
    def load(cls, path: Path) -> Policy:
        # Any file/config failure means empty grants, never implicit permission.
        try:
            obj = json.loads(private_file(path))
            if set(obj) != {"version", "grants"} or type(obj["version"]) is not int or obj["version"] != 1:
                return cls()
            if not isinstance(obj["grants"], list) or len(obj["grants"]) > 100:
                return cls()
            grants = []
            for item in obj["grants"]:
                fields = {"peer_id", "operation", "expires_at", "max_chars", "per_minute", "per_day"}
                if set(item) != fields or item["operation"] != "send_message":
                    return cls()
                grant = Grant(peer_id(item["peer_id"]), integer(item["expires_at"], 1, 2**53),
                              integer(item["max_chars"], 1, 4096), integer(item["per_minute"], 1, 10),
                              integer(item["per_day"], 1, 100))
                if any(g.peer_id == grant.peer_id for g in grants):
                    return cls()
                grants.append(grant)
            return cls(grants)
        except (OSError, ValueError, TypeError, KeyError, Denied):
            return cls()

    def authorize(self, target: int, text: str, scopes: frozenset[str], now: float) -> Grant:
        if "telegram:send" not in scopes:
            raise Denied("send_scope_required")
        grant = self.grants.get(target)
        if grant is None or now >= grant.expires_at:
            raise Denied("send_denied")
        if not isinstance(text, str) or not text.strip():
            raise Denied("invalid_text")
        # Telegram length counts UTF-16 units (emoji may consume two).
        try:
            units = len(text.encode("utf-16-le")) // 2
        except UnicodeError:
            raise Denied("invalid_text") from None
        if units > grant.max_chars:
            raise Denied("text_too_long")
        return grant


class Quotas:
    """Reserve before RPC, including failures; SQLite survives restarts."""
    def __init__(self, path: Path):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.parent.is_symlink() or path.parent.stat().st_mode & 0o077:
            raise Denied("unsafe_runtime")
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
                raise Denied("unsafe_runtime")
        finally:
            os.close(fd)
        self.db = sqlite3.connect(path)
        self.db.execute("CREATE TABLE IF NOT EXISTS attempts (peer INTEGER, at REAL)")
        self.db.execute("CREATE INDEX IF NOT EXISTS attempts_lookup ON attempts(peer, at)")
        self.db.execute("CREATE TABLE IF NOT EXISTS read_gate (id INTEGER PRIMARY KEY CHECK(id=1), state TEXT)")
        self.db.commit()

    def load_gate(self):
        row = self.db.execute('SELECT state FROM read_gate WHERE id=1').fetchone()
        if row is None:
            return None
        if len(row[0]) > 4096:
            raise Denied('rate_state_unavailable')
        return json.loads(row[0])

    def save_gate(self, state):
        self.db.execute('INSERT OR REPLACE INTO read_gate VALUES(1, ?)',
                        (json.dumps(state, allow_nan=False, separators=(',', ':')),))
        self.db.commit()

    def reserve(self, grant: Grant, now: float):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            # A rolling 24-hour limit; no reset-at-midnight burst.
            self.db.execute("DELETE FROM attempts WHERE at <= ?", (now - 86400,))
            rows = self.db.execute("SELECT at FROM attempts WHERE peer=? AND at>? ORDER BY at",
                                   (grant.peer_id, now - 86400)).fetchall()
            recent = [at for (at,) in rows if at > now - 60]
            if len(rows) >= grant.per_day or len(recent) >= grant.per_minute:
                raise Denied("send_quota_exceeded")
            self.db.execute("INSERT INTO attempts VALUES (?, ?)", (grant.peer_id, now))
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def close(self):
        self.db.close()


class RateGate:
    def __init__(self, limit=30, clock=time.monotonic, *, storage=None, wall_clock=time.time, startup_grace=0):
        self.clock = clock
        self.limit = limit
        self.calls = deque()
        self.blocked_until = 0.0
        self.storage, self.wall_clock = storage, wall_clock
        self.failed = False
        now, wall = self.clock(), self.wall_clock()
        if storage is not None:
            try:
                state = storage.load_gate()
                if state is not None:
                    valid_number = lambda value: type(value) in (int, float) and math.isfinite(value) and value >= 0
                    if (not isinstance(state, dict) or set(state) != {'version', 'flood_until', 'calls'} or
                            type(state['version']) is not int or state['version'] != 1 or
                            not valid_number(state['flood_until']) or not isinstance(state['calls'], list) or
                            len(state['calls']) > limit or not all(valid_number(x) for x in state['calls']) or
                            state['calls'] != sorted(state['calls'])):
                        raise ValueError
                    self.blocked_until = now + max(0, state['flood_until'] - wall)
                    # If wall time moves backwards, keep entries conservatively
                    # rather than dropping a persisted quota.
                    self.calls.extend(now - max(0, wall - x) for x in state['calls'] if x > wall - 60)
                self.blocked_until = max(self.blocked_until, now + startup_grace)
                self._persist()
            except Exception:
                raise Denied('rate_state_unavailable') from None

    def _persist(self):
        if self.storage is None:
            return
        now, wall = self.clock(), self.wall_clock()
        try:
            self.storage.save_gate({'version': 1, 'flood_until': wall + max(0, self.blocked_until - now),
                                    'calls': [wall - max(0, now - at) for at in self.calls]})
        except Exception:
            self.failed = True
            raise Denied('rate_state_unavailable') from None

    def check(self):
        if self.failed:
            raise Denied('rate_state_unavailable')
        now = self.clock()
        if now < self.blocked_until:
            raise Denied("telegram_rate_limited", math.ceil(self.blocked_until - now))
        while self.calls and self.calls[0] <= now - 60:
            self.calls.popleft()
        if len(self.calls) >= self.limit:
            raise Denied("local_rate_limited", math.ceil(60 - (now - self.calls[0])))
        self.calls.append(now)
        self._persist()

    def flood(self, seconds: int):
        self.blocked_until = max(self.blocked_until, self.clock() + max(1, seconds))
        try:
            self._persist()
        except Denied:
            # Subsequent checks fail closed; do not lose the original flood
            # response or accidentally retry a failed Telegram operation.
            self.failed = True
